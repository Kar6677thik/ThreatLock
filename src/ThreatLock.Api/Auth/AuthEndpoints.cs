using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ThreatLock.Core.Identity;
using ThreatLock.Core.Sessions;
using ThreatLock.Infrastructure.Persistence;
using ThreatLock.Infrastructure.Sessions;

namespace ThreatLock.Api.Auth;

public sealed record RegisterOrgRequest(
    [property: Required, StringLength(100, MinimumLength = 2)] string OrgName,
    [property: StringLength(Slug.MaxLength)] string? OrgSlug,
    [property: Required, StringLength(100, MinimumLength = 1)] string DisplayName,
    [property: Required, EmailAddress, StringLength(254)] string Email,
    [property: Required, StringLength(128)] string Password);

public sealed record LoginRequest(
    [property: Required, StringLength(254)] string Email,
    [property: Required, StringLength(128)] string Password);

public sealed record UserView(Guid Id, string Email, string DisplayName, Guid OrgId, string OrgName, string OrgSlug, IReadOnlyList<string> Roles);

public sealed record LoginResponse(string AccessToken, DateTimeOffset ExpiresAt, UserView User);

public sealed record SessionView(Guid Id, DateTimeOffset CreatedAt, DateTimeOffset LastSeenAt, string? Ip, string? DeviceId, string? UserAgent, bool Current);

public static class AuthEndpoints
{
    private const string InvalidCredentials = "Invalid email or password.";

    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var auth = app.MapGroup("/api/auth").WithTags("Auth");
        auth.MapPost("/register-org", RegisterOrg).AllowAnonymous();
        auth.MapPost("/login", Login).AllowAnonymous();
        // Anonymous at the bearer level: the refresh cookie is the credential here.
        auth.MapPost("/refresh", Refresh).AllowAnonymous();
        auth.MapPost("/logout", Logout);

        var me = app.MapGroup("/api/me").WithTags("Auth");
        me.MapGet("/", Me);
        me.MapGet("/sessions", MySessions);
        me.MapDelete("/sessions/{sid:guid}", RevokeMySession);
    }

    /// <summary>Creates an org and its owner in one transaction, then signs the owner in (SPEC §13).</summary>
    private static async Task<Results<Created<LoginResponse>, ValidationProblem, ProblemHttpResult, NotFound>> RegisterOrg(
        RegisterOrgRequest request,
        HttpContext http,
        IConfiguration config,
        ThreatLockDbContext db,
        UserManager<AppUser> users,
        SessionService sessions,
        IOptions<AuthOptions> auth,
        TimeProvider time,
        CancellationToken ct)
    {
        // Self-service signup is a demo feature; deployments can switch it off.
        if (!config.GetValue("Demo:AllowSignup", false)) return TypedResults.NotFound();

        var slug = string.IsNullOrWhiteSpace(request.OrgSlug) ? Slug.From(request.OrgName) : request.OrgSlug;
        if (!Slug.IsValid(slug))
        {
            return TypedResults.ValidationProblem(new Dictionary<string, string[]>
            {
                ["OrgSlug"] = ["Use lowercase letters, digits and single hyphens, e.g. \"acme-corp\"."],
            });
        }

        Org org;
        AppUser user;
        string[] roles = [Roles.Member, Roles.Owner];
        try
        {
            // Org, user and role assignment succeed or fail together. UserManager uses the same
            // scoped DbContext, so its writes join this transaction.
            await using var transaction = await db.Database.BeginTransactionAsync(ct);

            if (await db.Orgs.AnyAsync(o => o.Slug == slug, ct))
            {
                return Conflict("That organisation address is taken. Choose another slug.");
            }

            var now = time.GetUtcNow();
            org = new Org { Name = request.OrgName.Trim(), Slug = slug, CreatedAt = now };
            db.Orgs.Add(org);
            await db.SaveChangesAsync(ct);

            user = new AppUser
            {
                OrgId = org.Id,
                UserName = request.Email,
                Email = request.Email,
                DisplayName = request.DisplayName.Trim(),
                CreatedAt = now,
            };

            var created = await users.CreateAsync(user, request.Password);
            if (IsDuplicateEmail(created)) return Conflict("An account with that email already exists.");
            if (!created.Succeeded) return IdentityProblem(created);

            var assigned = await users.AddToRolesAsync(user, roles);
            if (!assigned.Succeeded) return IdentityProblem(assigned);

            await transaction.CommitAsync(ct);
        }
        catch (DbUpdateException ex) when (ex.IsUniqueViolation())
        {
            // Lost a race with a concurrent signup using the same slug or email.
            return Conflict("That organisation address or email is already taken.");
        }

        var tokens = await sessions.StartAsync(user, roles, ClientInfo.From(http), ct);
        return TypedResults.Created("/api/me", Respond(http, tokens, org, auth.Value));
    }

    private static async Task<Results<Ok<LoginResponse>, ProblemHttpResult>> Login(
        LoginRequest request,
        HttpContext http,
        UserManager<AppUser> users,
        ThreatLockDbContext db,
        SessionService sessions,
        DummyPasswordHash dummy,
        IOptions<AuthOptions> auth,
        CancellationToken ct)
    {
        var user = await users.FindByEmailAsync(request.Email);

        // Same answer, and roughly the same time, whether the email is unknown, the account is
        // locked or the password is wrong. Otherwise an attacker could probe which emails have
        // accounts (user enumeration). Hashing a dummy password evens out the timing.
        if (user is null || await users.IsLockedOutAsync(user))
        {
            dummy.Verify(request.Password);
            return Unauthorized(InvalidCredentials);
        }

        if (!await users.CheckPasswordAsync(user, request.Password))
        {
            // Counts towards lockout: 5 failures → locked for 15 minutes (AuthSetup).
            await users.AccessFailedAsync(user);
            return Unauthorized(InvalidCredentials);
        }

        await users.ResetAccessFailedCountAsync(user);

        var roles = (await users.GetRolesAsync(user)).ToArray();
        var tokens = await sessions.StartAsync(user, roles, ClientInfo.From(http), ct);
        var org = await db.Orgs.SingleAsync(o => o.Id == user.OrgId, ct);
        return TypedResults.Ok(Respond(http, tokens, org, auth.Value));
    }

    /// <summary>
    /// Swaps the refresh cookie for a new access token and a new refresh cookie (SPEC §6.4).
    /// </summary>
    private static async Task<Results<Ok<LoginResponse>, ProblemHttpResult>> Refresh(
        HttpContext http,
        SessionService sessions,
        ThreatLockDbContext db,
        IOptions<AuthOptions> auth,
        CancellationToken ct)
    {
        // CSRF guard #2 (the first is SameSite=Strict): a cross-site <form> can't add custom
        // headers, and a cross-site fetch that tries would need a CORS preflight we never allow.
        if (http.Request.Headers[RefreshCookie.CsrfHeader] != RefreshCookie.CsrfHeaderValue)
        {
            return TypedResults.Problem($"Missing {RefreshCookie.CsrfHeader} header.", statusCode: StatusCodes.Status403Forbidden);
        }

        var presented = RefreshCookie.Read(http.Request);
        if (string.IsNullOrEmpty(presented)) return Unauthorized("Not signed in.");

        var result = await sessions.RefreshAsync(presented, ct);
        switch (result.Status)
        {
            case RefreshStatus.Rotated:
                var org = await db.Orgs.SingleAsync(o => o.Id == result.Tokens!.User.OrgId, ct);
                return TypedResults.Ok(Respond(http, result.Tokens!, org, auth.Value));

            case RefreshStatus.Conflict:
                // Leave the cookie alone: the browser already holds the newer one from the
                // request that won the race. The client simply retries.
                return TypedResults.Problem("A refresh is already in progress. Retry.", statusCode: StatusCodes.Status409Conflict);

            default:
                RefreshCookie.Clear(http.Response, auth.Value.RefreshCookieSecure);
                return Unauthorized("Your session has ended. Please sign in again.");
        }
    }

    /// <summary>Ends this session on the server. From M3, the token stops working immediately.</summary>
    private static async Task<NoContent> Logout(HttpContext http, CurrentUser me, SessionStore store, IOptions<AuthOptions> auth, CancellationToken ct)
    {
        await store.RevokeAsync(me.SessionId, RevocationReasons.UserLogout, ct);
        RefreshCookie.Clear(http.Response, auth.Value.RefreshCookieSecure);
        return TypedResults.NoContent();
    }

    private static async Task<Results<Ok<UserView>, NotFound>> Me(
        CurrentUser current, UserManager<AppUser> users, ThreatLockDbContext db, CancellationToken ct)
    {
        var user = await users.FindByIdAsync(current.UserId.ToString());
        if (user is null) return TypedResults.NotFound();

        var org = await db.Orgs.SingleAsync(o => o.Id == user.OrgId, ct);
        var roles = await users.GetRolesAsync(user);
        return TypedResults.Ok(new UserView(user.Id, user.Email!, user.DisplayName, org.Id, org.Name, org.Slug, [.. roles]));
    }

    /// <summary>Your live sessions: where and when you're signed in (SPEC §14 "My sessions").</summary>
    private static async Task<Ok<List<SessionView>>> MySessions(CurrentUser me, ThreatLockDbContext db, TimeProvider time, CancellationToken ct)
    {
        var sessions = await ActiveSessionsQuery(db, me.UserId, time.GetUtcNow())
            .ToListAsync(ct);
        return TypedResults.Ok(sessions.Select(s => ToView(s, me.SessionId)).ToList());
    }

    private static async Task<Results<NoContent, NotFound>> RevokeMySession(
        Guid sid, CurrentUser me, ThreatLockDbContext db, SessionStore store, CancellationToken ct)
    {
        // Only your own sessions; someone else's session id is simply "not found".
        var mine = await db.Sessions.AnyAsync(s => s.Id == sid && s.UserId == me.UserId, ct);
        if (!mine) return TypedResults.NotFound();

        await store.RevokeAsync(sid, RevocationReasons.UserRevoked, ct);
        return TypedResults.NoContent();
    }

    internal static IQueryable<Session> ActiveSessionsQuery(ThreatLockDbContext db, Guid userId, DateTimeOffset now) =>
        db.Sessions
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.IdleExpiresAt > now && s.AbsoluteExpiresAt > now)
            .OrderByDescending(s => s.LastSeenAt);

    internal static SessionView ToView(Session s, Guid? currentSessionId) =>
        new(s.Id, s.CreatedAt, s.LastSeenAt, s.CreatedIp?.ToString(), s.CreatedDeviceId, s.CreatedUserAgent, s.Id == currentSessionId);

    private static LoginResponse Respond(HttpContext http, SessionTokens tokens, Org org, AuthOptions auth)
    {
        RefreshCookie.Set(http.Response, tokens.RefreshToken, tokens.RefreshExpiresAt, auth.RefreshCookieSecure);
        var user = tokens.User;
        var view = new UserView(user.Id, user.Email!, user.DisplayName, org.Id, org.Name, org.Slug, tokens.Roles);
        return new LoginResponse(tokens.Access.AccessToken, tokens.Access.ExpiresAt, view);
    }

    private static ProblemHttpResult Unauthorized(string detail) =>
        TypedResults.Problem(detail, statusCode: StatusCodes.Status401Unauthorized);

    private static ProblemHttpResult Conflict(string detail) =>
        TypedResults.Problem(detail, statusCode: StatusCodes.Status409Conflict);

    private static bool IsDuplicateEmail(IdentityResult result) =>
        result.Errors.Any(e => e.Code is nameof(IdentityErrorDescriber.DuplicateEmail) or nameof(IdentityErrorDescriber.DuplicateUserName));

    private static ValidationProblem IdentityProblem(IdentityResult result) =>
        TypedResults.ValidationProblem(result.Errors
            .GroupBy(e => e.Code.StartsWith("Password", StringComparison.Ordinal) ? "Password" : "Email")
            .ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray()));
}
