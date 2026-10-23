using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ThreatLock.Core.Identity;
using ThreatLock.Infrastructure.Persistence;

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

public static class AuthEndpoints
{
    private const string InvalidCredentials = "Invalid email or password.";

    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var auth = app.MapGroup("/api/auth").WithTags("Auth");
        auth.MapPost("/register-org", RegisterOrg).AllowAnonymous();
        auth.MapPost("/login", Login).AllowAnonymous();
        auth.MapPost("/logout", Logout);

        app.MapGet("/api/me", Me).WithTags("Auth");
    }

    /// <summary>Creates an org and its owner in one transaction (SPEC §13). Demo convenience.</summary>
    private static async Task<Results<Created<LoginResponse>, ValidationProblem, ProblemHttpResult, NotFound>> RegisterOrg(
        RegisterOrgRequest request,
        IConfiguration config,
        ThreatLockDbContext db,
        UserManager<AppUser> users,
        TokenService tokens,
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

        try
        {
            return await CreateOrgAndOwner(request, slug, db, users, tokens, time, ct);
        }
        catch (DbUpdateException ex) when (ex.IsUniqueViolation())
        {
            // Lost a race with a concurrent signup using the same slug or email.
            return Conflict("That organisation address or email is already taken.");
        }
    }

    private static async Task<Results<Created<LoginResponse>, ValidationProblem, ProblemHttpResult, NotFound>> CreateOrgAndOwner(
        RegisterOrgRequest request,
        string slug,
        ThreatLockDbContext db,
        UserManager<AppUser> users,
        TokenService tokens,
        TimeProvider time,
        CancellationToken ct)
    {
        // Org, user and role assignment succeed or fail together. UserManager uses the same
        // scoped DbContext, so its writes join this transaction.
        await using var transaction = await db.Database.BeginTransactionAsync(ct);

        if (await db.Orgs.AnyAsync(o => o.Slug == slug, ct))
        {
            return Conflict("That organisation address is taken. Choose another slug.");
        }

        var now = time.GetUtcNow();
        var org = new Org { Name = request.OrgName.Trim(), Slug = slug, CreatedAt = now };
        db.Orgs.Add(org);
        await db.SaveChangesAsync(ct);

        var user = new AppUser
        {
            OrgId = org.Id,
            UserName = request.Email,
            Email = request.Email,
            DisplayName = request.DisplayName.Trim(),
            CreatedAt = now,
        };

        var created = await users.CreateAsync(user, request.Password);
        if (!created.Succeeded) return IdentityProblem(created);

        string[] roles = [Roles.Member, Roles.Owner];
        var assigned = await users.AddToRolesAsync(user, roles);
        if (!assigned.Succeeded) return IdentityProblem(assigned);

        await transaction.CommitAsync(ct);

        var token = tokens.Issue(user, roles);
        var view = new UserView(user.Id, user.Email, user.DisplayName, org.Id, org.Name, org.Slug, roles);
        return TypedResults.Created("/api/me", new LoginResponse(token.AccessToken, token.ExpiresAt, view));
    }

    private static async Task<Results<Ok<LoginResponse>, ProblemHttpResult>> Login(
        LoginRequest request,
        UserManager<AppUser> users,
        ThreatLockDbContext db,
        TokenService tokens,
        DummyPasswordHash dummy,
        CancellationToken ct)
    {
        var user = await users.FindByEmailAsync(request.Email);

        // Same answer, and roughly the same time, whether the email is unknown, the account is
        // locked or the password is wrong. Otherwise an attacker could probe which emails have
        // accounts (user enumeration). Hashing a dummy password evens out the timing.
        if (user is null || await users.IsLockedOutAsync(user))
        {
            dummy.Verify(request.Password);
            return Unauthorized();
        }

        if (!await users.CheckPasswordAsync(user, request.Password))
        {
            // Counts towards lockout: 5 failures → locked for 15 minutes (Program.cs).
            await users.AccessFailedAsync(user);
            return Unauthorized();
        }

        await users.ResetAccessFailedCountAsync(user);

        var roles = await users.GetRolesAsync(user);
        var org = await db.Orgs.SingleAsync(o => o.Id == user.OrgId, ct);
        var token = tokens.Issue(user, roles);
        var view = new UserView(user.Id, user.Email!, user.DisplayName, org.Id, org.Name, org.Slug, [.. roles]);
        return TypedResults.Ok(new LoginResponse(token.AccessToken, token.ExpiresAt, view));
    }

    /// <summary>
    /// In M2 there is nothing on the server to revoke: the token is stateless and stays valid
    /// until it expires. The client forgets it, but a copy keeps working. That is Break B1;
    /// M3 makes logout revoke a server-side session.
    /// </summary>
    private static NoContent Logout() => TypedResults.NoContent();

    private static async Task<Results<Ok<UserView>, NotFound>> Me(
        CurrentUser current, UserManager<AppUser> users, ThreatLockDbContext db, CancellationToken ct)
    {
        var user = await users.FindByIdAsync(current.UserId.ToString());
        if (user is null) return TypedResults.NotFound();

        var org = await db.Orgs.SingleAsync(o => o.Id == user.OrgId, ct);
        var roles = await users.GetRolesAsync(user);
        return TypedResults.Ok(new UserView(user.Id, user.Email!, user.DisplayName, org.Id, org.Name, org.Slug, [.. roles]));
    }

    private static ProblemHttpResult Unauthorized() =>
        TypedResults.Problem(InvalidCredentials, statusCode: StatusCodes.Status401Unauthorized);

    private static ProblemHttpResult Conflict(string detail) =>
        TypedResults.Problem(detail, statusCode: StatusCodes.Status409Conflict);

    private static Results<Created<LoginResponse>, ValidationProblem, ProblemHttpResult, NotFound> IdentityProblem(IdentityResult result)
    {
        // Duplicate email is a conflict, not a validation error.
        if (result.Errors.Any(e => e.Code is nameof(IdentityErrorDescriber.DuplicateEmail) or nameof(IdentityErrorDescriber.DuplicateUserName)))
        {
            return Conflict("An account with that email already exists.");
        }

        return TypedResults.ValidationProblem(result.Errors
            .GroupBy(e => e.Code.StartsWith("Password", StringComparison.Ordinal) ? "Password" : "Email")
            .ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray()));
    }
}
