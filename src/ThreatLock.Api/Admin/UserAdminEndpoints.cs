using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ThreatLock.Api.Auth;
using ThreatLock.Core.Identity;
using ThreatLock.Infrastructure.Persistence;

namespace ThreatLock.Api.Admin;

public sealed record CreateUserRequest(
    [property: Required, EmailAddress, StringLength(254)] string Email,
    [property: Required, StringLength(100, MinimumLength = 1)] string DisplayName,
    [property: Required, StringLength(128)] string Password,
    string[]? Roles);

public sealed record SetRolesRequest([property: Required] string[] Roles);

public sealed record AdminUserView(Guid Id, string Email, string DisplayName, IReadOnlyList<string> Roles, DateTimeOffset CreatedAt);

public sealed record RevokeSessionsResponse(Guid UserId, string Effect);

/// <summary>
/// User management inside the caller's org (SPEC §13). The Users table is not tenant-filtered
/// (login has to find a user by email before knowing their org), so every query here filters
/// by org explicitly, and a user from another org is simply "not found".
/// </summary>
public static class UserAdminEndpoints
{
    public static void MapUserAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var admin = app.MapGroup("/api/admin/users").WithTags("Admin: users");
        admin.MapGet("/", List).RequireAuthorization(Policies.Admin);
        admin.MapPost("/", Create).RequireAuthorization(Policies.Admin);
        admin.MapPut("/{id:guid}/roles", SetRoles).RequireAuthorization(Policies.Owner);
        admin.MapPost("/{id:guid}/revoke-sessions", RevokeSessions).RequireAuthorization(Policies.SecurityAdmin);
    }

    private static async Task<Ok<List<AdminUserView>>> List(ThreatLockDbContext db, CurrentUser me, CancellationToken ct)
    {
        var orgId = me.RequiredOrgId;
        var users = await db.Users
            .Where(u => u.OrgId == orgId)
            .OrderBy(u => u.CreatedAt)
            .Select(u => new AdminUserView(
                u.Id,
                u.Email!,
                u.DisplayName,
                db.UserRoles.Where(ur => ur.UserId == u.Id)
                    .Join(db.Roles, ur => ur.RoleId, r => r.Id, (_, r) => r.Name!)
                    .OrderBy(name => name)
                    .ToList(),
                u.CreatedAt))
            .ToListAsync(ct);
        return TypedResults.Ok(users);
    }

    private static async Task<Results<Created<AdminUserView>, ValidationProblem, ProblemHttpResult, ForbidHttpResult>> Create(
        CreateUserRequest request, UserManager<AppUser> users, ThreatLockDbContext db, CurrentUser me, TimeProvider time, CancellationToken ct)
    {
        var roles = NormaliseRoles(request.Roles);
        if (roles is null) return UnknownRoles();
        if (!MayGrant(me, roles)) return TypedResults.Forbid();

        var user = new AppUser
        {
            OrgId = me.RequiredOrgId,
            UserName = request.Email,
            Email = request.Email,
            DisplayName = request.DisplayName.Trim(),
            CreatedAt = time.GetUtcNow(),
        };

        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        try
        {
            var created = await users.CreateAsync(user, request.Password);
            if (IsDuplicateEmail(created)) return EmailTaken();
            if (!created.Succeeded) return IdentityProblem(created);
            var assigned = await users.AddToRolesAsync(user, roles);
            if (!assigned.Succeeded) return IdentityProblem(assigned);
            await transaction.CommitAsync(ct);
        }
        catch (DbUpdateException ex) when (ex.IsUniqueViolation())
        {
            return EmailTaken();
        }

        return TypedResults.Created($"/api/admin/users/{user.Id}",
            new AdminUserView(user.Id, user.Email, user.DisplayName, roles, user.CreatedAt));
    }

    /// <summary>Owner only. Replaces the user's roles.</summary>
    private static async Task<Results<Ok<AdminUserView>, NotFound, ValidationProblem, ProblemHttpResult>> SetRoles(
        Guid id, SetRolesRequest request, UserManager<AppUser> users, ThreatLockDbContext db, CurrentUser me, CancellationToken ct)
    {
        var roles = NormaliseRoles(request.Roles);
        if (roles is null) return UnknownRoles();

        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == id && u.OrgId == me.RequiredOrgId, ct);
        if (user is null) return TypedResults.NotFound();

        // An org must never end up without an owner; the simplest rule is that owners can't
        // demote themselves.
        if (user.Id == me.UserId && !roles.Contains(Roles.Owner))
        {
            return TypedResults.Problem("You can't remove your own owner role.", statusCode: StatusCodes.Status400BadRequest);
        }

        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var current = await users.GetRolesAsync(user);
        var removed = await users.RemoveFromRolesAsync(user, current.Except(roles));
        if (!removed.Succeeded) return IdentityProblem(removed);
        var added = await users.AddToRolesAsync(user, roles.Except(current));
        if (!added.Succeeded) return IdentityProblem(added);
        await transaction.CommitAsync(ct);

        return TypedResults.Ok(new AdminUserView(user.Id, user.Email!, user.DisplayName, roles, user.CreatedAt));
    }

    /// <summary>
    /// M2 (naive) version, kept honest. Rotating the security stamp is all the server can do,
    /// and it affects nothing: access tokens are stateless, so every token already issued keeps
    /// working until it expires. This is Break B1 (SPEC §15). M3 replaces it with real
    /// session revocation.
    /// </summary>
    private static async Task<Results<Ok<RevokeSessionsResponse>, NotFound>> RevokeSessions(
        Guid id, UserManager<AppUser> users, ThreatLockDbContext db, CurrentUser me, CancellationToken ct)
    {
        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == id && u.OrgId == me.RequiredOrgId, ct);
        if (user is null) return TypedResults.NotFound();

        await users.UpdateSecurityStampAsync(user);
        return TypedResults.Ok(new RevokeSessionsResponse(user.Id,
            "Security stamp rotated. Access tokens are stateless, so tokens already issued stay valid until they expire."));
    }

    /// <summary>Validates role names and always includes "member". Null means an unknown role was sent.</summary>
    private static string[]? NormaliseRoles(string[]? requested)
    {
        var roles = (requested ?? []).Select(r => r.Trim().ToLowerInvariant()).Append(Roles.Member).Distinct().Order().ToArray();
        return roles.All(Roles.IsKnown) ? roles : null;
    }

    /// <summary>Only owners can hand out admin, security_admin or owner (privilege-escalation guard).</summary>
    private static bool MayGrant(CurrentUser me, IEnumerable<string> roles) =>
        me.IsInRole(Roles.Owner) || !roles.Intersect(Roles.Privileged).Any();

    private static ValidationProblem UnknownRoles() =>
        TypedResults.ValidationProblem(new Dictionary<string, string[]>
        {
            ["Roles"] = [$"Allowed roles: {string.Join(", ", Roles.All)}."],
        });

    private static ProblemHttpResult EmailTaken() =>
        TypedResults.Problem("An account with that email already exists.", statusCode: StatusCodes.Status409Conflict);

    private static bool IsDuplicateEmail(IdentityResult result) =>
        result.Errors.Any(e => e.Code is nameof(IdentityErrorDescriber.DuplicateEmail) or nameof(IdentityErrorDescriber.DuplicateUserName));

    private static ValidationProblem IdentityProblem(IdentityResult result) =>
        TypedResults.ValidationProblem(result.Errors
            .GroupBy(e => e.Code.StartsWith("Password", StringComparison.Ordinal) ? "Password" : "Email")
            .ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray()));
}
