using System.ComponentModel.DataAnnotations;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.HttpResults;
using ThreatLock.Api.Audit;
using ThreatLock.Api.Events;
using ThreatLock.Core.Audit;
using ThreatLock.Infrastructure.Audit;
using ThreatLock.Core.Events;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ThreatLock.Api.Auth;
using ThreatLock.Core.Identity;
using ThreatLock.Core.Sessions;
using ThreatLock.Infrastructure.Persistence;
using ThreatLock.Infrastructure.Sessions;

namespace ThreatLock.Api.Admin;

public sealed record CreateUserRequest(
    [property: Required, EmailAddress, StringLength(254)] string Email,
    [property: Required, StringLength(100, MinimumLength = 1)] string DisplayName,
    [property: Required, StringLength(128)] string Password,
    string[]? Roles);

public sealed record SetRolesRequest([property: Required] string[] Roles);

/// <param name="SecurityLockedAt">Set when a revoke_and_lock response locked the account (M6).</param>
public sealed record AdminUserView(
    Guid Id, string Email, string DisplayName, IReadOnlyList<string> Roles, DateTimeOffset CreatedAt,
    DateTimeOffset? SecurityLockedAt = null, string? SecurityLockedReason = null);

public sealed record RevokeSessionsResponse(Guid UserId, int RevokedSessions);

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
        admin.MapGet("/{id:guid}/sessions", UserSessions).RequireAuthorization(Policies.Admin);
        admin.MapPost("/{id:guid}/revoke-sessions", RevokeSessions).RequireAuthorization(Policies.SecurityAdmin);
        admin.MapPost("/{id:guid}/unlock", Unlock).RequireAuthorization(Policies.SecurityAdmin);
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
                u.CreatedAt,
                u.SecurityLockedAt,
                u.SecurityLockedReason))
            .ToListAsync(ct);
        return TypedResults.Ok(users);
    }

    private static async Task<Results<Created<AdminUserView>, ValidationProblem, ProblemHttpResult, ForbidHttpResult>> Create(
        CreateUserRequest request, UserManager<AppUser> users, ThreatLockDbContext db, CurrentUser me, AuditLog audit, TimeProvider time,
        CancellationToken ct)
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
            await audit.AppendAsync(db, new AuditRecord(user.OrgId, ActorTypes.Admin, me.UserId, AuditActions.UserCreated, "user", user.Id.ToString(),
                Details: new JsonObject { ["email"] = user.Email, ["roles"] = RolesJson(roles) }), ct);
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
        Guid id, SetRolesRequest request, UserManager<AppUser> users, ThreatLockDbContext db, CurrentUser me, AuditLog audit, CancellationToken ct)
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
        await audit.AppendAsync(db, new AuditRecord(user.OrgId, ActorTypes.Admin, me.UserId, AuditActions.RolesChanged, "user", user.Id.ToString(),
            Details: new JsonObject { ["from"] = RolesJson(current.Order()), ["to"] = RolesJson(roles) }), ct);
        await transaction.CommitAsync(ct);

        return TypedResults.Ok(new AdminUserView(user.Id, user.Email!, user.DisplayName, roles, user.CreatedAt,
            user.SecurityLockedAt, user.SecurityLockedReason));
    }

    /// <summary>A user's live sessions, for an admin deciding whether to revoke them.</summary>
    private static async Task<Results<Ok<List<SessionView>>, NotFound>> UserSessions(
        Guid id, ThreatLockDbContext db, CurrentUser me, TimeProvider time, CancellationToken ct)
    {
        if (!await db.Users.AnyAsync(u => u.Id == id && u.OrgId == me.RequiredOrgId, ct)) return TypedResults.NotFound();

        var sessions = await AuthEndpoints.ActiveSessionsQuery(db, id, time.GetUtcNow()).ToListAsync(ct);
        return TypedResults.Ok(sessions.Select(s => AuthEndpoints.ToView(s, me.SessionId)).ToList());
    }

    /// <summary>
    /// Signs the user out everywhere, effective on their very next request (SPEC §6.6). In M2
    /// this only rotated the security stamp and changed nothing for issued tokens (Break B1).
    /// </summary>
    private static async Task<Results<Ok<RevokeSessionsResponse>, NotFound>> RevokeSessions(
        Guid id, ThreatLockDbContext db, SessionStore store, ActivityRecorder activity, AuditLog audit, CurrentUser me, CancellationToken ct)
    {
        if (!await db.Users.AnyAsync(u => u.Id == id && u.OrgId == me.RequiredOrgId, ct)) return TypedResults.NotFound();

        var revoked = await store.RevokeAllForUserAsync(id, RevocationReasons.AdminManual, ct);
        foreach (var sid in revoked)
        {
            // About the *target* user and session; "by" records which admin did it.
            await activity.RecordAsync(EventTypes.SessionRevoked, me.RequiredOrgId, id, sid,
                new JsonObject { ["reason"] = RevocationReasons.AdminManual, ["by"] = me.UserId.ToString() }, ct);
        }

        await audit.AppendAsync(new AuditRecord(me.RequiredOrgId, ActorTypes.Admin, me.UserId, AuditActions.SessionsRevokedByAdmin, "user", id.ToString(),
            Details: new JsonObject
            {
                ["reason"] = RevocationReasons.AdminManual,
                ["revokedSessions"] = new JsonArray([.. revoked.Select(s => JsonValue.Create(s.ToString()))]),
            }), ct);
        return TypedResults.Ok(new RevokeSessionsResponse(id, revoked.Count));
    }

    /// <summary>
    /// Clears a security lock (SPEC §10.3): password reset is out of scope, so an admin vouching
    /// for the user is the way back in. Idempotent: unlocking an unlocked user is a no-op. The
    /// unlock and its audit entry commit together.
    /// </summary>
    private static async Task<Results<NoContent, NotFound>> Unlock(Guid id, ThreatLockDbContext db, CurrentUser me, AuditLog audit, CancellationToken ct)
    {
        var orgId = me.RequiredOrgId;
        var lockedReason = await db.Users.Where(u => u.Id == id && u.OrgId == orgId)
            .Select(u => new { u.SecurityLockedAt, u.SecurityLockedReason }).SingleOrDefaultAsync(ct);
        if (lockedReason is null) return TypedResults.NotFound();
        if (lockedReason.SecurityLockedAt is null) return TypedResults.NoContent();   // nothing to unlock, nothing to audit

        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        await db.Users
            .Where(u => u.Id == id && u.OrgId == orgId)
            .ExecuteUpdateAsync(set => set
                .SetProperty(u => u.SecurityLockedAt, (DateTimeOffset?)null)
                .SetProperty(u => u.SecurityLockedReason, (string?)null), ct);
        await audit.AppendAsync(db, new AuditRecord(orgId, ActorTypes.Admin, me.UserId, AuditActions.UserUnlocked, "user", id.ToString(),
            Details: new JsonObject { ["lockedReason"] = lockedReason.SecurityLockedReason }), ct);
        await transaction.CommitAsync(ct);
        return TypedResults.NoContent();
    }

    private static JsonArray RolesJson(IEnumerable<string> roles) => new([.. roles.Select(r => JsonValue.Create(r))]);

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
