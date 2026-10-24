using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using ThreatLock.Api.Auth;
using ThreatLock.Core.Policy;
using ThreatLock.Infrastructure.Persistence;
using ThreatLock.Infrastructure.Policy;

namespace ThreatLock.Api.Admin;

public sealed record PolicyView(int Version, DateTimeOffset? UpdatedAt, string? UpdatedBy, SecurityPolicy Policy);

/// <summary>
/// A policy edit. <see cref="ExpectedVersion"/> is the version the editor started from; if
/// someone saved in between, the save is refused (409) instead of silently overwriting their change.
/// </summary>
public sealed record PolicyUpdate(int ExpectedVersion, SecurityPolicy? Policy);

public sealed record PolicyVersionView(int Version, DateTimeOffset UpdatedAt, string? UpdatedBy);

/// <summary>Read and edit the org's security policy (SPEC §9, §13). Security admins and owners only.</summary>
public static class PolicyEndpoints
{
    public static void MapPolicyEndpoints(this IEndpointRouteBuilder app)
    {
        var policy = app.MapGroup("/api/admin/policy").WithTags("Admin: policy").RequireAuthorization(Policies.SecurityAdmin);
        policy.MapGet("/", Get);
        policy.MapPut("/", Put);
        policy.MapGet("/versions", Versions);
        policy.MapGet("/versions/{version:int}", GetVersion);
    }

    private static async Task<Ok<PolicyView>> Get(PolicyStore store, ThreatLockDbContext db, CurrentUser me, CancellationToken ct)
    {
        var current = await store.GetCurrentAsync(me.RequiredOrgId, ct);
        return TypedResults.Ok(new PolicyView(current.Version, current.UpdatedAt, await NameAsync(db, current.UpdatedBy, ct), current.Policy));
    }

    private static async Task<Results<Ok<PolicyView>, ValidationProblem, ProblemHttpResult>> Put(
        PolicyUpdate update, PolicyStore store, ThreatLockDbContext db, CurrentUser me, CancellationToken ct)
    {
        if (update.Policy is null)
        {
            return TypedResults.ValidationProblem(new Dictionary<string, string[]> { ["policy"] = ["A policy document is required."] });
        }

        var policy = Normalise(update.Policy);
        var errors = PolicyValidator.Validate(policy);
        if (errors.Count > 0) return TypedResults.ValidationProblem(errors);

        var version = await store.SaveAsync(me.RequiredOrgId, update.ExpectedVersion, policy, me.UserId, ct);
        if (version is null)
        {
            return TypedResults.Problem(
                "Someone else changed the policy since you loaded it. Reload, reapply your change and save again.",
                statusCode: StatusCodes.Status409Conflict);
        }

        var saved = await store.GetCurrentAsync(me.RequiredOrgId, ct);
        return TypedResults.Ok(new PolicyView(saved.Version, saved.UpdatedAt, await NameAsync(db, saved.UpdatedBy, ct), saved.Policy));
    }

    private static async Task<Ok<List<PolicyVersionView>>> Versions(PolicyStore store, ThreatLockDbContext db, CurrentUser me, CancellationToken ct)
    {
        var versions = await store.ListVersionsAsync(me.RequiredOrgId, ct);
        var editorIds = versions.Select(v => v.UpdatedBy).OfType<Guid>().Distinct().ToList();
        var names = await db.Users.Where(u => editorIds.Contains(u.Id)).ToDictionaryAsync(u => u.Id, u => u.DisplayName, ct);
        return TypedResults.Ok(versions
            .Select(v => new PolicyVersionView(v.Version, v.UpdatedAt, v.UpdatedBy is { } id ? names.GetValueOrDefault(id) : null))
            .ToList());
    }

    /// <summary>A past version, so "which rules judged this anomaly?" can be answered exactly.</summary>
    private static async Task<Results<Ok<PolicyView>, NotFound>> GetVersion(int version, ThreatLockDbContext db, CurrentUser me, CancellationToken ct)
    {
        if (version == 0) return TypedResults.Ok(new PolicyView(0, null, null, SecurityPolicy.Default));

        var orgId = me.RequiredOrgId;
        var row = await db.OrgPolicies.SingleOrDefaultAsync(p => p.OrgId == orgId && p.Version == version, ct);
        if (row is null) return TypedResults.NotFound();

        var policy = System.Text.Json.JsonSerializer.Deserialize<SecurityPolicy>(row.Document, PolicyJson.Options)!;
        return TypedResults.Ok(new PolicyView(row.Version, row.UpdatedAt, await NameAsync(db, row.UpdatedBy, ct), policy));
    }

    /// <summary>Missing lists become empty lists, and names are trimmed, so the validator and evaluator never see nulls.</summary>
    private static SecurityPolicy Normalise(SecurityPolicy p) => new(
        [.. (p.TrustedNetworks ?? []).Select(n => n.Trim()).Where(n => n.Length > 0).Distinct()],
        [.. (p.ExcludedUserIds ?? []).Distinct()],
        [.. (p.ExcludedRoles ?? []).Select(r => r.Trim()).Distinct()],
        [.. (p.NotifyRoles ?? []).Select(r => r.Trim()).Distinct()],
        p.Detectors ?? [],
        p.Response ?? new ResponsePolicy());

    private static async Task<string?> NameAsync(ThreatLockDbContext db, Guid? userId, CancellationToken ct) =>
        userId is null ? null : await db.Users.Where(u => u.Id == userId).Select(u => u.DisplayName).SingleOrDefaultAsync(ct);
}
