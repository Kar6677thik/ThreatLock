using System.Text.Json;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using ThreatLock.Api.Auth;
using ThreatLock.Core.Audit;
using ThreatLock.Infrastructure.Audit;
using ThreatLock.Infrastructure.Persistence;

namespace ThreatLock.Api.Admin;

public sealed record AuditEntryView(
    long Seq,
    DateTimeOffset OccurredAt,
    string ActorType,
    Guid? ActorId,
    string? ActorName,
    string Action,
    string? TargetType,
    string? TargetId,
    Guid? AnomalyId,
    JsonElement Details,
    string PrevHash,
    string EntryHash);

/// <summary>A head saved earlier, e.g. copied from a previous verify into a password manager or another system.</summary>
public sealed record AnchorRequest(long Seq, string Hash);

public sealed record VerifyRequest(AnchorRequest? Anchor);

/// <summary>Browse and verify the org's audit chain (SPEC §11.4, §13). Security admins and owners.</summary>
public static class AuditEndpoints
{
    public static void MapAuditEndpoints(this IEndpointRouteBuilder app)
    {
        var audit = app.MapGroup("/api/admin/audit").WithTags("Admin: audit").RequireAuthorization(Policies.SecurityAdmin);
        audit.MapGet("/", List);
        audit.MapPost("/verify", Verify);
    }

    /// <summary>Oldest first, paged by seq: <c>?afterSeq=</c> is the last seq you have.</summary>
    private static async Task<Ok<List<AuditEntryView>>> List(
        AuditLog audit, ThreatLockDbContext db, CurrentUser me, long? afterSeq, int? limit, CancellationToken ct)
    {
        var rows = await audit.ReadAsync(me.RequiredOrgId, Math.Max(afterSeq ?? 0, 0), Math.Clamp(limit ?? 100, 1, 500), ct);
        var actorIds = rows.Select(r => r.Entry.Fields.ActorId).OfType<Guid>().Distinct().ToList();
        var names = await db.Users.Where(u => actorIds.Contains(u.Id)).ToDictionaryAsync(u => u.Id, u => u.DisplayName, ct);

        return TypedResults.Ok(rows.Select(r =>
        {
            var f = r.Entry.Fields;
            using var details = JsonDocument.Parse(r.DetailsJson);
            return new AuditEntryView(f.Seq, f.OccurredAt, f.ActorType, f.ActorId, f.ActorId is { } id ? names.GetValueOrDefault(id) : null,
                f.Action, f.TargetType, f.TargetId, f.AnomalyId, details.RootElement.Clone(),
                Convert.ToHexStringLower(f.PrevHash), Convert.ToHexStringLower(r.Entry.EntryHash));
        }).ToList());
    }

    /// <summary>
    /// Recomputes every hash from what's stored now. <c>{ ok, entries, head }</c>, or the first
    /// broken seq and why. Answers 200 either way: a broken chain is a finding, not an error.
    /// </summary>
    private static async Task<Results<Ok<VerifyResult>, ValidationProblem>> Verify(
        VerifyRequest? request, AuditLog audit, CurrentUser me, CancellationToken ct)
    {
        AuditAnchor? anchor = null;
        if (request?.Anchor is { } a)
        {
            if (a.Seq < 1 || a.Hash.Length != AuditChain.HashLength * 2 || !a.Hash.All(Uri.IsHexDigit))
            {
                return TypedResults.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["anchor"] = ["An anchor is a seq (≥ 1) and a 64-character hex hash from an earlier verify."],
                });
            }

            anchor = new AuditAnchor(a.Seq, a.Hash);
        }

        return TypedResults.Ok(await audit.VerifyAsync(me.RequiredOrgId, anchor, ct));
    }
}
