using System.Text.Json;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using ThreatLock.Api.Auth;
using ThreatLock.Infrastructure.Persistence;

namespace ThreatLock.Api.Admin;

public sealed record AnomalyView(
    Guid Id,
    string Detector,
    string Severity,
    Guid UserId,
    string? UserName,
    Guid? SessionId,
    DateTimeOffset DetectedAt,
    int EventCount,
    IReadOnlyList<Guid> EventIds,
    JsonElement Evidence,
    string? Decision,
    string? DecisionReason,
    int? PolicyVersion,
    DateTimeOffset? RespondedAt = null,
    ResponseJobView? Response = null,
    int RevokedSessions = 0);

/// <summary>
/// Read-only view of anomalies for admins (SPEC §13). The detail adds the response timeline:
/// the job, its steps and how many sessions it revoked (M6).
/// </summary>
public static class AnomalyEndpoints
{
    public static void MapAnomalyEndpoints(this IEndpointRouteBuilder app)
    {
        var anomalies = app.MapGroup("/api/admin/anomalies").WithTags("Admin: anomalies").RequireAuthorization(Policies.Admin);
        anomalies.MapGet("/", List);
        anomalies.MapGet("/{id:guid}", Get);
    }

    private static async Task<Ok<List<AnomalyView>>> List(
        ThreatLockDbContext db, CurrentUser me, string? detector, string? decision, int? limit, CancellationToken ct)
    {
        var orgId = me.RequiredOrgId;
        var query = db.Anomalies.Where(a => a.OrgId == orgId);
        if (!string.IsNullOrWhiteSpace(detector)) query = query.Where(a => a.Detector == detector);
        if (!string.IsNullOrWhiteSpace(decision)) query = query.Where(a => a.Decision == decision);

        var rows = await query
            .OrderByDescending(a => a.DetectedAt)
            .Take(Math.Clamp(limit ?? 50, 1, 200))
            .Select(a => new { Anomaly = a, UserName = db.Users.Where(u => u.Id == a.UserId).Select(u => u.DisplayName).FirstOrDefault() })
            .ToListAsync(ct);
        return TypedResults.Ok(rows.Select(r => ToView(r.Anomaly, r.UserName)).ToList());
    }

    private static async Task<Results<Ok<AnomalyView>, NotFound>> Get(Guid id, ThreatLockDbContext db, CurrentUser me, CancellationToken ct)
    {
        var orgId = me.RequiredOrgId;
        var row = await db.Anomalies
            .Where(a => a.Id == id && a.OrgId == orgId)
            .Select(a => new { Anomaly = a, UserName = db.Users.Where(u => u.Id == a.UserId).Select(u => u.DisplayName).FirstOrDefault() })
            .SingleOrDefaultAsync(ct);
        if (row is null) return TypedResults.NotFound();

        var job = await db.ResponseJobs.SingleOrDefaultAsync(j => j.AnomalyId == id, ct);
        var revoked = await db.Sessions.CountAsync(s => s.RevokedByAnomalyId == id, ct);
        return TypedResults.Ok(ToView(row.Anomaly, row.UserName) with
        {
            Response = job is null ? null : ResponseJobView.From(job),
            RevokedSessions = revoked,
        });
    }

    private static AnomalyView ToView(Anomaly a, string? userName)
    {
        using var evidence = JsonDocument.Parse(a.Evidence);
        return new AnomalyView(a.Id, a.Detector, a.Severity, a.UserId, userName, a.SessionId, a.DetectedAt,
            a.EventIds.Count, a.EventIds, evidence.RootElement.Clone(), a.Decision, a.DecisionReason, a.PolicyVersion, a.RespondedAt);
    }
}
