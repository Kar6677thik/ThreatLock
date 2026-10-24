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
    int? PolicyVersion);

/// <summary>
/// Read-only view of anomalies for admins (SPEC §13). The admin UI and decisions arrive in M5;
/// M4 exposes the data so detections can be inspected end to end.
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
        return row is null ? TypedResults.NotFound() : TypedResults.Ok(ToView(row.Anomaly, row.UserName));
    }

    private static AnomalyView ToView(Anomaly a, string? userName)
    {
        using var evidence = JsonDocument.Parse(a.Evidence);
        return new AnomalyView(a.Id, a.Detector, a.Severity, a.UserId, userName, a.SessionId, a.DetectedAt,
            a.EventIds.Count, a.EventIds, evidence.RootElement.Clone(), a.Decision, a.DecisionReason, a.PolicyVersion);
    }
}
