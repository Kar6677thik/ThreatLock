using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using ThreatLock.Api.Auth;
using ThreatLock.Core.Response;
using ThreatLock.Infrastructure.Persistence;
using ThreatLock.Infrastructure.Response;

namespace ThreatLock.Api.Admin;

/// <summary>A response job as admins see it: on the Jobs screen and in an anomaly's response timeline.</summary>
public sealed record ResponseJobView(
    Guid Id,
    Guid AnomalyId,
    Guid UserId,
    string Action,
    string Status,
    int Attempts,
    string? LastError,
    DateTimeOffset CreatedAt,
    DateTimeOffset NextAttemptAt,
    DateTimeOffset? RevokedAt,
    DateTimeOffset? NotifiedAt,
    DateTimeOffset? FinishedAt)
{
    public static ResponseJobView From(ResponseJob j) =>
        new(j.Id, j.AnomalyId, j.UserId, j.Action, j.Status, j.Attempts, j.LastError, j.CreatedAt, j.NextAttemptAt, j.RevokedAt, j.NotifiedAt, j.FinishedAt);
}

/// <summary>Failed and dead response jobs, and "Retry" (SPEC §13, §14 "Jobs").</summary>
public static class ResponseJobEndpoints
{
    public static void MapResponseJobEndpoints(this IEndpointRouteBuilder app)
    {
        var jobs = app.MapGroup("/api/admin/response-jobs").WithTags("Admin: response jobs").RequireAuthorization(Policies.SecurityAdmin);
        jobs.MapGet("/", List);
        jobs.MapPost("/{id:guid}/retry", Retry);
    }

    /// <summary>
    /// By default, jobs needing attention: dead ones, and pending ones that already failed at
    /// least once (they're backing off). <c>?status=</c> picks one status instead.
    /// </summary>
    private static async Task<Results<Ok<List<ResponseJobView>>, ValidationProblem>> List(
        ThreatLockDbContext db, CurrentUser me, string? status, CancellationToken ct)
    {
        var orgId = me.RequiredOrgId;
        var query = db.ResponseJobs.Where(j => j.OrgId == orgId);
        if (string.IsNullOrWhiteSpace(status))
        {
            query = query.Where(j => j.Status == JobStatuses.Dead || (j.Status == JobStatuses.Pending && j.LastError != null));
        }
        else if (JobStatuses.All.Contains(status))
        {
            query = query.Where(j => j.Status == status);
        }
        else
        {
            return TypedResults.ValidationProblem(new Dictionary<string, string[]>
            {
                ["status"] = [$"Allowed: {string.Join(", ", JobStatuses.All)}."],
            });
        }

        var jobs = await query.OrderByDescending(j => j.CreatedAt).Take(100).ToListAsync(ct);
        return TypedResults.Ok(jobs.Select(ResponseJobView.From).ToList());
    }

    private static async Task<Results<NoContent, ProblemHttpResult>> Retry(Guid id, ResponseJobStore store, CurrentUser me, CancellationToken ct) =>
        await store.RetryAsync(id, me.RequiredOrgId, ct)
            ? TypedResults.NoContent()
            : TypedResults.Problem("Only dead jobs in your organisation can be retried.", statusCode: StatusCodes.Status409Conflict);
}
