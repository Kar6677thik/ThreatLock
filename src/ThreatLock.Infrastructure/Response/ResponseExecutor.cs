using Microsoft.Extensions.Logging;
using Npgsql;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Response;
using ThreatLock.Core.Sessions;
using ThreatLock.Infrastructure.Sessions;

namespace ThreatLock.Infrastructure.Response;

/// <summary>The points between steps where a crash can be injected (tests and Break B4).</summary>
public enum ResponseStep { Revoked, CacheMarked, Notified }

/// <summary>
/// A test seam for "the Worker died right here". Production uses <see cref="NoFaults"/>; the
/// crash tests throw from it to prove every step can be rerun safely (SPEC §17).
/// </summary>
public interface IResponseFaultInjector
{
    ValueTask AfterAsync(ResponseStep completed, ClaimedJob job);
}

public sealed class NoFaults : IResponseFaultInjector
{
    public ValueTask AfterAsync(ResponseStep completed, ClaimedJob job) => ValueTask.CompletedTask;
}

/// <summary>
/// Carries out one response job (SPEC §10.2).
/// <para>
/// BREAK B4: this is the naive version, kept under the git tag <c>break/b4-naive-responder</c>.
/// It works when nothing fails. But a job is retried whenever the Worker dies before marking it
/// done, and these steps aren't safe to repeat: every retry notifies the admins again, and an
/// admin holding two notify roles gets one notification per role.
/// </para>
/// </summary>
public sealed partial class ResponseExecutor(
    NpgsqlDataSource db,
    SessionStore sessions,
    ResponseJobStore jobs,
    IResponseFaultInjector faults,
    TimeProvider time,
    ILogger<ResponseExecutor> logger)
{
    public async Task ExecuteAsync(ClaimedJob job, CancellationToken ct)
    {
        if (JobActions.Revokes(job.Action))
        {
            var revoked = await RevokeAsync(job, ct);
            await faults.AfterAsync(ResponseStep.Revoked, job);

            await sessions.MarkRevokedAsync(revoked);
            await faults.AfterAsync(ResponseStep.CacheMarked, job);
        }

        await NotifyAsync(job, ct);
        await faults.AfterAsync(ResponseStep.Notified, job);

        await FinishAsync(job, ct);
        LogExecuted(job.Id, job.Action, job.AnomalyId, job.Attempts);
    }

    /// <summary>Steps 1 and 3: revoke the user's sessions and, for revoke_and_lock, lock the account.</summary>
    private async Task<List<(Guid, DateTimeOffset)>> RevokeAsync(ClaimedJob job, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        await using var connection = await db.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);

        var revoked = new List<(Guid, DateTimeOffset)>();
        await using (var command = new NpgsqlCommand(
            """
            UPDATE sessions SET revoked_at = $1, revoked_reason = $2, revoked_by_anomaly_id = $3
            WHERE user_id = $4 AND revoked_at IS NULL AND created_at <= $5
            RETURNING id, absolute_expires_at
            """, connection, transaction))
        {
            command.Parameters.AddWithValue(now);
            command.Parameters.AddWithValue(RevocationReasons.AnomalyResponse);
            command.Parameters.AddWithValue(job.AnomalyId);
            command.Parameters.AddWithValue(job.UserId);
            command.Parameters.AddWithValue(job.Cutoff);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) revoked.Add((reader.GetGuid(0), reader.GetFieldValue<DateTimeOffset>(1)));
        }

        if (job.Action == JobActions.RevokeAndLock)
        {
            await using var lockUser = new NpgsqlCommand(
                "UPDATE users SET security_locked_at = $1, security_locked_reason = $2 WHERE id = $3", connection, transaction);
            lockUser.Parameters.AddWithValue(now);
            lockUser.Parameters.AddWithValue(job.Detector);
            lockUser.Parameters.AddWithValue(job.UserId);
            await lockUser.ExecuteNonQueryAsync(ct);
        }

        await transaction.CommitAsync(ct);
        return revoked;
    }

    /// <summary>Step 5 (naive): one notification per role membership, inserted unconditionally.</summary>
    private async Task NotifyAsync(ClaimedJob job, CancellationToken ct)
    {
        var title = await TitleAsync(job, ct);
        foreach (var role in job.NotifyRoles)
        {
            await using var command = db.CreateCommand(
                """
                INSERT INTO notifications (id, org_id, recipient_user_id, anomaly_id, title, created_at)
                SELECT gen_random_uuid(), u.org_id, u.id, $1, $2, $3
                FROM users u
                JOIN user_roles ur ON ur.user_id = u.id
                JOIN roles r ON r.id = ur.role_id
                WHERE u.org_id = $4 AND r.name = $5
                """);
            command.Parameters.AddWithValue(job.AnomalyId);
            command.Parameters.AddWithValue(title);
            command.Parameters.AddWithValue(time.GetUtcNow());
            command.Parameters.AddWithValue(job.OrgId);
            command.Parameters.AddWithValue(role);
            await command.ExecuteNonQueryAsync(ct);
        }
    }

    /// <summary>Step 6: stamp the anomaly and mark the job done.</summary>
    private async Task FinishAsync(ClaimedJob job, CancellationToken ct)
    {
        if (JobActions.Revokes(job.Action))
        {
            await using var command = db.CreateCommand("UPDATE anomalies SET responded_at = $1 WHERE id = $2");
            command.Parameters.AddWithValue(time.GetUtcNow());
            command.Parameters.AddWithValue(job.AnomalyId);
            await command.ExecuteNonQueryAsync(ct);
        }

        await jobs.CompleteAsync(job, ct);
    }

    /// <summary>
    /// "Tor exit node: Ben". Never an IP or note content (SPEC §10.4): titles show up in lists and
    /// badges; the details are one click away behind the anomaly link, where access is checked.
    /// </summary>
    private async Task<string> TitleAsync(ClaimedJob job, CancellationToken ct)
    {
        await using var command = db.CreateCommand("SELECT display_name FROM users WHERE id = $1");
        command.Parameters.AddWithValue(job.UserId);
        var name = await command.ExecuteScalarAsync(ct) as string ?? "unknown user";
        var title = $"{DetectorIds.DisplayName(job.Detector)}: {name}";
        return title.Length > 200 ? title[..200] : title;
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Response job {JobId} ({Action}) done for anomaly {AnomalyId} on attempt {Attempt}")]
    private partial void LogExecuted(Guid jobId, string action, Guid anomalyId, int attempt);
}
