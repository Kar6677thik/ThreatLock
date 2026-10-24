using Microsoft.Extensions.Logging;
using Npgsql;
using System.Text.Json.Nodes;
using ThreatLock.Core.Audit;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Response;
using ThreatLock.Core.Sessions;
using ThreatLock.Infrastructure.Audit;
using ThreatLock.Infrastructure.Sessions;

namespace ThreatLock.Infrastructure.Response;

/// <summary>The points between steps where a crash can be injected (tests and Break B4).</summary>
public enum ResponseStep { Revoked, CacheMarked, Audited, Notified }

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
/// Carries out one response job (SPEC §10.2). A job runs again whenever a Worker dies before
/// marking it done, and possibly on two Workers at once if a lease expires mid-run, so every
/// step must be safe to repeat. Each one is, on its own:
/// <list type="number">
/// <item>Revoke (and lock): skipped if the job's <c>revoked_at</c> marker is set; the marker
/// commits with the revocation, so they can't disagree.</item>
/// <item>Mark the revoked sessions in Redis: rerun every time, from the sessions this anomaly
/// revoked (not from what step 1 happened to return on this run). Writing "r" twice is harmless.</item>
/// <item>Audit entry, keyed <c>response:{anomalyId}</c>: the key is unique, so a retry finds
/// the entry already there and writes nothing.</item>
/// <item>Notify: skipped if <c>notified_at</c> is set; recipients are distinct people, not role
/// memberships; <c>UNIQUE (anomaly_id, recipient_user_id)</c> is the backstop.</item>
/// <item>Finish: conditional updates only.</item>
/// </list>
/// The naive first version is kept under the git tag <c>break/b4-naive-responder</c> (Break B4).
/// </summary>
public sealed partial class ResponseExecutor(
    NpgsqlDataSource db,
    SessionStore sessions,
    ResponseJobStore jobs,
    AuditLog audit,
    IResponseFaultInjector faults,
    TimeProvider time,
    ILogger<ResponseExecutor> logger)
{
    /// <summary>Repeated anomalies about one user within this window share one unread notification.</summary>
    public static readonly TimeSpan GroupingWindow = TimeSpan.FromHours(1);

    public async Task ExecuteAsync(ClaimedJob job, CancellationToken ct)
    {
        if (JobActions.Revokes(job.Action))
        {
            await RevokeAsync(job, ct);
            await faults.AfterAsync(ResponseStep.Revoked, job);

            var revoked = await RevokedByAnomalyAsync(job, ct);
            await sessions.MarkRevokedAsync(revoked);
            await faults.AfterAsync(ResponseStep.CacheMarked, job);

            await AuditAsync(job, revoked, ct);
            await faults.AfterAsync(ResponseStep.Audited, job);
        }

        await NotifyAsync(job, ct);
        await faults.AfterAsync(ResponseStep.Notified, job);

        await FinishAsync(job, ct);
        LogExecuted(job.Id, job.Action, job.AnomalyId, job.Attempts);
    }

    /// <summary>
    /// Steps 1 and 3 in one transaction. <c>FOR UPDATE</c> on the job row serialises two Workers
    /// running the same job (after a lease expired), so the marker check can't race.
    /// </summary>
    private async Task RevokeAsync(ClaimedJob job, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        await using var connection = await db.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        if (await MarkerSetAsync(connection, transaction, job, "revoked_at", ct)) return;

        // The cutoff protects the real user: if they signed in again after the detection, a
        // revoke-only response leaves that new session alone. A lock is different: the account
        // is now closed to everyone, so every live session goes.
        var cutoff = job.Action == JobActions.RevokeAndLock ? now : job.Cutoff;
        await using (var revoke = new NpgsqlCommand(
            """
            UPDATE sessions SET revoked_at = $1, revoked_reason = $2, revoked_by_anomaly_id = $3
            WHERE user_id = $4 AND revoked_at IS NULL AND created_at <= $5
            """, connection, transaction))
        {
            revoke.Parameters.AddWithValue(now);
            revoke.Parameters.AddWithValue(RevocationReasons.AnomalyResponse);
            revoke.Parameters.AddWithValue(job.AnomalyId);
            revoke.Parameters.AddWithValue(job.UserId);
            revoke.Parameters.AddWithValue(cutoff);
            await revoke.ExecuteNonQueryAsync(ct);
        }

        if (job.Action == JobActions.RevokeAndLock)
        {
            // "Only if null": an existing lock keeps its original time and reason.
            await using var lockUser = new NpgsqlCommand(
                "UPDATE users SET security_locked_at = $1, security_locked_reason = $2 WHERE id = $3 AND security_locked_at IS NULL",
                connection, transaction);
            lockUser.Parameters.AddWithValue(now);
            lockUser.Parameters.AddWithValue(job.Detector);
            lockUser.Parameters.AddWithValue(job.UserId);
            await lockUser.ExecuteNonQueryAsync(ct);
        }

        await SetMarkerAsync(connection, transaction, job, "revoked_at", now, ct);
        await transaction.CommitAsync(ct);
    }

    private async Task<List<(Guid, DateTimeOffset)>> RevokedByAnomalyAsync(ClaimedJob job, CancellationToken ct)
    {
        await using var command = db.CreateCommand("SELECT id, absolute_expires_at FROM sessions WHERE revoked_by_anomaly_id = $1 ORDER BY id");
        command.Parameters.AddWithValue(job.AnomalyId);
        var revoked = new List<(Guid, DateTimeOffset)>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) revoked.Add((reader.GetGuid(0), reader.GetFieldValue<DateTimeOffset>(1)));
        return revoked;
    }

    /// <summary>
    /// Step 4: what the response did, as evidence. Rerunning it is a no-op because of the
    /// idempotency key; the session list comes from durable state, so it's the same on a retry.
    /// </summary>
    private async Task AuditAsync(ClaimedJob job, List<(Guid Id, DateTimeOffset)> revoked, CancellationToken ct) =>
        await audit.AppendAsync(new AuditRecord(
            job.OrgId, ActorTypes.System, null, AuditActions.ResponseExecuted, "user", job.UserId.ToString(), job.AnomalyId,
            new JsonObject
            {
                ["action"] = job.Action,
                ["detector"] = job.Detector,
                ["locked"] = job.Action == JobActions.RevokeAndLock,
                ["revokedSessions"] = new JsonArray([.. revoked.Select(s => JsonValue.Create(s.Id.ToString()))]),
            },
            IdempotencyKey: $"response:{job.AnomalyId}"), ct);

    /// <summary>
    /// Step 5: one notification per distinct admin, grouped per (recipient, subject user) within
    /// <see cref="GroupingWindow"/>, all in one transaction with the <c>notified_at</c> marker.
    /// </summary>
    private async Task NotifyAsync(ClaimedJob job, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        await using var connection = await db.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        if (await MarkerSetAsync(connection, transaction, job, "notified_at", ct)) return;

        // Two different jobs about the same user (say Tor and impossible travel, seconds apart)
        // could otherwise both see "no unread entry yet" and both insert one. A transaction-scoped
        // advisory lock on the subject user makes them take turns; it's released at commit.
        await using (var serialise = new NpgsqlCommand("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", connection, transaction))
        {
            serialise.Parameters.AddWithValue($"notify:{job.UserId}");
            await serialise.ExecuteNonQueryAsync(ct);
        }

        var title = await TitleAsync(connection, transaction, job, ct);
        foreach (var recipient in await RecipientsAsync(connection, transaction, job, ct))
        {
            await using var group = new NpgsqlCommand(
                """
                UPDATE notifications SET count = count + 1, last_anomaly_id = $1, updated_at = $2
                WHERE id = (
                    SELECT id FROM notifications
                    WHERE recipient_user_id = $3 AND subject_user_id = $4 AND read_at IS NULL AND created_at > $5
                    ORDER BY created_at DESC
                    LIMIT 1)
                """, connection, transaction);
            group.Parameters.AddWithValue(job.AnomalyId);
            group.Parameters.AddWithValue(now);
            group.Parameters.AddWithValue(recipient);
            group.Parameters.AddWithValue(job.UserId);
            group.Parameters.AddWithValue(now - GroupingWindow);
            if (await group.ExecuteNonQueryAsync(ct) == 1) continue;

            await using var insert = new NpgsqlCommand(
                """
                INSERT INTO notifications (id, org_id, recipient_user_id, subject_user_id, anomaly_id, last_anomaly_id, count, title, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $5, 1, $6, $7, $7)
                ON CONFLICT (anomaly_id, recipient_user_id) DO NOTHING
                """, connection, transaction);
            insert.Parameters.AddWithValue(Guid.CreateVersion7());
            insert.Parameters.AddWithValue(job.OrgId);
            insert.Parameters.AddWithValue(recipient);
            insert.Parameters.AddWithValue(job.UserId);
            insert.Parameters.AddWithValue(job.AnomalyId);
            insert.Parameters.AddWithValue(title);
            insert.Parameters.AddWithValue(now);
            await insert.ExecuteNonQueryAsync(ct);
        }

        await SetMarkerAsync(connection, transaction, job, "notified_at", now, ct);
        await transaction.CommitAsync(ct);
    }

    /// <summary>
    /// Distinct people holding any of the notify roles. The naive version looped over roles, so
    /// someone who is both admin and security_admin got two notifications.
    /// </summary>
    private static async Task<List<Guid>> RecipientsAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, ClaimedJob job, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(
            """
            SELECT DISTINCT u.id
            FROM users u
            JOIN user_roles ur ON ur.user_id = u.id
            JOIN roles r ON r.id = ur.role_id
            WHERE u.org_id = $1 AND r.name = ANY ($2)
            ORDER BY u.id
            """, connection, transaction);
        command.Parameters.AddWithValue(job.OrgId);
        command.Parameters.AddWithValue(job.NotifyRoles.ToArray());
        var recipients = new List<Guid>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) recipients.Add(reader.GetGuid(0));
        return recipients;
    }

    /// <summary>Step 6: stamp the anomaly (first time only) and mark the job done, together.</summary>
    private async Task FinishAsync(ClaimedJob job, CancellationToken ct)
    {
        if (JobActions.Revokes(job.Action))
        {
            await using var command = db.CreateCommand("UPDATE anomalies SET responded_at = $1 WHERE id = $2 AND responded_at IS NULL");
            command.Parameters.AddWithValue(time.GetUtcNow());
            command.Parameters.AddWithValue(job.AnomalyId);
            await command.ExecuteNonQueryAsync(ct);
        }

        await jobs.CompleteAsync(job, ct);
    }

    // `marker` is one of two constant column names above, never input.
    private static async Task<bool> MarkerSetAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, ClaimedJob job, string marker, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand($"SELECT {marker} IS NOT NULL FROM response_jobs WHERE id = $1 FOR UPDATE", connection, transaction);
        command.Parameters.AddWithValue(job.Id);
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    private static async Task SetMarkerAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, ClaimedJob job, string marker,
        DateTimeOffset now, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand($"UPDATE response_jobs SET {marker} = $1 WHERE id = $2", connection, transaction);
        command.Parameters.AddWithValue(now);
        command.Parameters.AddWithValue(job.Id);
        await command.ExecuteNonQueryAsync(ct);
    }

    /// <summary>
    /// "Tor exit node: Ben". Never an IP or note content (SPEC §10.4): titles show up in lists and
    /// badges; the details are one click away behind the anomaly link, where access is checked.
    /// </summary>
    private static async Task<string> TitleAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, ClaimedJob job, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SELECT display_name FROM users WHERE id = $1", connection, transaction);
        command.Parameters.AddWithValue(job.UserId);
        var name = await command.ExecuteScalarAsync(ct) as string ?? "unknown user";
        var title = $"{DetectorIds.DisplayName(job.Detector)}: {name}";
        return title.Length > 200 ? title[..200] : title;
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Response job {JobId} ({Action}) done for anomaly {AnomalyId} on attempt {Attempt}")]
    private partial void LogExecuted(Guid jobId, string action, Guid anomalyId, int attempt);
}
