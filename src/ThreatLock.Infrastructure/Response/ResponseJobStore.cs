using Microsoft.Extensions.Options;
using Npgsql;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Response;

namespace ThreatLock.Infrastructure.Response;

/// <summary>Bound from the <c>Responses</c> configuration section.</summary>
public sealed class ResponseOptions
{
    public const string SectionName = "Responses";

    /// <summary>How often an idle orchestrator looks for due jobs. A NOTIFY usually wakes it sooner.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromMilliseconds(250);

    /// <summary>How long a claimed job is ours. If we crash, another Worker takes it after this.</summary>
    public TimeSpan Lease { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>Whether this process runs response jobs at all. Tests switch it off for extra Workers.</summary>
    public bool Enabled { get; set; } = true;
}

/// <summary>A job as claimed by a Worker: everything needed to run it.</summary>
public sealed record ClaimedJob(
    Guid Id,
    Guid AnomalyId,
    Guid OrgId,
    Guid UserId,
    string Detector,
    DateTimeOffset Cutoff,
    string Action,
    IReadOnlyList<string> NotifyRoles,
    int Attempts);

/// <summary>
/// The response job queue (SPEC §10.1, ADR-0003): a PostgreSQL table, not the Redis stream,
/// because these jobs must never be lost and must commit together with their anomaly.
/// </summary>
public sealed class ResponseJobStore(NpgsqlDataSource db, IOptions<ResponseOptions> options, TimeProvider time)
{
    /// <summary>The channel a new job is announced on, so an idle Worker starts it at once.</summary>
    public const string Channel = "response_jobs";

    /// <summary>
    /// Inserts the job inside the caller's transaction, and queues a NOTIFY. PostgreSQL delivers
    /// a NOTIFY only when the transaction commits, so a Worker is never woken for a job it can't
    /// see yet, and a rolled-back job wakes nobody.
    /// </summary>
    internal static async Task<Guid> CreateAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, Guid anomalyId, DetectionSignal signal, ResponsePlan plan,
        DateTimeOffset now, CancellationToken ct)
    {
        var id = Guid.CreateVersion7();
        await using var command = new NpgsqlCommand(
            $"""
            INSERT INTO response_jobs (id, anomaly_id, org_id, user_id, cutoff, action, notify_roles, status, attempts, next_attempt_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, '{JobStatuses.Pending}', 0, $5, $5)
            """, connection, transaction);
        command.Parameters.AddWithValue(id);
        command.Parameters.AddWithValue(anomalyId);
        command.Parameters.AddWithValue(signal.OrgId);
        command.Parameters.AddWithValue(signal.UserId);
        command.Parameters.AddWithValue(now);
        command.Parameters.AddWithValue(plan.Action);
        command.Parameters.AddWithValue(plan.NotifyRoles.ToArray());
        await command.ExecuteNonQueryAsync(ct);

        await using var notify = new NpgsqlCommand($"SELECT pg_notify('{Channel}', $1)", connection, transaction);
        notify.Parameters.AddWithValue(id.ToString());
        await notify.ExecuteNonQueryAsync(ct);
        return id;
    }

    /// <summary>
    /// Claims the oldest due job, or returns null. <c>FOR UPDATE SKIP LOCKED</c> lets many
    /// Workers claim concurrently: each skips rows another transaction has locked instead of
    /// waiting for them, so no two Workers get the same job and none of them blocks.
    /// <para>
    /// A job is due if it's pending and its retry time has come, or if it's "running" but the
    /// lease has expired: the Worker that claimed it crashed (or hung) without finishing.
    /// Attempts are counted at claim time, so a job that crashes its Worker every time still
    /// runs out of attempts.
    /// </para>
    /// </summary>
    public async Task<ClaimedJob?> ClaimAsync(CancellationToken ct)
    {
        var now = time.GetUtcNow();
        await using var command = db.CreateCommand(
            $"""
            UPDATE response_jobs j
            SET status = '{JobStatuses.Running}', locked_until = $2, attempts = j.attempts + 1
            FROM anomalies a
            WHERE a.id = j.anomaly_id
              AND j.id = (
                SELECT id FROM response_jobs
                WHERE (status = '{JobStatuses.Pending}' AND next_attempt_at <= $1)
                   OR (status = '{JobStatuses.Running}' AND locked_until < $1)
                ORDER BY created_at
                FOR UPDATE SKIP LOCKED
                LIMIT 1)
            RETURNING j.id, j.anomaly_id, j.org_id, j.user_id, a.detector, j.cutoff, j.action, j.notify_roles, j.attempts
            """);
        command.Parameters.AddWithValue(now);
        command.Parameters.AddWithValue(now + options.Value.Lease);

        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        return new ClaimedJob(
            reader.GetGuid(0), reader.GetGuid(1), reader.GetGuid(2), reader.GetGuid(3), reader.GetString(4),
            reader.GetFieldValue<DateTimeOffset>(5), reader.GetString(6), reader.GetFieldValue<string[]>(7), reader.GetInt32(8));
    }

    /// <summary>
    /// Marks the job done. Only if it's still ours and running: if our lease expired and another
    /// Worker finished it first, this is a harmless no-op.
    /// </summary>
    public async Task<bool> CompleteAsync(ClaimedJob job, CancellationToken ct)
    {
        await using var command = db.CreateCommand(
            $"""
            UPDATE response_jobs SET status = '{JobStatuses.Succeeded}', finished_at = $2, locked_until = NULL, last_error = NULL
            WHERE id = $1 AND status = '{JobStatuses.Running}'
            """);
        command.Parameters.AddWithValue(job.Id);
        command.Parameters.AddWithValue(time.GetUtcNow());
        return await command.ExecuteNonQueryAsync(ct) == 1;
    }

    /// <summary>
    /// Hands a job back when this Worker is shutting down mid-run (a deploy, a scale-down), so
    /// another Worker can start it now instead of after the lease. The attempt isn't counted: the
    /// job didn't fail, we stopped. A crash can't do this, which is what the lease is for.
    /// </summary>
    public async Task ReleaseAsync(ClaimedJob job, CancellationToken ct)
    {
        await using var command = db.CreateCommand(
            $"""
            UPDATE response_jobs SET status = '{JobStatuses.Pending}', locked_until = NULL, attempts = attempts - 1, next_attempt_at = $2
            WHERE id = $1 AND status = '{JobStatuses.Running}'
            """);
        command.Parameters.AddWithValue(job.Id);
        command.Parameters.AddWithValue(time.GetUtcNow());
        await command.ExecuteNonQueryAsync(ct);
    }

    /// <summary>
    /// An admin's "Retry" on a dead job: back to pending with a fresh set of attempts. Only dead
    /// jobs, and only in the admin's org. The step markers are kept, so steps that had already
    /// succeeded before the job died are not repeated.
    /// </summary>
    public async Task<bool> RetryAsync(Guid jobId, Guid orgId, CancellationToken ct)
    {
        await using var connection = await db.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var command = new NpgsqlCommand(
            $"""
            UPDATE response_jobs SET status = '{JobStatuses.Pending}', attempts = 0, next_attempt_at = $3, finished_at = NULL
            WHERE id = $1 AND org_id = $2 AND status = '{JobStatuses.Dead}'
            """, connection, transaction);
        command.Parameters.AddWithValue(jobId);
        command.Parameters.AddWithValue(orgId);
        command.Parameters.AddWithValue(time.GetUtcNow());
        if (await command.ExecuteNonQueryAsync(ct) == 0) return false;

        await using var notify = new NpgsqlCommand($"SELECT pg_notify('{Channel}', $1)", connection, transaction);
        notify.Parameters.AddWithValue(jobId.ToString());
        await notify.ExecuteNonQueryAsync(ct);
        await transaction.CommitAsync(ct);
        return true;
    }

    /// <summary>
    /// Puts a failed job back with exponential backoff, or marks it dead after
    /// <see cref="ResponseBackoff.MaxAttempts"/>. Dead jobs wait for an admin's "Retry".
    /// Returns the new status.
    /// </summary>
    public async Task<string> FailAsync(ClaimedJob job, Exception error, CancellationToken ct)
    {
        var dead = ResponseBackoff.IsExhausted(job.Attempts);
        var status = dead ? JobStatuses.Dead : JobStatuses.Pending;
        var now = time.GetUtcNow();

        await using var command = db.CreateCommand(
            $"""
            UPDATE response_jobs SET status = $2, next_attempt_at = $3, locked_until = NULL, last_error = $4,
                                     finished_at = CASE WHEN $2 = '{JobStatuses.Dead}' THEN $5 END
            WHERE id = $1 AND status = '{JobStatuses.Running}'
            """);
        command.Parameters.AddWithValue(job.Id);
        command.Parameters.AddWithValue(status);
        command.Parameters.AddWithValue(now + ResponseBackoff.Delay(job.Attempts, Random.Shared.NextDouble()));
        // Type and message only: no stack trace, and capped, since admins see this in the UI.
        var message = $"{error.GetType().Name}: {error.Message}";
        command.Parameters.AddWithValue(message.Length > 2000 ? message[..2000] : message);
        command.Parameters.AddWithValue(now);
        await command.ExecuteNonQueryAsync(ct);
        return status;
    }
}
