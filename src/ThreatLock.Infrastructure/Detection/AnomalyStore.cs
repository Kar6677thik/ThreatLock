using Npgsql;
using ThreatLock.Core.Detection;

namespace ThreatLock.Infrastructure.Detection;

public sealed record AnomalyUpsert(Guid Id, bool Created);

/// <summary>Persists detection signals as anomalies, de-duplicated (SPEC §8.3).</summary>
public sealed class AnomalyStore(NpgsqlDataSource db, TimeProvider time)
{
    /// <summary>
    /// Inserts a new anomaly, or, if one with the same <c>(org_id, dedupe_key)</c> exists, adds the
    /// event id to it (once). Safe to call twice with the same signal: that's what happens when an
    /// event is redelivered.
    /// <para>
    /// <c>xmax = 0</c> is a PostgreSQL detail worth knowing: a freshly inserted row has no deleting
    /// or updating transaction yet, so it tells us whether <c>ON CONFLICT</c> inserted or updated.
    /// </para>
    /// </summary>
    public async Task<AnomalyUpsert> UpsertAsync(DetectionSignal signal, CancellationToken ct)
    {
        await using var command = db.CreateCommand(
            """
            INSERT INTO anomalies (id, org_id, user_id, session_id, detector, severity, dedupe_key, evidence, event_ids, detected_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, ARRAY[$9]::uuid[], $10)
            ON CONFLICT (org_id, dedupe_key) DO UPDATE
                SET event_ids = CASE
                    WHEN $9 = ANY (anomalies.event_ids) THEN anomalies.event_ids
                    ELSE array_append(anomalies.event_ids, $9)
                END
            RETURNING id, (xmax = 0) AS created
            """);
        command.Parameters.AddWithValue(Guid.CreateVersion7());
        command.Parameters.AddWithValue(signal.OrgId);
        command.Parameters.AddWithValue(signal.UserId);
        command.Parameters.AddWithValue((object?)signal.SessionId ?? DBNull.Value);
        command.Parameters.AddWithValue(signal.Detector);
        command.Parameters.AddWithValue(signal.Severity.ToString().ToLowerInvariant());
        command.Parameters.AddWithValue(signal.DedupeKey);
        command.Parameters.AddWithValue(signal.Evidence.ToJsonString());
        command.Parameters.AddWithValue(signal.EventId);
        command.Parameters.AddWithValue(time.GetUtcNow());

        await using var reader = await command.ExecuteReaderAsync(ct);
        await reader.ReadAsync(ct);
        return new AnomalyUpsert(reader.GetGuid(0), reader.GetBoolean(1));
    }
}
