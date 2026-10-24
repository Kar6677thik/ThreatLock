using Npgsql;
using System.Text.Json.Nodes;
using ThreatLock.Core.Audit;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Policy;
using ThreatLock.Core.Response;
using ThreatLock.Infrastructure.Audit;
using ThreatLock.Infrastructure.Response;

namespace ThreatLock.Infrastructure.Detection;

public sealed record AnomalyUpsert(Guid Id, bool Created, Guid? JobId = null);

/// <summary>Persists detection signals as anomalies, de-duplicated (SPEC §8.3).</summary>
public sealed class AnomalyStore(NpgsqlDataSource db, AuditLog audit, TimeProvider time)
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
    /// <param name="decision">Stored only when the row is created: an anomaly is judged once, by
    /// the policy version in force when it was first detected (SPEC §9.1).</param>
    /// <param name="plan">If not null and the anomaly is new, a response job is created in the
    /// <em>same transaction</em> (SPEC §10.1): either both exist or neither does, so a crash
    /// can't leave a "responded" anomaly that nobody acts on. The decision is audited in the same
    /// transaction too (SPEC §11.1: decisions that lead to action).</param>
    public async Task<AnomalyUpsert> UpsertAsync(DetectionSignal signal, Decision decision, int policyVersion, ResponsePlan? plan, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        await using var connection = await db.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);

        await using var command = new NpgsqlCommand(
            """
            INSERT INTO anomalies (id, org_id, user_id, session_id, detector, severity, dedupe_key, evidence, event_ids, detected_at,
                                   decision, decision_reason, policy_version)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, ARRAY[$9]::uuid[], $10, $11, $12, $13)
            ON CONFLICT (org_id, dedupe_key) DO UPDATE
                SET event_ids = CASE
                    WHEN $9 = ANY (anomalies.event_ids) THEN anomalies.event_ids
                    ELSE array_append(anomalies.event_ids, $9)
                END
            RETURNING id, (xmax = 0) AS created
            """, connection, transaction);
        command.Parameters.AddWithValue(Guid.CreateVersion7());
        command.Parameters.AddWithValue(signal.OrgId);
        command.Parameters.AddWithValue(signal.UserId);
        command.Parameters.AddWithValue((object?)signal.SessionId ?? DBNull.Value);
        command.Parameters.AddWithValue(signal.Detector);
        command.Parameters.AddWithValue(signal.Severity.ToString().ToLowerInvariant());
        command.Parameters.AddWithValue(signal.DedupeKey);
        command.Parameters.AddWithValue(signal.Evidence.ToJsonString());
        command.Parameters.AddWithValue(signal.EventId);
        command.Parameters.AddWithValue(now);
        command.Parameters.AddWithValue(decision.Outcome.ToString().ToLowerInvariant());
        command.Parameters.AddWithValue(decision.Reason);
        command.Parameters.AddWithValue(policyVersion);

        Guid id;
        bool created;
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            await reader.ReadAsync(ct);
            (id, created) = (reader.GetGuid(0), reader.GetBoolean(1));
        }

        Guid? jobId = null;
        if (created && plan is not null)
        {
            jobId = await ResponseJobStore.CreateAsync(connection, transaction, id, signal, plan, now, ct);
            await audit.AppendAsync(connection, transaction, new AuditRecord(
                signal.OrgId, ActorTypes.System, null, AuditActions.AnomalyDecided, "user", signal.UserId.ToString(), id,
                new JsonObject
                {
                    ["detector"] = signal.Detector,
                    ["severity"] = signal.Severity.ToString().ToLowerInvariant(),
                    ["decision"] = decision.Outcome.ToString().ToLowerInvariant(),
                    ["reason"] = decision.Reason,
                    ["policyVersion"] = policyVersion,
                    ["action"] = plan.Action,
                },
                IdempotencyKey: $"anomaly:{id}"), ct);
        }

        await transaction.CommitAsync(ct);
        return new AnomalyUpsert(id, created, jobId);
    }
}
