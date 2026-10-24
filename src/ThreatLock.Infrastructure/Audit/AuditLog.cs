using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Npgsql;
using ThreatLock.Core.Audit;

namespace ThreatLock.Infrastructure.Audit;

/// <summary>
/// What to audit (SPEC §11.1). Never put passwords, tokens, refresh-token hashes or note content
/// in <see cref="Details"/>.
/// </summary>
public sealed record AuditRecord(
    Guid OrgId,
    string ActorType,
    Guid? ActorId,
    string Action,
    string? TargetType = null,
    string? TargetId = null,
    Guid? AnomalyId = null,
    JsonObject? Details = null,
    string? IdempotencyKey = null);

/// <param name="Created">False if an entry with the same idempotency key already existed.</param>
public sealed record AuditAppended(long Seq, bool Created);

/// <summary>A stored entry as admins see it.</summary>
public sealed record AuditRow(AuditEntry Entry, string DetailsJson);

/// <summary>
/// Appends to and verifies each org's hash chain (SPEC §11.2, ADR-0005).
/// <para>
/// Appending takes a transaction-scoped advisory lock on the org, reads the chain's head,
/// computes the new hash and inserts, all in one transaction. Without the lock, two concurrent
/// appends would both read head N and both write N+1: a fork. <c>PRIMARY KEY (org_id, seq)</c>
/// would reject the second, but the lock means it never gets that far.
/// </para>
/// </summary>
public sealed class AuditLog(NpgsqlDataSource db, TimeProvider time)
{
    /// <summary>Appends in a transaction of its own.</summary>
    public async Task<AuditAppended> AppendAsync(AuditRecord record, CancellationToken ct)
    {
        await using var connection = await db.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        var appended = await AppendAsync(connection, transaction, record, ct);
        await transaction.CommitAsync(ct);
        return appended;
    }

    /// <summary>
    /// Appends inside the caller's transaction, so the entry commits (or rolls back) with the
    /// change it describes. The org's lock is held until that transaction ends.
    /// </summary>
    public async Task<AuditAppended> AppendAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, AuditRecord record, CancellationToken ct)
    {
        await using (var serialise = new NpgsqlCommand("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", connection, transaction))
        {
            serialise.Parameters.AddWithValue($"audit:{record.OrgId}");
            await serialise.ExecuteNonQueryAsync(ct);
        }

        if (record.IdempotencyKey is not null)
        {
            // Checked under the lock, so a retry racing the original can't both pass.
            await using var existing = new NpgsqlCommand("SELECT seq FROM audit_log WHERE idempotency_key = $1", connection, transaction);
            existing.Parameters.AddWithValue(record.IdempotencyKey);
            if (await existing.ExecuteScalarAsync(ct) is long seq) return new AuditAppended(seq, Created: false);
        }

        long headSeq = 0;
        var prevHash = AuditChain.Genesis;
        await using (var head = new NpgsqlCommand(
            "SELECT seq, entry_hash FROM audit_log WHERE org_id = $1 ORDER BY seq DESC LIMIT 1", connection, transaction))
        {
            head.Parameters.AddWithValue(record.OrgId);
            await using var reader = await head.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct)) (headSeq, prevHash) = (reader.GetInt64(0), reader.GetFieldValue<byte[]>(1));
        }

        var fields = new AuditFields(
            record.OrgId, headSeq + 1, AuditChain.ToStoredPrecision(time.GetUtcNow()), record.ActorType, record.ActorId, record.Action,
            record.TargetType, record.TargetId, record.AnomalyId, record.Details ?? [], record.IdempotencyKey, prevHash);
        var hash = AuditChain.Hash(fields);

        await using var insert = new NpgsqlCommand(
            """
            INSERT INTO audit_log (org_id, seq, occurred_at, actor_type, actor_id, action, target_type, target_id, anomaly_id,
                                   details, idempotency_key, prev_hash, entry_hash)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13)
            """, connection, transaction);
        insert.Parameters.AddWithValue(fields.OrgId);
        insert.Parameters.AddWithValue(fields.Seq);
        insert.Parameters.AddWithValue(fields.OccurredAt);
        insert.Parameters.AddWithValue(fields.ActorType);
        insert.Parameters.AddWithValue((object?)fields.ActorId ?? DBNull.Value);
        insert.Parameters.AddWithValue(fields.Action);
        insert.Parameters.AddWithValue((object?)fields.TargetType ?? DBNull.Value);
        insert.Parameters.AddWithValue((object?)fields.TargetId ?? DBNull.Value);
        insert.Parameters.AddWithValue((object?)fields.AnomalyId ?? DBNull.Value);
        insert.Parameters.AddWithValue(AuditChain.CanonicalJson(fields.Details));
        insert.Parameters.AddWithValue((object?)fields.IdempotencyKey ?? DBNull.Value);
        insert.Parameters.AddWithValue(fields.PrevHash);
        insert.Parameters.AddWithValue(hash);
        await insert.ExecuteNonQueryAsync(ct);
        return new AuditAppended(fields.Seq, Created: true);
    }

    /// <summary>A page of the org's chain, oldest first, after <paramref name="afterSeq"/>.</summary>
    public async Task<IReadOnlyList<AuditRow>> ReadAsync(Guid orgId, long afterSeq, int limit, CancellationToken ct)
    {
        var rows = new List<AuditRow>();
        await foreach (var row in StreamAsync(orgId, afterSeq, limit, ct)) rows.Add(row);
        return rows;
    }

    /// <summary>
    /// Walks the whole chain from seq 1, streaming rows rather than loading them all. The hash is
    /// recomputed from what's stored now; <paramref name="anchor"/> is a head saved earlier,
    /// somewhere the database's admins can't reach.
    /// </summary>
    public async Task<VerifyResult> VerifyAsync(Guid orgId, AuditAnchor? anchor, CancellationToken ct)
    {
        var verifier = new AuditChainVerifier(anchor);
        await foreach (var row in StreamAsync(orgId, 0, int.MaxValue, ct))
        {
            if (verifier.Add(row.Entry) is { } failure) return failure;
        }

        return verifier.Complete();
    }

    private async IAsyncEnumerable<AuditRow> StreamAsync(Guid orgId, long afterSeq, int limit, [EnumeratorCancellation] CancellationToken ct)
    {
        await using var command = db.CreateCommand(
            """
            SELECT org_id, seq, occurred_at, actor_type, actor_id, action, target_type, target_id, anomaly_id,
                   details::text, idempotency_key, prev_hash, entry_hash
            FROM audit_log WHERE org_id = $1 AND seq > $2 ORDER BY seq LIMIT $3
            """);
        command.Parameters.AddWithValue(orgId);
        command.Parameters.AddWithValue(afterSeq);
        command.Parameters.AddWithValue(limit);
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var details = reader.GetString(9);
            var fields = new AuditFields(
                reader.GetGuid(0),
                reader.GetInt64(1),
                reader.GetFieldValue<DateTimeOffset>(2),
                reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetGuid(4),
                reader.GetString(5),
                reader.IsDBNull(6) ? null : reader.GetString(6),
                reader.IsDBNull(7) ? null : reader.GetString(7),
                reader.IsDBNull(8) ? null : reader.GetGuid(8),
                JsonNode.Parse(details) as JsonObject ?? [],
                reader.IsDBNull(10) ? null : reader.GetString(10),
                reader.GetFieldValue<byte[]>(11));
            yield return new AuditRow(new AuditEntry(fields, reader.GetFieldValue<byte[]>(12)), details);
        }
    }
}
