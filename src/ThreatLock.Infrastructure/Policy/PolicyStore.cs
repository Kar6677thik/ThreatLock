using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using Npgsql;
using ThreatLock.Core.Audit;
using ThreatLock.Core.Policy;
using ThreatLock.Infrastructure.Audit;
using ThreatLock.Infrastructure.Persistence;

namespace ThreatLock.Infrastructure.Policy;

/// <summary>Bound from the <c>Policy</c> configuration section.</summary>
public sealed class PolicyOptions
{
    public const string SectionName = "Policy";

    /// <summary>
    /// How long the Worker may reuse a policy it has read. A policy edit therefore takes effect
    /// within this many seconds. Tests set 0.
    /// </summary>
    public int CacheSeconds { get; set; } = 10;
}

/// <summary>A policy version as stored. Version 0 means "never edited: the default policy".</summary>
public sealed record StoredPolicy(int Version, SecurityPolicy Policy, DateTimeOffset? UpdatedAt, Guid? UpdatedBy);

/// <summary>JSON format for policy documents: <c>"mode": "respond"</c>, <c>"minSeverity": "high"</c>.</summary>
public static class PolicyJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower, allowIntegerValues: false) },
    };
}

/// <summary>Reads and versions org policies (SPEC §9.1).</summary>
public sealed class PolicyStore(NpgsqlDataSource db, AuditLog audit, IOptions<PolicyOptions> options, TimeProvider time)
{
    private readonly ConcurrentDictionary<Guid, (StoredPolicy Policy, DateTimeOffset Expires)> cache = new();

    public async Task<StoredPolicy> GetCurrentAsync(Guid orgId, CancellationToken ct)
    {
        await using var command = db.CreateCommand(
            "SELECT version, document, updated_at, updated_by FROM org_policies WHERE org_id = $1 ORDER BY version DESC LIMIT 1");
        command.Parameters.AddWithValue(orgId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return new StoredPolicy(0, SecurityPolicy.Default, null, null);

        return new StoredPolicy(
            reader.GetInt32(0),
            JsonSerializer.Deserialize<SecurityPolicy>(reader.GetString(1), PolicyJson.Options)!,
            reader.GetFieldValue<DateTimeOffset>(2),
            reader.IsDBNull(3) ? null : reader.GetGuid(3));
    }

    /// <summary>
    /// For the Worker's hot path: reuses a recent read for up to <see cref="PolicyOptions.CacheSeconds"/>.
    /// The anomaly still records the version it actually used, so a decision made with a
    /// slightly stale policy is explainable.
    /// </summary>
    public async Task<StoredPolicy> GetCachedAsync(Guid orgId, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        if (cache.TryGetValue(orgId, out var entry) && entry.Expires > now) return entry.Policy;

        var policy = await GetCurrentAsync(orgId, ct);
        if (options.Value.CacheSeconds > 0) cache[orgId] = (policy, now.AddSeconds(options.Value.CacheSeconds));
        return policy;
    }

    /// <summary>
    /// Saves a new version, but only if the current version is still <paramref name="expectedVersion"/>.
    /// This is optimistic concurrency: without it, two admins editing at once would silently
    /// overwrite each other (a "lost update"). Returns the new version, or null if someone else
    /// saved first.
    /// </summary>
    public async Task<int?> SaveAsync(Guid orgId, int expectedVersion, SecurityPolicy policy, Guid updatedBy, CancellationToken ct)
    {
        await using var connection = await db.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var command = new NpgsqlCommand(
            """
            INSERT INTO org_policies (org_id, version, document, updated_by, updated_at)
            SELECT $1, $2 + 1, $3::jsonb, $4, $5
            WHERE COALESCE((SELECT max(version) FROM org_policies WHERE org_id = $1), 0) = $2
            """, connection, transaction);
        command.Parameters.AddWithValue(orgId);
        command.Parameters.AddWithValue(expectedVersion);
        command.Parameters.AddWithValue(JsonSerializer.Serialize(policy, PolicyJson.Options));
        command.Parameters.AddWithValue(updatedBy);
        command.Parameters.AddWithValue(time.GetUtcNow());

        try
        {
            if (await command.ExecuteNonQueryAsync(ct) == 0) return null;
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            // Two saves with the same expected version raced past the WHERE; the primary key let
            // exactly one through.
            return null;
        }

        // Audited in the same transaction: a policy change and its audit entry exist together or
        // not at all (SPEC §11.1). The entry names the versions; the document itself is in
        // org_policies, which is never updated in place.
        var version = expectedVersion + 1;
        await audit.AppendAsync(connection, transaction, new AuditRecord(
            orgId, ActorTypes.Admin, updatedBy, AuditActions.PolicyUpdated, "policy", version.ToString(CultureInfo.InvariantCulture),
            Details: new JsonObject { ["fromVersion"] = expectedVersion, ["toVersion"] = version }), ct);
        await transaction.CommitAsync(ct);
        return version;
    }

    public async Task<IReadOnlyList<(int Version, DateTimeOffset UpdatedAt, Guid? UpdatedBy)>> ListVersionsAsync(Guid orgId, CancellationToken ct)
    {
        var versions = new List<(int, DateTimeOffset, Guid?)>();
        await using var command = db.CreateCommand(
            "SELECT version, updated_at, updated_by FROM org_policies WHERE org_id = $1 ORDER BY version DESC");
        command.Parameters.AddWithValue(orgId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            versions.Add((reader.GetInt32(0), reader.GetFieldValue<DateTimeOffset>(1), reader.IsDBNull(2) ? null : reader.GetGuid(2)));
        }

        return versions;
    }

    /// <summary>A user's role names, for exclusion rules. Read only when a detector fires, which is rare.</summary>
    public async Task<IReadOnlyList<string>> GetUserRolesAsync(Guid userId, CancellationToken ct)
    {
        var roles = new List<string>();
        await using var command = db.CreateCommand(
            "SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1");
        command.Parameters.AddWithValue(userId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) roles.Add(reader.GetString(0));
        return roles;
    }
}
