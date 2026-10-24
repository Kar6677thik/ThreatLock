using Microsoft.Extensions.Logging;
using Npgsql;
using StackExchange.Redis;
using ThreatLock.Core.Sessions;

namespace ThreatLock.Infrastructure.Sessions;

/// <summary>Neither Redis nor PostgreSQL could answer "is this session alive?".</summary>
public sealed class SessionStoreUnavailableException(Exception inner)
    : Exception("Session status unavailable: Redis and PostgreSQL both failed.", inner);

/// <summary>
/// Answers "is session X still alive?" on every request, and revokes sessions (SPEC §6.5).
/// <para>
/// PostgreSQL is the source of truth. Redis caches each session's status under
/// <c>tl:sess:{sid}</c> as <c>a</c> (active, 60 s TTL) or <c>r</c> (revoked, kept until the
/// session would have expired anyway). Revoking *writes* <c>r</c> rather than deleting the key,
/// so a revoked session can never be served a stale <c>a</c>; the only exception is a failed
/// Redis write after the PostgreSQL commit, bounded by the 60 s TTL.
/// </para>
/// Redis down → every check goes to PostgreSQL (slower, still correct). Both down → throw, and
/// the caller answers 503: we fail closed, never treating "can't check" as "active".
/// </summary>
public sealed partial class SessionStore(
    NpgsqlDataSource db,
    IConnectionMultiplexer redis,
    TimeProvider time,
    ILogger<SessionStore> logger)
{
    private static readonly TimeSpan ActiveCacheTtl = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan LastSeenThrottle = TimeSpan.FromMinutes(1);
    private const string Active = "a";
    private const string Revoked = "r";

    private static RedisKey StatusKey(Guid sid) => $"tl:sess:{sid}";
    private static RedisKey SeenKey(Guid sid) => $"tl:sess-seen:{sid}";

    /// <summary>True if the session exists, isn't revoked and hasn't expired.</summary>
    public async Task<bool> IsActiveAsync(Guid sid, CancellationToken ct)
    {
        var cached = await TryRedisAsync(() => redis.GetDatabase().StringGetAsync(StatusKey(sid)));
        if (cached is { HasValue: true } value) return value == Active;

        bool active;
        DateTimeOffset absoluteExpiresAt;
        try
        {
            await using var command = db.CreateCommand(
                "SELECT revoked_at, idle_expires_at, absolute_expires_at FROM sessions WHERE id = $1");
            command.Parameters.AddWithValue(sid);
            await using var reader = await command.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) return false;   // unknown session id: not active

            DateTimeOffset? revokedAt = reader.IsDBNull(0) ? null : reader.GetFieldValue<DateTimeOffset>(0);
            var idleExpiresAt = reader.GetFieldValue<DateTimeOffset>(1);
            absoluteExpiresAt = reader.GetFieldValue<DateTimeOffset>(2);
            active = SessionRules.IsActive(revokedAt, idleExpiresAt, absoluteExpiresAt, time.GetUtcNow());
        }
        catch (Exception ex) when (ex is NpgsqlException or TimeoutException)
        {
            throw new SessionStoreUnavailableException(ex);
        }

        await TryRedisAsync(() => active
            ? redis.GetDatabase().StringSetAsync(StatusKey(sid), Active, ActiveCacheTtl)
            : redis.GetDatabase().StringSetAsync(StatusKey(sid), Revoked, RevokedTtl(absoluteExpiresAt)));
        return active;
    }

    /// <summary>
    /// Records activity at most once a minute per session, so a busy session costs one UPDATE a
    /// minute instead of one per request. Skipped entirely if Redis (the throttle) is down.
    /// </summary>
    public async Task TouchAsync(Guid sid, CancellationToken ct)
    {
        var first = await TryRedisAsync(() => redis.GetDatabase().StringSetAsync(SeenKey(sid), 1, LastSeenThrottle, When.NotExists));
        if (first != true) return;

        try
        {
            await using var command = db.CreateCommand("UPDATE sessions SET last_seen_at = $1 WHERE id = $2");
            command.Parameters.AddWithValue(time.GetUtcNow());
            command.Parameters.AddWithValue(sid);
            await command.ExecuteNonQueryAsync(ct);
        }
        catch (Exception ex) when (ex is NpgsqlException or TimeoutException)
        {
            LogTouchFailed(ex, sid);   // best effort: last-seen is informational
        }
    }

    /// <summary>Revokes one session. Returns false if it was already revoked or doesn't exist.</summary>
    public async Task<bool> RevokeAsync(Guid sid, string reason, CancellationToken ct) =>
        (await RevokeWhereAsync("id = $3", sid, reason, ct)).Count == 1;

    /// <summary>
    /// Revokes every live session of a user. Idempotent: a second call finds nothing to revoke
    /// (the "WHERE revoked_at IS NULL" makes sure of that). Returns the ids it revoked.
    /// </summary>
    public Task<IReadOnlyList<Guid>> RevokeAllForUserAsync(Guid userId, string reason, CancellationToken ct) =>
        RevokeWhereAsync("user_id = $3", userId, reason, ct);

    // `predicate` is spliced into the SQL text, so it must only ever be one of the constant
    // strings above, never anything derived from input. All values travel as $n parameters.
    private async Task<IReadOnlyList<Guid>> RevokeWhereAsync(string predicate, Guid id, string reason, CancellationToken ct)
    {
        var revoked = new List<(Guid Id, DateTimeOffset AbsoluteExpiresAt)>();

        // PostgreSQL first: once this commits, the revocation is real even if Redis fails below,
        // because cache misses and Redis outages both fall through to this table.
        await using (var command = db.CreateCommand(
            $"""
            UPDATE sessions SET revoked_at = $1, revoked_reason = $2
            WHERE {predicate} AND revoked_at IS NULL
            RETURNING id, absolute_expires_at
            """))
        {
            command.Parameters.AddWithValue(time.GetUtcNow());
            command.Parameters.AddWithValue(reason);
            command.Parameters.AddWithValue(id);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                revoked.Add((reader.GetGuid(0), reader.GetFieldValue<DateTimeOffset>(1)));
            }
        }

        await MarkRevokedAsync(revoked);
        return [.. revoked.Select(r => r.Id)];
    }

    /// <summary>
    /// Writes <c>r</c> into the Redis cache for sessions already revoked in PostgreSQL, so a cached
    /// <c>a</c> can't keep them alive for up to 60 s. Best effort and idempotent: writing the same
    /// value twice is harmless, which is why the response orchestrator can simply repeat it.
    /// </summary>
    public async Task MarkRevokedAsync(IEnumerable<(Guid Id, DateTimeOffset AbsoluteExpiresAt)> sessions)
    {
        foreach (var (sid, absoluteExpiresAt) in sessions)
        {
            var written = await TryRedisAsync(() => redis.GetDatabase().StringSetAsync(StatusKey(sid), Revoked, RevokedTtl(absoluteExpiresAt)));
            if (written != true) LogCacheWriteFailed(sid);
        }
    }

    // Keep "revoked" cached until the session would have expired anyway; after that, a cache miss
    // reads PostgreSQL, which also says "not active".
    private TimeSpan RevokedTtl(DateTimeOffset absoluteExpiresAt)
    {
        var remaining = absoluteExpiresAt - time.GetUtcNow();
        return remaining > TimeSpan.FromSeconds(1) ? remaining : TimeSpan.FromSeconds(1);
    }

    /// <summary>Runs a Redis call; on any Redis failure logs it and returns default instead of throwing.</summary>
    private async Task<T?> TryRedisAsync<T>(Func<Task<T>> call)
    {
        try
        {
            return await call();
        }
        catch (Exception ex) when (ex is RedisException or TimeoutException)
        {
            LogRedisUnavailable(ex);
            return default;
        }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Redis unavailable for session cache; falling back to PostgreSQL")]
    private partial void LogRedisUnavailable(Exception ex);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Session {SessionId} revoked in PostgreSQL but the Redis marker was not written; a cached 'active' may survive up to 60 s")]
    private partial void LogCacheWriteFailed(Guid sessionId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Could not update last_seen_at for session {SessionId}")]
    private partial void LogTouchFailed(Exception ex, Guid sessionId);
}
