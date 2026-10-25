using System.Text.Json;
using StackExchange.Redis;
using ThreatLock.Core.Detection;
using ThreatLock.Infrastructure.Events;

namespace ThreatLock.Infrastructure.Detection;

/// <summary>
/// Detector scratch state in Redis (SPEC §8.1). Each key expires on its own (the detector picks
/// the TTL), so state for users who've gone quiet cleans itself up.
/// </summary>
public sealed class RedisDetectorState(IConnectionMultiplexer redis) : IDetectorState
{
    private static RedisKey LocationKey(Guid userId) => $"tl:det:loc:{userId}";

    public async ValueTask<LastLocation?> GetLastLocationAsync(Guid userId, CancellationToken ct)
    {
        var value = await redis.GetDatabase().StringGetAsync(LocationKey(userId));
        return value.HasValue ? JsonSerializer.Deserialize<LastLocation>(value.ToString(), EventJson.Options) : null;
    }

    public async ValueTask SetLastLocationAsync(Guid userId, LastLocation location, TimeSpan ttl, CancellationToken ct) =>
        await redis.GetDatabase().StringSetAsync(LocationKey(userId), JsonSerializer.Serialize(location, EventJson.Options), ttl);

    private static RedisKey Key(string key) => $"tl:det:{key}";

    /// <summary>
    /// A sorted set per window, scored by event time in milliseconds. ZADD of an existing member
    /// just updates its score, which is what makes a redelivered event count once. Old members are
    /// trimmed on every call, and the key expires once the window has gone quiet.
    /// </summary>
    public async ValueTask<long> CountInWindowAsync(string key, string member, DateTimeOffset at, TimeSpan window, CancellationToken ct)
    {
        var redisKey = Key(key);
        var now = at.ToUnixTimeMilliseconds();
        var from = (at - window).ToUnixTimeMilliseconds();

        // MULTI/EXEC: the four commands run back to back, with nobody else's in between.
        var transaction = redis.GetDatabase().CreateTransaction();
        _ = transaction.SortedSetAddAsync(redisKey, member, now);
        _ = transaction.SortedSetRemoveRangeByScoreAsync(redisKey, double.NegativeInfinity, from, Exclude.Stop);
        var count = transaction.SortedSetLengthAsync(redisKey, from, now, Exclude.Start);
        _ = transaction.KeyExpireAsync(redisKey, window + window + TimeSpan.FromMinutes(1));
        await transaction.ExecuteAsync();
        return await count;
    }

    public async ValueTask<string?> GetValueAsync(string key, CancellationToken ct) =>
        await redis.GetDatabase().StringGetAsync(Key(key)) is { HasValue: true } value ? value.ToString() : null;

    public async ValueTask<bool> SetValueAsync(string key, string value, TimeSpan ttl, bool onlyIfAbsent, CancellationToken ct) =>
        await redis.GetDatabase().StringSetAsync(Key(key), value, ttl, onlyIfAbsent ? When.NotExists : When.Always);
}
