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
}
