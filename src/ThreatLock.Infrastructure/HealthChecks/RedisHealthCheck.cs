using Microsoft.Extensions.Diagnostics.HealthChecks;
using StackExchange.Redis;

namespace ThreatLock.Infrastructure.HealthChecks;

/// <summary>Ready only if Redis answers a PING.</summary>
internal sealed class RedisHealthCheck(IConnectionMultiplexer redis) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            var latency = await redis.GetDatabase().PingAsync();
            return HealthCheckResult.Healthy($"PING {latency.TotalMilliseconds:F1} ms");
        }
        catch (Exception ex) when (ex is RedisException or TimeoutException)
        {
            return HealthCheckResult.Unhealthy("Redis unreachable", ex);
        }
    }
}
