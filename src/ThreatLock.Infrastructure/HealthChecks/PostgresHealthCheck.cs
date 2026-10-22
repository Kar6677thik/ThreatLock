using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;

namespace ThreatLock.Infrastructure.HealthChecks;

/// <summary>
/// Ready only if we can open a connection and run a trivial query. Opening a connection alone
/// can succeed from the pool even when the server has gone away, so we round-trip a query.
/// </summary>
internal sealed class PostgresHealthCheck(NpgsqlDataSource dataSource) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var command = dataSource.CreateCommand("SELECT 1");
            await command.ExecuteScalarAsync(cancellationToken);
            return HealthCheckResult.Healthy();
        }
        catch (Exception ex) when (ex is NpgsqlException or TimeoutException or InvalidOperationException)
        {
            // Never put connection strings or stack traces in a health response; the message is enough.
            return HealthCheckResult.Unhealthy("PostgreSQL unreachable", ex);
        }
    }
}
