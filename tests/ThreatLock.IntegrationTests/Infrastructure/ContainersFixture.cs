using Testcontainers.PostgreSql;
using Testcontainers.Redis;

// One set of containers for the whole test assembly: starting PostgreSQL takes a few seconds,
// so we pay that once, not per test. (xUnit v3 assembly fixture.)
[assembly: AssemblyFixture(typeof(ThreatLock.IntegrationTests.Infrastructure.ContainersFixture))]

namespace ThreatLock.IntegrationTests.Infrastructure;

/// <summary>
/// Starts real PostgreSQL and Redis in Docker. Image tags are pinned to the same versions as
/// deploy/compose/docker-compose.yml so tests run against what we deploy.
/// </summary>
public sealed class ContainersFixture : IAsyncLifetime
{
    public const string PostgresImage = "postgres:17.11-alpine";
    public const string RedisImage = "redis:8.10.2-alpine";

    public PostgreSqlContainer Postgres { get; } = new PostgreSqlBuilder(PostgresImage).Build();

    public RedisContainer Redis { get; } = new RedisBuilder(RedisImage).Build();

    public async ValueTask InitializeAsync() =>
        await Task.WhenAll(Postgres.StartAsync(), Redis.StartAsync());

    public async ValueTask DisposeAsync()
    {
        await Postgres.DisposeAsync();
        await Redis.DisposeAsync();
    }
}
