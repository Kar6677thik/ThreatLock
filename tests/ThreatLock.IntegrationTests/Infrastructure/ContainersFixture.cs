using Microsoft.EntityFrameworkCore;
using Testcontainers.PostgreSql;
using Testcontainers.Redis;
using ThreatLock.Infrastructure.Persistence;

// One set of containers for the whole test assembly: starting PostgreSQL takes a few seconds,
// so we pay that once, not per test. (xUnit v3 assembly fixture.)
[assembly: AssemblyFixture(typeof(ThreatLock.IntegrationTests.Infrastructure.ContainersFixture))]

namespace ThreatLock.IntegrationTests.Infrastructure;

/// <summary>
/// Starts real PostgreSQL and Redis in Docker, applies the EF Core migrations once, and shares
/// one API instance (<see cref="Api"/>) across tests.
/// <para>
/// Isolation strategy: tests share the database but every test registers its own org with a
/// random slug and emails (<see cref="TestData"/>). Tenant data never overlaps, so tests can run
/// in parallel without cleaning up. Tests that need a misconfigured app create their own factory.
/// </para>
/// Image tags are pinned to the same versions as deploy/compose/docker-compose.yml.
/// </summary>
public sealed class ContainersFixture : IAsyncLifetime
{
    public const string PostgresImage = "postgres:17.11-alpine";
    public const string RedisImage = "redis:8.10.2-alpine";

    public PostgreSqlContainer Postgres { get; } = new PostgreSqlBuilder(PostgresImage).WithDatabase("threatlock_tests").Build();

    public RedisContainer Redis { get; } = new RedisBuilder(RedisImage).Build();

    /// <summary>The API, healthy and pointed at the containers. Shared by most tests.</summary>
    public ThreatLockApiFactory Api { get; private set; } = null!;

    public async ValueTask InitializeAsync()
    {
        await Task.WhenAll(Postgres.StartAsync(), Redis.StartAsync());

        // Migrate once, up front. The app itself runs with MigrateOnStartup=false in tests, so
        // parallel test factories never race to migrate the same database.
        var options = new DbContextOptionsBuilder<ThreatLockDbContext>();
        DbContextConfiguration.Configure(options, Postgres.GetConnectionString());
        await using (var db = new ThreatLockDbContext(options.Options, new NoTenantContext()))
        {
            await db.Database.MigrateAsync();
        }

        Api = new ThreatLockApiFactory(this);
    }

    public async ValueTask DisposeAsync()
    {
        await Api.DisposeAsync();
        await Postgres.DisposeAsync();
        await Redis.DisposeAsync();
    }
}
