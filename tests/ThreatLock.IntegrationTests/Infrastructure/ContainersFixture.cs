using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Testcontainers.PostgreSql;
using Testcontainers.Redis;
using ThreatLock.Infrastructure.Persistence;
using ThreatLock.Worker;

// One set of containers for the whole test assembly: starting PostgreSQL takes a few seconds,
// so we pay that once, not per test. (xUnit v3 assembly fixture.)
[assembly: AssemblyFixture(typeof(ThreatLock.IntegrationTests.Infrastructure.ContainersFixture))]

namespace ThreatLock.IntegrationTests.Infrastructure;

/// <summary>
/// Starts real PostgreSQL and Redis in Docker, applies the EF Core migrations once, and runs one
/// API (<see cref="Api"/>) and one real Worker (<see cref="StartWorkerAsync"/>) that tests share.
/// <para>
/// Isolation strategy: tests share the database but every test registers its own org with a
/// random slug and emails (<see cref="TestData"/>). Tenant data never overlaps, so tests can run
/// in parallel without cleaning up. Tests that need a misconfigured app, or their own event
/// stream, create their own factory or Worker.
/// </para>
/// Image tags are pinned to the same versions as deploy/compose/docker-compose.yml.
/// </summary>
public sealed class ContainersFixture : IAsyncLifetime
{
    public const string PostgresImage = "postgres:17.11-alpine";
    public const string RedisImage = "redis:8.10.2-alpine";
    public const string SimulatorKey = "integration-test-simulator-key";

    public PostgreSqlContainer Postgres { get; } = new PostgreSqlBuilder(PostgresImage).WithDatabase("threatlock_tests").Build();

    public RedisContainer Redis { get; } = new RedisBuilder(RedisImage).Build();

    /// <summary>The API, healthy and pointed at the containers. Shared by most tests.</summary>
    public ThreatLockApiFactory Api { get; private set; } = null!;

    /// <summary>A fixture Tor exit list: one documentation-range address (see <see cref="TestGeoIpLookup"/>).</summary>
    public string TorListPath { get; } = Path.Combine(Path.GetTempPath(), $"threatlock-tor-{Guid.NewGuid():N}.txt");

    /// <summary>The shared Worker, consuming the default stream.</summary>
    public IHost Worker { get; private set; } = null!;

    public async ValueTask InitializeAsync()
    {
        await Task.WhenAll(Postgres.StartAsync(), Redis.StartAsync());

        // Migrate once, up front. The app itself runs with MigrateOnStartup=false in tests, so
        // parallel test factories never race to migrate the same database.
        await MigrateAsync(Postgres.GetConnectionString());

        // A second, migrated copy that is never used directly: CREATE DATABASE ... TEMPLATE
        // clones it in milliseconds for tests that need a database to themselves.
        await using (var admin = new NpgsqlConnection(Postgres.GetConnectionString()))
        {
            await admin.OpenAsync();
            await using var create = new NpgsqlCommand($"CREATE DATABASE {TemplateDatabase}", admin);
            await create.ExecuteNonQueryAsync();
        }

        // Pooling off: a template must have no open connections when it's cloned.
        await MigrateAsync(new NpgsqlConnectionStringBuilder(Postgres.GetConnectionString())
        {
            Database = TemplateDatabase,
            Pooling = false,
        }.ConnectionString);

        await File.WriteAllTextAsync(TorListPath, $"# fixture\n{TestGeoIpLookup.TorExitIp}\nnot-an-ip\n");

        Api = new ThreatLockApiFactory(this);
        Worker = await StartWorkerAsync();
    }

    /// <summary>
    /// Starts a real Worker against the test containers. Defaults are tuned for tests (fast
    /// sweeps and reclaims); pass overrides for a Worker on its own stream.
    /// </summary>
    public async Task<IHost> StartWorkerAsync(IDictionary<string, string?>? overrides = null)
    {
        var settings = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Postgres"] = Postgres.GetConnectionString(),
            ["ConnectionStrings:Redis"] = Redis.GetConnectionString(),
            ["Tor:ListPath"] = TorListPath,
            ["Events:ConsumerName"] = $"test-worker-{Guid.NewGuid():N}",
            ["Events:SweepInterval"] = "00:00:00.200",
            ["Events:SweepMinAge"] = "00:00:00",
            // No policy caching: a test that edits the policy sees it applied to the very next event.
            ["Policy:CacheSeconds"] = "0",
            ["Logging:LogLevel:Default"] = "Warning",
            ["Metrics:WorkerPort"] = "0",
            // Only the shared Worker runs response jobs. Extra Workers come and go mid-test; one
            // stopped while holding a job would delay another test's response.
            ["Responses:Enabled"] = overrides is null ? "true" : "false",
        };
        foreach (var (key, value) in overrides ?? new Dictionary<string, string?>()) settings[key] = value;

        var host = WorkerApp.CreateBuilder([], settings).Build();
        await host.StartAsync();
        return host;
    }

    private const string TemplateDatabase = "threatlock_template";

    // Two clones of one template at the same moment can fail ("source database is being accessed
    // by other users"), so tests take turns. Each clone takes milliseconds.
    private readonly SemaphoreSlim cloning = new(1, 1);

    private static async Task MigrateAsync(string connectionString)
    {
        var options = new DbContextOptionsBuilder<ThreatLockDbContext>();
        DbContextConfiguration.Configure(options, connectionString);
        await using var db = new ThreatLockDbContext(options.Options, new NoTenantContext());
        await db.Database.MigrateAsync();
    }

    /// <summary>
    /// A fresh, fully migrated database of the test's own, for tests where the shared Worker
    /// must not interfere (e.g. claiming response jobs). Returns its connection string.
    /// </summary>
    public async Task<string> CreateDatabaseAsync()
    {
        var name = $"tl_{Guid.NewGuid():N}";
        await cloning.WaitAsync();
        try
        {
            await using var admin = new NpgsqlConnection(Postgres.GetConnectionString());
            await admin.OpenAsync();
            await using var create = new NpgsqlCommand($"CREATE DATABASE {name} TEMPLATE {TemplateDatabase}", admin);
            await create.ExecuteNonQueryAsync();
        }
        finally
        {
            cloning.Release();
        }

        return new NpgsqlConnectionStringBuilder(Postgres.GetConnectionString()) { Database = name }.ConnectionString;
    }

    public async ValueTask DisposeAsync()
    {
        await Worker.StopAsync();
        Worker.Dispose();
        await Api.DisposeAsync();
        await Postgres.DisposeAsync();
        await Redis.DisposeAsync();
        File.Delete(TorListPath);
        cloning.Dispose();
    }
}
