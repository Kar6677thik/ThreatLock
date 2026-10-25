using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Npgsql;
using StackExchange.Redis;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Geo;
using ThreatLock.Infrastructure.Audit;
using ThreatLock.Infrastructure.Detection;
using ThreatLock.Infrastructure.Events;
using ThreatLock.Infrastructure.Geo;
using ThreatLock.Infrastructure.HealthChecks;
using ThreatLock.Infrastructure.Observability;
using ThreatLock.Infrastructure.Persistence;
using ThreatLock.Infrastructure.Policy;
using ThreatLock.Infrastructure.Response;
using ThreatLock.Infrastructure.Sessions;

namespace ThreatLock.Infrastructure;

public static class ServiceCollectionExtensions
{
    /// <summary>Health-check tag for dependencies that must be up before we accept traffic.</summary>
    public const string ReadyTag = "ready";

    /// <summary>
    /// Registers PostgreSQL, Redis and their readiness checks. Shared by the API and the Worker so
    /// both connect the same way.
    /// </summary>
    public static IServiceCollection AddThreatLockInfrastructure(this IServiceCollection services)
    {
        // Validate on start: a missing connection string should crash at boot with a clear
        // message, not fail on the first request ("fail fast").
        services.AddOptions<ConnectionStringsOptions>()
            .BindConfiguration(ConnectionStringsOptions.SectionName)
            .Validate(o => !string.IsNullOrWhiteSpace(o.Postgres), "ConnectionStrings:Postgres is required")
            .Validate(o => !string.IsNullOrWhiteSpace(o.Redis), "ConnectionStrings:Redis is required")
            .ValidateOnStart();

        // One NpgsqlDataSource per process: it owns the connection pool. Resolved lazily from
        // options so tests can override configuration before anything connects.
        services.AddSingleton(sp =>
            NpgsqlDataSource.Create(sp.GetRequiredService<IOptions<ConnectionStringsOptions>>().Value.Postgres));

        // One multiplexer per process: it is thread-safe and designed to be shared.
        services.AddSingleton<IConnectionMultiplexer>(sp =>
        {
            var options = ConfigurationOptions.Parse(sp.GetRequiredService<IOptions<ConnectionStringsOptions>>().Value.Redis);
            // Keep starting even if Redis is down; it reconnects in the background. Whether we
            // can *serve* without Redis is decided per feature (SPEC §6.5), not at boot.
            options.AbortOnConnectFail = false;
            options.ConnectTimeout = 2000;
            // PING doesn't accept a CancellationToken, so the health-check timeout can't stop it.
            // Bound each command instead, or /readyz could hang for the 5 s default.
            options.AsyncTimeout = 2000;
            // While disconnected, fail commands immediately instead of queueing them until a
            // reconnect. Callers that can cope without Redis (e.g. the session check falling
            // back to PostgreSQL in M3) then react in milliseconds, not seconds.
            options.BacklogPolicy = BacklogPolicy.FailFast;
            return ConnectionMultiplexer.Connect(options);
        });

        // EF Core reuses the same NpgsqlDataSource (and so the same connection pool).
        services.AddDbContext<ThreatLockDbContext>((sp, options) =>
            DbContextConfiguration.Configure(options, sp.GetRequiredService<NpgsqlDataSource>()));

        // The tamper-evident audit log (SPEC §11), written by both the API and the Worker.
        services.AddSingleton<AuditLog>();

        // Metrics (SPEC §18): plain System.Diagnostics.Metrics; each host decides how to export them.
        services.AddMetrics();
        services.AddSingleton<ThreatLockMetrics>();

        // Shared by the API (checks on every request) and the Worker (revokes in M6).
        services.AddSingleton<SessionStore>();

        // Activity events: written by the API, read by the Worker (SPEC §7).
        services.AddOptions<EventStreamOptions>().BindConfiguration(EventStreamOptions.SectionName);
        services.AddSingleton<EventPublisher>();

        // Detection (SPEC §8): state, Tor list and anomaly storage.
        services.AddOptions<TorOptions>().BindConfiguration(TorOptions.SectionName);
        services.AddHttpClient(nameof(TorExitListLoader), client => client.Timeout = TimeSpan.FromSeconds(30));
        services.AddSingleton<TorExitListLoader>();
        services.AddSingleton<ITorExitList, RedisTorExitList>();
        services.AddSingleton<IDetectorState, RedisDetectorState>();
        services.AddSingleton<AnomalyStore>();
        services.AddSingleton<UserBaselineStore>();
        services.AddSingleton<IUserBaselines>(sp => sp.GetRequiredService<UserBaselineStore>());

        // Per-org policy (SPEC §9).
        services.AddOptions<PolicyOptions>().BindConfiguration(PolicyOptions.SectionName);
        services.AddSingleton<PolicyStore>();

        // Response orchestrator (SPEC §10): the job queue and the steps it runs.
        services.AddOptions<ResponseOptions>().BindConfiguration(ResponseOptions.SectionName);
        services.AddSingleton<ResponseJobStore>();
        services.AddSingleton<ResponseExecutor>();
        services.TryAddSingleton<IResponseFaultInjector, NoFaults>();

        // GeoIP (ADR-0009). Without the database file every lookup is "unknown": the app still
        // works, impossible travel just never fires. A warning is logged at startup.
        services.AddOptions<GeoIpOptions>().BindConfiguration(GeoIpOptions.SectionName);
        services.AddSingleton<IGeoIpLookup>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<GeoIpOptions>>().Value;
            var path = Path.IsPathRooted(options.DatabasePath)
                ? options.DatabasePath
                : Path.GetFullPath(Path.Combine(sp.GetRequiredService<IHostEnvironment>().ContentRootPath, options.DatabasePath));
            if (File.Exists(path)) return new MmdbGeoIpLookup(path, options.DefaultAccuracyKm);

            StartupLog.GeoIpMissing(sp.GetRequiredService<ILoggerFactory>().CreateLogger("ThreatLock.GeoIp"), path);
            return new NullGeoIpLookup();
        });

        // Hosts that act for a tenant (the API) register their own ITenantContext; TryAdd keeps it.
        services.TryAddScoped<ITenantContext, NoTenantContext>();

        services.AddHealthChecks()
            .AddCheck<PostgresHealthCheck>("postgres", tags: [ReadyTag], timeout: TimeSpan.FromSeconds(3))
            .AddCheck<RedisHealthCheck>("redis", tags: [ReadyTag], timeout: TimeSpan.FromSeconds(3));

        return services;
    }
}
