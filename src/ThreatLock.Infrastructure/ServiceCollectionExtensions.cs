using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Npgsql;
using StackExchange.Redis;
using ThreatLock.Infrastructure.HealthChecks;
using ThreatLock.Infrastructure.Persistence;

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

        // Hosts that act for a tenant (the API) register their own ITenantContext; TryAdd keeps it.
        services.TryAddScoped<ITenantContext, NoTenantContext>();

        services.AddHealthChecks()
            .AddCheck<PostgresHealthCheck>("postgres", tags: [ReadyTag], timeout: TimeSpan.FromSeconds(3))
            .AddCheck<RedisHealthCheck>("redis", tags: [ReadyTag], timeout: TimeSpan.FromSeconds(3));

        return services;
    }
}
