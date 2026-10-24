using ThreatLock.Core.Detection;
using ThreatLock.Infrastructure;
using ThreatLock.Worker.Detection;
using ThreatLock.Worker.Events;

namespace ThreatLock.Worker;

/// <summary>
/// Builds the Worker host. Separate from Program.cs so integration tests can start the real
/// Worker, with test configuration, next to the real API.
/// </summary>
public static class WorkerApp
{
    public static HostApplicationBuilder CreateBuilder(string[] args, IDictionary<string, string?>? overrides = null)
    {
        var builder = Host.CreateApplicationBuilder(args);
        if (overrides is not null) builder.Configuration.AddInMemoryCollection(overrides);

        if (!builder.Environment.IsDevelopment())
        {
            builder.Logging.ClearProviders();
            builder.Logging.AddJsonConsole(o => o.UseUtcTimestamp = true);
        }

        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddThreatLockInfrastructure();

        // The detectors (SPEC §8.2). D3–D5 join in M8.
        builder.Services.AddSingleton<IDetector, TorExitDetector>();
        builder.Services.AddSingleton<IDetector>(new ImpossibleTravelDetector());
        builder.Services.AddSingleton<EventProcessor>();

        builder.Services.AddHostedService<DependencyHeartbeat>();
        builder.Services.AddHostedService<TorListRefresher>();
        builder.Services.AddHostedService<EventSweeper>();
        builder.Services.AddHostedService<EventConsumer>();
        builder.Services.AddHostedService<RetentionPurger>();

        return builder;
    }
}
