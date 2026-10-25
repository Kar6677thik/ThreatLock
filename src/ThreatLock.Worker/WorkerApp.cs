using ThreatLock.Core.Detection;
using ThreatLock.Infrastructure;
using ThreatLock.Worker.Detection;
using ThreatLock.Worker.Events;
using ThreatLock.Worker.Response;

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

        // The detectors (SPEC §8.2). Each runs on every event and ignores the ones it doesn't care about.
        builder.Services.AddSingleton<IDetector, TorExitDetector>();
        builder.Services.AddSingleton<IDetector>(new ImpossibleTravelDetector());
        builder.Services.AddSingleton<IDetector>(new ScrapingDetector());
        builder.Services.AddSingleton<IDetector>(new NewDeviceExportDetector());
        builder.Services.AddSingleton<IDetector, SessionHijackDetector>();
        builder.Services.AddSingleton<EventProcessor>();

        builder.Services.AddHostedService<DependencyHeartbeat>();
        builder.Services.AddHostedService<TorListRefresher>();
        builder.Services.AddHostedService<EventSweeper>();
        builder.Services.AddHostedService<EventConsumer>();
        builder.Services.AddHostedService<RetentionPurger>();
        builder.Services.AddHostedService<BaselineUpdater>();
        builder.Services.AddHostedService<ResponseOrchestrator>();

        return builder;
    }
}
