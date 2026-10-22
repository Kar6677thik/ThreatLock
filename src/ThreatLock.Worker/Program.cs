using ThreatLock.Core;
using ThreatLock.Infrastructure;
using ThreatLock.Worker;

var builder = Host.CreateApplicationBuilder(args);

if (!builder.Environment.IsDevelopment())
{
    builder.Logging.ClearProviders();
    builder.Logging.AddJsonConsole(o => o.UseUtcTimestamp = true);
}

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddThreatLockInfrastructure();

// M1 has one job: prove the Worker can reach its dependencies. The event consumer (M4) and
// response orchestrator (M6) are added here as further hosted services.
builder.Services.AddHostedService<DependencyHeartbeat>();

var host = builder.Build();

var logger = host.Services.GetRequiredService<ILogger<Program>>();
StartupLog.Starting(logger, AppInfo.Name, "Worker", AppInfo.Version, builder.Environment.EnvironmentName);

await host.RunAsync();
