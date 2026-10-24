using ThreatLock.Core;
using ThreatLock.Infrastructure;
using ThreatLock.Worker;

// All registrations live in WorkerApp so integration tests can build the same host.
// (Program stays internal: tests also see the API's public Program, and two would clash.)
var host = WorkerApp.CreateBuilder(args).Build();

var logger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("ThreatLock.Worker");
var environment = host.Services.GetRequiredService<IHostEnvironment>().EnvironmentName;
StartupLog.Starting(logger, AppInfo.Name, "Worker", AppInfo.Version, environment);

await host.RunAsync();
