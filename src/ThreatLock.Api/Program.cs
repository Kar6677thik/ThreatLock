using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using ThreatLock.Api;
using ThreatLock.Core;
using ThreatLock.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

// Structured JSON logs outside Development so the deployed app can be searched by field
// (SPEC §18). Plain console text is easier to read while developing.
if (!builder.Environment.IsDevelopment())
{
    builder.Logging.ClearProviders();
    builder.Logging.AddJsonConsole(o => o.UseUtcTimestamp = true);
}

// Everything time-based asks this clock instead of DateTime.UtcNow, so tests can control time
// (concepts.md §6.2).
builder.Services.AddSingleton(TimeProvider.System);

builder.Services.AddThreatLockInfrastructure();

// Errors come back as RFC 9457 problem+json without stack traces (SPEC §13).
builder.Services.AddProblemDetails();

var app = builder.Build();

app.UseExceptionHandler();
app.UseStatusCodePages();

// Liveness: "is the process running?" Runs no checks, so a database outage does not make
// Kubernetes restart a perfectly healthy API process.
app.MapHealthChecks("/healthz", new HealthCheckOptions { Predicate = _ => false });

// Readiness: "should this instance receive traffic?" Requires PostgreSQL and Redis.
app.MapHealthChecks("/readyz", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains(ServiceCollectionExtensions.ReadyTag),
    ResponseWriter = HealthResponseWriter.WriteAsync,
});

app.MapGet("/api/info", (IHostEnvironment env) => new
{
    name = AppInfo.Name,
    version = AppInfo.Version,
    environment = env.EnvironmentName,
});

StartupLog.Starting(app.Logger, AppInfo.Name, "API", AppInfo.Version, app.Environment.EnvironmentName);

await app.RunAsync();

/// <summary>Exposed so integration tests can boot the app with WebApplicationFactory.</summary>
public partial class Program;
