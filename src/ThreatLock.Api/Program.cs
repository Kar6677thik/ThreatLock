using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using ThreatLock.Api;
using ThreatLock.Api.Admin;
using ThreatLock.Api.Auth;
using ThreatLock.Api.Notes;
using ThreatLock.Core;
using ThreatLock.Infrastructure;
using ThreatLock.Infrastructure.Persistence;

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
builder.Services.AddThreatLockAuth();
builder.Services.AddThreatLockForwardedHeaders();

// Errors come back as RFC 9457 problem+json without stack traces (SPEC §13).
builder.Services.AddProblemDetails();

// Validates [Required], [StringLength] etc. on request records before the endpoint runs and
// answers 400 with the field errors (.NET 10 minimal-API validation, source-generated).
builder.Services.AddValidation();

var app = builder.Build();

// Development and tests create/upgrade the schema at startup. Deployments run migrations as a
// separate step with a more privileged database role (SPEC §19, M10).
if (app.Configuration.GetValue("Database:MigrateOnStartup", false))
{
    await using var scope = app.Services.CreateAsyncScope();
    await scope.ServiceProvider.GetRequiredService<ThreatLockDbContext>().Database.MigrateAsync();
}

// First in the pipeline, so everything after it sees the real client IP (ADR-0007).
app.UseForwardedHeaders();
app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseAuthentication();
app.UseAuthorization();

// Liveness: "is the process running?" Runs no checks, so a database outage does not make
// Kubernetes restart a perfectly healthy API process.
app.MapHealthChecks("/healthz", new HealthCheckOptions { Predicate = _ => false }).AllowAnonymous();

// Readiness: "should this instance receive traffic?" Requires PostgreSQL and Redis.
app.MapHealthChecks("/readyz", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains(ServiceCollectionExtensions.ReadyTag),
    ResponseWriter = HealthResponseWriter.WriteAsync,
}).AllowAnonymous();

app.MapGet("/api/info", (IHostEnvironment env) => new
{
    name = AppInfo.Name,
    version = AppInfo.Version,
    environment = env.EnvironmentName,
}).AllowAnonymous();

app.MapAuthEndpoints();
app.MapNoteEndpoints();
app.MapUserAdminEndpoints();

StartupLog.Starting(app.Logger, AppInfo.Name, "API", AppInfo.Version, app.Environment.EnvironmentName);

await app.RunAsync();

/// <summary>Exposed so integration tests can boot the app with WebApplicationFactory.</summary>
public partial class Program;
