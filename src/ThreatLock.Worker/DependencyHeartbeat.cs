using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace ThreatLock.Worker;

/// <summary>
/// Every 30 seconds, runs the same readiness checks as the API's <c>/readyz</c> and logs the
/// result. Logs only when the status changes, so a healthy Worker stays quiet.
/// </summary>
internal sealed partial class DependencyHeartbeat(
    HealthCheckService healthChecks,
    TimeProvider time,
    ILogger<DependencyHeartbeat> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        HealthStatus? last = null;

        // PeriodicTimer takes a TimeProvider, so tests could drive it with a fake clock.
        using var timer = new PeriodicTimer(Interval, time);
        do
        {
            var report = await healthChecks.CheckHealthAsync(stoppingToken);
            if (report.Status != last)
            {
                var detail = string.Join(", ", report.Entries.Select(e => $"{e.Key}={e.Value.Status}"));
                LogStatusChanged(report.Status, detail);
                last = report.Status;
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    // Source-generated logging: no boxing or string formatting unless the level is enabled.
    [LoggerMessage(Level = LogLevel.Information, Message = "Dependencies {Status}: {Detail}")]
    private partial void LogStatusChanged(HealthStatus status, string detail);
}
