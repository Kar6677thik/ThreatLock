using System.Text.Json;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace ThreatLock.Api;

/// <summary>
/// Writes <c>/readyz</c> as JSON so you can see *which* dependency is down:
/// <c>{"status":"Unhealthy","checks":{"postgres":"Healthy","redis":"Unhealthy"}}</c>.
/// Exception details are deliberately left out: they can leak hostnames and connection details.
/// </summary>
internal static class HealthResponseWriter
{
    public static Task WriteAsync(HttpContext context, HealthReport report)
    {
        context.Response.ContentType = "application/json";
        var body = new
        {
            status = report.Status.ToString(),
            checks = report.Entries.ToDictionary(e => e.Key, e => e.Value.Status.ToString()),
        };
        return JsonSerializer.SerializeAsync(context.Response.Body, body, cancellationToken: context.RequestAborted);
    }
}
