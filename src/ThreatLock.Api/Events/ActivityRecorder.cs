using System.Text.Json.Nodes;
using ThreatLock.Api.Auth;
using ThreatLock.Core.Events;
using ThreatLock.Core.Geo;
using ThreatLock.Infrastructure.Events;

namespace ThreatLock.Api.Events;

/// <summary>
/// Turns "this request did X" into an <see cref="ActivityEvent"/> and records it (SPEC §7).
/// Adds everything a detector needs that the endpoint shouldn't have to think about: client IP,
/// geography, device, user agent, request id, the time the request *arrived*, and the simulation flag.
/// </summary>
public sealed class ActivityRecorder(
    IHttpContextAccessor accessor,
    CurrentUser me,
    IGeoIpLookup geo,
    EventPublisher publisher,
    TimeProvider time)
{
    public const string ReceivedAtItem = "tl.received_at";

    /// <summary>An event by the authenticated caller, in their current session.</summary>
    public Task RecordAsync(string type, JsonObject? metadata = null, CancellationToken ct = default) =>
        RecordAsync(type, me.RequiredOrgId, me.UserId, me.SessionId, metadata, ct);

    /// <summary>An event about a specific user and session (login, refresh, revocations).</summary>
    public Task RecordAsync(string type, Guid orgId, Guid? userId, Guid? sessionId, JsonObject? metadata = null, CancellationToken ct = default)
    {
        var http = accessor.HttpContext ?? throw new InvalidOperationException("ActivityRecorder needs an HTTP request.");
        var client = ClientInfo.From(http);

        if (http.Items.ContainsKey(SimulationMiddleware.SimulatedItem))
        {
            metadata ??= [];
            metadata["simulated"] = true;
        }

        var evt = new ActivityEvent(
            Guid.CreateVersion7(),
            orgId,
            userId,
            sessionId,
            type,
            // When the request arrived, not when we got round to recording it.
            http.Items[ReceivedAtItem] as DateTimeOffset? ?? time.GetUtcNow(),
            client.Ip?.ToString(),
            client.Ip is null ? null : geo.Lookup(client.Ip),
            client.DeviceId,
            client.UserAgent,
            http.TraceIdentifier,
            metadata);

        return publisher.RecordAsync(evt, ct);
    }
}
