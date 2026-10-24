using System.Text.Json.Nodes;
using ThreatLock.Core.Events;

namespace ThreatLock.Core.Detection;

/// <summary>
/// D1 (SPEC §8.2): someone using this user's credentials is coming from a Tor exit node.
/// Legitimate users of a corporate notes app rarely use Tor; attackers hiding their origin often do.
/// <para>
/// Known weaknesses, documented not solved: the list lags by up to an hour, and attackers can use
/// residential proxies or VPNs instead.
/// </para>
/// </summary>
public sealed class TorExitDetector : IDetector
{
    public string Id => DetectorIds.Tor;

    public async ValueTask<IReadOnlyList<DetectionSignal>> EvaluateAsync(ActivityEvent evt, DetectionContext context, CancellationToken ct)
    {
        if (!EventTypes.IsAuthenticatedActivity(evt) || evt.IpAddress is not { } ip) return [];
        if (!await context.TorExits.IsExitAsync(ip, ct)) return [];

        // One anomaly per session: an attacker clicking around through Tor produces many events
        // but one incident.
        var dedupeKey = $"tor:{evt.UserId}:{evt.SessionId?.ToString() ?? "no-session"}";
        var evidence = new JsonObject
        {
            ["ip"] = evt.Ip,
            ["eventType"] = evt.Type,
            ["occurredAt"] = evt.OccurredAt,
            ["country"] = evt.Geo?.CountryCode,
            ["userAgent"] = evt.UserAgent,
            ["simulated"] = evt.Simulated,
        };

        return [new DetectionSignal(Id, evt.OrgId, evt.UserId!.Value, evt.SessionId, Severity.High, dedupeKey, evidence, evt.Id)];
    }
}
