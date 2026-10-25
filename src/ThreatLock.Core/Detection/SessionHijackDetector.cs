using System.Text.Json.Nodes;
using ThreatLock.Core.Events;

namespace ThreatLock.Core.Detection;

/// <summary>
/// D5 (SPEC §8.2): signs that a session is being used by someone other than whoever started it.
/// <list type="bullet">
/// <item>(a) <c>refresh_token_reused</c>: two parties hold the same refresh token. Critical.</item>
/// <item>(b) the session's <em>fingerprint</em> changed: a different device id, or a different
/// user-agent family (browser and OS, ignoring versions), from the one the session started with.
/// High. That's what a copied cookie used from the attacker's machine looks like.</item>
/// </list>
/// Not "the IP changed": phones change IP all the time; geography is D2's job.
/// <para>
/// The fingerprint is kept in detector state, keyed by session, from the session's first event
/// (its login). Known weakness: an attacker who copies the device id and the exact user agent
/// defeats (b); (a) still catches them as soon as both parties refresh.
/// </para>
/// </summary>
public sealed class SessionHijackDetector : IDetector
{
    /// <summary>Longer than any session can live (7 days absolute).</summary>
    public static readonly TimeSpan FingerprintTtl = TimeSpan.FromDays(8);

    public string Id => DetectorIds.SessionHijack;

    public static string Fingerprint(ActivityEvent evt) => $"{evt.DeviceId ?? "-"}|{UserAgentFamily.Of(evt.UserAgent)}";

    public async ValueTask<IReadOnlyList<DetectionSignal>> EvaluateAsync(ActivityEvent evt, DetectionContext context, CancellationToken ct)
    {
        if (evt.UserId is not { } userId || evt.SessionId is not { } sessionId) return [];
        var ips = evt.Ip is null ? Array.Empty<string>() : [evt.Ip];

        if (evt.Type == EventTypes.RefreshTokenReused)
        {
            return
            [
                new DetectionSignal(Id, evt.OrgId, userId, sessionId, Severity.Critical, $"hijack:{sessionId}",
                    new JsonObject { ["signal"] = "refresh_token_reused", ["ip"] = evt.Ip, ["userAgent"] = evt.UserAgent }, evt.Id, ips),
            ];
        }

        // Only events made *with* the session say who's using it.
        if (!EventTypes.IsAuthenticatedActivity(evt)) return [];

        var key = $"sess-fp:{sessionId}";
        var current = Fingerprint(evt);
        // The first event of a session sets its fingerprint; later ones are compared with it.
        if (await context.State.SetValueAsync(key, current, FingerprintTtl, onlyIfAbsent: true, ct)) return [];

        var expected = await context.State.GetValueAsync(key, ct);
        if (expected is null || expected == current) return [];

        var (expectedDevice, expectedAgent) = Split(expected);
        var (actualDevice, actualAgent) = Split(current);
        return
        [
            new DetectionSignal(Id, evt.OrgId, userId, sessionId, Severity.High, $"hijack:{sessionId}",
                new JsonObject
                {
                    ["signal"] = "fingerprint_changed",
                    ["expectedDevice"] = expectedDevice,
                    ["actualDevice"] = actualDevice,
                    ["expectedUserAgentFamily"] = expectedAgent,
                    ["actualUserAgentFamily"] = actualAgent,
                    ["ip"] = evt.Ip,
                    ["eventType"] = evt.Type,
                },
                evt.Id, ips),
        ];
    }

    private static (string Device, string Agent) Split(string fingerprint)
    {
        var bar = fingerprint.IndexOf('|', StringComparison.Ordinal);
        return bar < 0 ? (fingerprint, "") : (fingerprint[..bar], fingerprint[(bar + 1)..]);
    }
}

/// <summary>
/// "Chrome/Windows", "Firefox/Linux", "curl/other": the parts of a user agent that don't change
/// when a browser updates itself. Comparing full strings would flag every auto-update as a hijack.
/// Deliberately rough; it only has to tell "same browser on same OS" from "something else".
/// </summary>
public static class UserAgentFamily
{
    public static string Of(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent)) return "none";
        var ua = userAgent;

        // Order matters: Edge and Opera also say "Chrome", Chrome also says "Safari".
        var browser =
            Has(ua, "Edg/") ? "Edge" :
            Has(ua, "OPR/") ? "Opera" :
            Has(ua, "Firefox/") ? "Firefox" :
            Has(ua, "Chrome/") || Has(ua, "CriOS/") ? "Chrome" :
            Has(ua, "Safari/") ? "Safari" :
            Has(ua, "curl/") ? "curl" :
            Has(ua, "python-requests") || Has(ua, "Python") ? "python" :
            "other";

        var os =
            Has(ua, "Windows") ? "Windows" :
            Has(ua, "iPhone") || Has(ua, "iPad") ? "iOS" :
            Has(ua, "Mac OS X") || Has(ua, "Macintosh") ? "macOS" :
            Has(ua, "Android") ? "Android" :
            Has(ua, "Linux") ? "Linux" :
            "other";

        return $"{browser}/{os}";
    }

    private static bool Has(string ua, string token) => ua.Contains(token, StringComparison.OrdinalIgnoreCase);
}
