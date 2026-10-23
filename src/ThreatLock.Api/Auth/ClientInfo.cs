using System.Net;
using System.Text.RegularExpressions;

namespace ThreatLock.Api.Auth;

/// <summary>
/// What we know about the client making a request. All of it is a *signal* for detectors
/// (SPEC §6.7–6.8), none of it is proof: device ids and user agents are whatever the client says.
/// </summary>
public sealed partial record ClientInfo(IPAddress? Ip, string? DeviceId, string? UserAgent)
{
    public const string DeviceIdHeader = "X-Device-Id";
    private const int MaxUserAgentLength = 512;

    /// <summary>
    /// <see cref="HttpContext.Connection"/> RemoteIpAddress is already the real client IP here:
    /// the forwarded-headers middleware rewrote it, but only if the request came through a
    /// trusted proxy (ADR-0007).
    /// </summary>
    public static ClientInfo From(HttpContext http)
    {
        var deviceId = http.Request.Headers[DeviceIdHeader].ToString();
        var userAgent = http.Request.Headers.UserAgent.ToString();
        return new ClientInfo(
            http.Connection.RemoteIpAddress is { } ip && ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : http.Connection.RemoteIpAddress,
            // Accept only a plain token; anything else is dropped rather than stored.
            DeviceIdPattern().IsMatch(deviceId) ? deviceId : null,
            string.IsNullOrEmpty(userAgent) ? null : userAgent[..Math.Min(userAgent.Length, MaxUserAgentLength)]);
    }

    [GeneratedRegex("^[A-Za-z0-9-]{8,64}$")]
    private static partial Regex DeviceIdPattern();
}
