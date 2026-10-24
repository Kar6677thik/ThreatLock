using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace ThreatLock.Api;

/// <summary>Bound from the <c>Simulation</c> configuration section (ADR-0007).</summary>
public sealed class SimulationOptions
{
    public const string SectionName = "Simulation";
    public const string KeyHeader = "X-Simulator-Key";
    public const string IpHeader = "X-Simulated-Client-Ip";

    /// <summary>Off by default. Must stay off if ThreatLock is ever reachable from the internet.</summary>
    public bool Enabled { get; set; }

    /// <summary>Shared secret the Simulator sends. At least 16 characters.</summary>
    public string Key { get; set; } = "";
}

/// <summary>
/// Lets the Simulator pretend to be somewhere else (ADR-0007): with simulation enabled and the
/// right key, <c>X-Simulated-Client-Ip</c> replaces the client IP for this request, and the request
/// is marked so every event it produces says <c>"simulated": true</c>. Without the key the header
/// is ignored, so it can't be used to spoof an IP.
/// </summary>
public sealed class SimulationMiddleware(RequestDelegate next, IOptions<SimulationOptions> options)
{
    public const string SimulatedItem = "tl.simulated";

    public Task InvokeAsync(HttpContext context)
    {
        var simulation = options.Value;
        if (simulation.Enabled
            && context.Request.Headers.TryGetValue(SimulationOptions.KeyHeader, out var key)
            && KeyMatches(key.ToString(), simulation.Key)
            && IPAddress.TryParse(context.Request.Headers[SimulationOptions.IpHeader].ToString(), out var ip))
        {
            context.Connection.RemoteIpAddress = ip;
            context.Items[SimulatedItem] = true;
        }

        return next(context);
    }

    /// <summary>
    /// Constant-time comparison: a normal string compare returns as soon as one character differs,
    /// and that timing difference can leak the key one character at a time.
    /// </summary>
    private static bool KeyMatches(string presented, string expected) =>
        expected.Length >= 16 &&
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(presented), Encoding.UTF8.GetBytes(expected));
}
