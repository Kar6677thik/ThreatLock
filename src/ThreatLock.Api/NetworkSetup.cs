using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

namespace ThreatLock.Api;

/// <summary>Bound from the <c>Network</c> configuration section (ADR-0007).</summary>
public sealed class NetworkOptions
{
    public const string SectionName = "Network";

    /// <summary>Exact proxy addresses allowed to set X-Forwarded-For, e.g. "10.42.0.7".</summary>
    public string[] KnownProxies { get; set; } = [];

    /// <summary>Proxy networks in CIDR form, e.g. "10.42.0.0/16" for a k3s pod network.</summary>
    public string[] KnownNetworks { get; set; } = [];
}

public static class NetworkSetup
{
    /// <summary>
    /// Trust X-Forwarded-For only from configured proxies. Anyone can *send* that header, so
    /// believing it from any client would let an attacker choose the IP our detectors see.
    /// </summary>
    public static IServiceCollection AddThreatLockForwardedHeaders(this IServiceCollection services)
    {
        // Read configuration when the options are first needed, not while Program.cs runs, so
        // overrides applied later (tests, environment) are seen.
        services.AddOptions<ForwardedHeadersOptions>().Configure<IConfiguration>((options, config) =>
        {
            var network = config.GetSection(NetworkOptions.SectionName).Get<NetworkOptions>() ?? new NetworkOptions();

            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

            // ASP.NET Core trusts loopback (127.0.0.1, ::1) by default. Start from nothing so
            // the list in configuration is the whole truth.
            options.KnownProxies.Clear();
            options.KnownIPNetworks.Clear();
            foreach (var proxy in network.KnownProxies) options.KnownProxies.Add(IPAddress.Parse(proxy));
            foreach (var cidr in network.KnownNetworks) options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(cidr));

            // Use only the last hop the trusted proxy appended. Earlier entries in the header came
            // from the client and can't be trusted.
            options.ForwardLimit = 1;
        });

        return services;
    }
}
