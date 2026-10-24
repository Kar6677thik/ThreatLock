using System.Net;
using MaxMind.Db;
using ThreatLock.Core.Geo;

namespace ThreatLock.Infrastructure.Geo;

/// <summary>Bound from the <c>GeoIp</c> configuration section (ADR-0009).</summary>
public sealed class GeoIpOptions
{
    public const string SectionName = "GeoIp";

    /// <summary>Path to the .mmdb file, absolute or relative to the app's content root.</summary>
    public string DatabasePath { get; set; } = "data/geoip/dbip-city-lite.mmdb";

    /// <summary>
    /// Used when a record carries no accuracy radius. DB-IP Lite is city-level, and city-level
    /// GeoIP is commonly off by tens of km, so 50 km is a deliberately cautious default.
    /// </summary>
    public double DefaultAccuracyKm { get; set; } = 50;
}

/// <summary>
/// Looks IPs up in a MaxMind-format database (DB-IP Lite City). The reader memory-maps the file,
/// so lookups are in-process and take microseconds: no network call per event, and users' IPs
/// are never sent to a third party.
/// </summary>
public sealed class MmdbGeoIpLookup(string path, double defaultAccuracyKm) : IGeoIpLookup, IDisposable
{
    private readonly Reader reader = new(path, FileAccessMode.MemoryMapped);

    public GeoInfo? Lookup(IPAddress ip)
    {
        if (!IpRanges.IsPublic(ip)) return null;

        // Generic decoding: maps become dictionaries, so missing fields are simply absent.
        var record = reader.Find<Dictionary<string, object>>(ip);
        if (record is null || !record.TryGetValue("location", out var loc) || loc is not Dictionary<string, object> location) return null;
        if (!location.TryGetValue("latitude", out var lat) || !location.TryGetValue("longitude", out var lon)) return null;

        var accuracy = location.TryGetValue("accuracy_radius", out var radius) ? Convert.ToDouble(radius, System.Globalization.CultureInfo.InvariantCulture) : defaultAccuracyKm;
        return new GeoInfo(
            Nested(record, "country", "iso_code"),
            Nested(record, "city", "names", "en"),
            Convert.ToDouble(lat, System.Globalization.CultureInfo.InvariantCulture),
            Convert.ToDouble(lon, System.Globalization.CultureInfo.InvariantCulture),
            accuracy);
    }

    private static string? Nested(Dictionary<string, object> record, params string[] path)
    {
        object? node = record;
        foreach (var key in path)
        {
            if (node is not Dictionary<string, object> map || !map.TryGetValue(key, out node)) return null;
        }

        return node as string;
    }

    public void Dispose() => reader.Dispose();
}

/// <summary>Used when no GeoIP database is installed: every lookup is "unknown". Impossible travel then never fires.</summary>
public sealed class NullGeoIpLookup : IGeoIpLookup
{
    public GeoInfo? Lookup(IPAddress ip) => null;
}

public static class IpRanges
{
    private static readonly IPNetwork[] NonPublic =
    [
        IPNetwork.Parse("0.0.0.0/8"),
        IPNetwork.Parse("10.0.0.0/8"),          // private
        IPNetwork.Parse("100.64.0.0/10"),       // carrier-grade NAT, and Tailscale addresses
        IPNetwork.Parse("127.0.0.0/8"),         // loopback
        IPNetwork.Parse("169.254.0.0/16"),      // link-local
        IPNetwork.Parse("172.16.0.0/12"),       // private
        IPNetwork.Parse("192.168.0.0/16"),      // private
        IPNetwork.Parse("::1/128"),
        IPNetwork.Parse("fc00::/7"),            // unique local
        IPNetwork.Parse("fe80::/10"),           // link-local
    ];

    /// <summary>False for private, loopback, link-local and CGNAT addresses: they have no geography.</summary>
    public static bool IsPublic(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return !NonPublic.Any(network => network.Contains(ip));
    }
}
