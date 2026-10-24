using System.Net;
using ThreatLock.Core.Geo;

namespace ThreatLock.IntegrationTests.Infrastructure;

/// <summary>
/// Fake GeoIP for tests: a handful of documentation-range IPs (RFC 5737) pinned to real cities, so
/// tests don't need the 120 MB database and always get the same answers.
/// </summary>
public sealed class TestGeoIpLookup : IGeoIpLookup
{
    public const string BangaloreIp = "203.0.113.10";
    public const string LondonIp = "203.0.113.20";
    public const string FrankfurtIp = "203.0.113.30";
    public const string ChennaiIp = "203.0.113.40";
    public const string TorExitIp = "198.51.100.77";   // also listed in the fixture Tor list

    private static readonly Dictionary<string, GeoInfo> Places = new()
    {
        [BangaloreIp] = new("IN", "Bengaluru", 12.9716, 77.5946, 20),
        [LondonIp] = new("GB", "London", 51.5074, -0.1278, 20),
        [FrankfurtIp] = new("DE", "Frankfurt", 50.1109, 8.6821, 20),
        [ChennaiIp] = new("IN", "Chennai", 13.0827, 80.2707, 20),
        [TorExitIp] = new("NL", "Amsterdam", 52.3676, 4.9041, 20),
    };

    public GeoInfo? Lookup(IPAddress ip) => Places.GetValueOrDefault(ip.ToString());
}
