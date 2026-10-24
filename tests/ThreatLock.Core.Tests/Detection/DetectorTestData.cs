using System.Text.Json.Nodes;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Events;
using ThreatLock.Core.Geo;

namespace ThreatLock.Core.Tests.Detection;

/// <summary>Cities and an event builder shared by detector tests. IPs are from documentation ranges (RFC 5737).</summary>
internal static class DetectorTestData
{
    public static readonly DateTimeOffset T0 = new(2026, 10, 24, 9, 0, 0, TimeSpan.Zero);

    public static readonly GeoInfo Bangalore = new("IN", "Bengaluru", 12.9716, 77.5946, 20);
    public static readonly GeoInfo Chennai = new("IN", "Chennai", 13.0827, 80.2707, 20);       // ~290 km from Bangalore
    public static readonly GeoInfo London = new("GB", "London", 51.5074, -0.1278, 20);         // ~8,000 km from Bangalore
    public static readonly GeoInfo Frankfurt = new("DE", "Frankfurt", 50.1109, 8.6821, 20);

    public const string TorIp = "198.51.100.77";

    public static readonly Guid Org = Guid.NewGuid();
    public static readonly Guid User = Guid.NewGuid();
    public static readonly Guid Session = Guid.NewGuid();

    public static ActivityEvent Event(
        DateTimeOffset at,
        GeoInfo? geo,
        string ip = "203.0.113.10",
        string type = EventTypes.NoteRead,
        Guid? user = null,
        bool simulated = false) =>
        new(Guid.CreateVersion7(), Org, user ?? User, Session, type, at, ip, geo, "device-1", "TestBrowser/1.0", "req-1",
            simulated ? new JsonObject { ["simulated"] = true } : null);

    public static DetectionContext Context(IDetectorState? state = null) =>
        new(state ?? new InMemoryDetectorState(), new StaticTorExitList([TorIp]));
}
