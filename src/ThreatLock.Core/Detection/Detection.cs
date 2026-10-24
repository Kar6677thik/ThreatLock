using System.Net;
using System.Text.Json.Nodes;
using ThreatLock.Core.Events;
using ThreatLock.Core.Geo;

namespace ThreatLock.Core.Detection;

public enum Severity { Low, Medium, High, Critical }

/// <summary>Stable detector ids, stored on anomalies and used as policy keys in M5.</summary>
public static class DetectorIds
{
    public const string Tor = "tor";
    public const string ImpossibleTravel = "impossible_travel";
}

/// <summary>
/// What a detector says when something looks wrong (SPEC §8.1). Identical
/// <see cref="DedupeKey"/>s collapse into one anomaly, which is what makes redelivered events
/// and repeated behaviour harmless.
/// </summary>
public sealed record DetectionSignal(
    string Detector,
    Guid OrgId,
    Guid UserId,
    Guid? SessionId,
    Severity Severity,
    string DedupeKey,
    JsonObject Evidence,
    Guid EventId);

/// <summary>A detector: looks at one event (plus whatever state it keeps) and returns signals.</summary>
public interface IDetector
{
    string Id { get; }

    ValueTask<IReadOnlyList<DetectionSignal>> EvaluateAsync(ActivityEvent evt, DetectionContext context, CancellationToken ct);
}

/// <summary>Everything a detector may consult. Each piece is an interface so tests and the replay harness can fake it.</summary>
public sealed record DetectionContext(IDetectorState State, ITorExitList TorExits);

/// <summary>Where the user was last seen, for impossible travel.</summary>
public sealed record LastLocation(string Ip, GeoInfo Geo, DateTimeOffset At);

/// <summary>
/// Scratch state detectors keep between events. Redis-backed in the Worker, in-memory in unit tests
/// and the replay harness (ADR-0006). It is a cache of recent behaviour, not a source of truth:
/// losing it means a missed detection, never a wrong revocation.
/// </summary>
public interface IDetectorState
{
    ValueTask<LastLocation?> GetLastLocationAsync(Guid userId, CancellationToken ct);

    ValueTask SetLastLocationAsync(Guid userId, LastLocation location, TimeSpan ttl, CancellationToken ct);
}

/// <summary>The current Tor exit-node list.</summary>
public interface ITorExitList
{
    ValueTask<bool> IsExitAsync(IPAddress ip, CancellationToken ct);
}

/// <summary>
/// Simple in-memory state for unit tests and the offline replay harness. Ignores TTLs: replay
/// runs are short, and detectors already ignore locations older than their own window.
/// </summary>
public sealed class InMemoryDetectorState : IDetectorState
{
    private readonly Dictionary<Guid, LastLocation> locations = [];

    public ValueTask<LastLocation?> GetLastLocationAsync(Guid userId, CancellationToken ct) =>
        ValueTask.FromResult(locations.GetValueOrDefault(userId));

    public ValueTask SetLastLocationAsync(Guid userId, LastLocation location, TimeSpan ttl, CancellationToken ct)
    {
        locations[userId] = location;
        return ValueTask.CompletedTask;
    }
}

/// <summary>A fixed Tor list, for tests and replay.</summary>
public sealed class StaticTorExitList(IEnumerable<string> ips) : ITorExitList
{
    private readonly HashSet<IPAddress> exits = [.. ips.Select(IPAddress.Parse)];

    public ValueTask<bool> IsExitAsync(IPAddress ip, CancellationToken ct) => ValueTask.FromResult(exits.Contains(ip));
}
