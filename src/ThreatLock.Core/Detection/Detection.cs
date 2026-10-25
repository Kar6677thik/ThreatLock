using System.Net;
using System.Text.Json.Nodes;
using ThreatLock.Core.Events;
using ThreatLock.Core.Geo;
using ThreatLock.Core.Policy;

namespace ThreatLock.Core.Detection;

public enum Severity { Low, Medium, High, Critical }

/// <summary>Stable detector ids, stored on anomalies and used as policy keys in M5.</summary>
public static class DetectorIds
{
    public const string Tor = "tor";
    public const string ImpossibleTravel = "impossible_travel";
    public const string Scraping = "scraping";
    public const string NewDeviceExport = "new_device_export";
    public const string SessionHijack = "session_hijack";

    public static IReadOnlyList<string> All { get; } = [Tor, ImpossibleTravel, Scraping, NewDeviceExport, SessionHijack];

    /// <summary>A human name for notifications and logs.</summary>
    public static string DisplayName(string id) => id switch
    {
        Tor => "Tor exit node",
        ImpossibleTravel => "Impossible travel",
        Scraping => "Scraping",
        NewDeviceExport => "New device export",
        SessionHijack => "Session hijack",
        _ => id,
    };
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
    Guid EventId,
    IReadOnlyList<string> Ips);

/// <summary>A detector: looks at one event (plus whatever state it keeps) and returns signals.</summary>
public interface IDetector
{
    string Id { get; }

    ValueTask<IReadOnlyList<DetectionSignal>> EvaluateAsync(ActivityEvent evt, DetectionContext context, CancellationToken ct);
}

/// <summary>
/// Everything a detector may consult. Each piece is an interface (or plain data) so tests and the
/// replay harness can fake it. <see cref="Policy"/> is the event's org policy, so detectors can
/// use per-org thresholds.
/// </summary>
public sealed record DetectionContext(IDetectorState State, ITorExitList TorExits, SecurityPolicy? Policy = null, IUserBaselines? Baselines = null)
{
    public SecurityPolicy EffectivePolicy => Policy ?? SecurityPolicy.Default;

    /// <summary>Without a baseline store, every user is cold-started (D3 uses the org floor).</summary>
    public IUserBaselines EffectiveBaselines => Baselines ?? NoBaselines.Instance;
}

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

    /// <summary>
    /// Records <paramref name="member"/> at <paramref name="at"/> in a sliding window and returns
    /// how many distinct members fall within <paramref name="window"/> before <paramref name="at"/>.
    /// Time is *event* time, so a replay counts exactly like live traffic. Adding the same member
    /// twice (a redelivered event) counts it once.
    /// </summary>
    ValueTask<long> CountInWindowAsync(string key, string member, DateTimeOffset at, TimeSpan window, CancellationToken ct);

    ValueTask<string?> GetValueAsync(string key, CancellationToken ct);

    /// <summary>Sets a value that expires. With <paramref name="onlyIfAbsent"/>, keeps an existing value; returns whether it set.</summary>
    ValueTask<bool> SetValueAsync(string key, string value, TimeSpan ttl, bool onlyIfAbsent, CancellationToken ct);
}

/// <summary>The current Tor exit-node list.</summary>
public interface ITorExitList
{
    ValueTask<bool> IsExitAsync(IPAddress ip, CancellationToken ct);
}

/// <summary>
/// Simple in-memory state for unit tests and the offline replay harness. Ignores TTLs (detectors
/// check ages themselves) but trims sliding windows, as Redis does.
/// </summary>
public sealed class InMemoryDetectorState : IDetectorState
{
    private readonly Dictionary<Guid, LastLocation> locations = [];
    private readonly Dictionary<string, Dictionary<string, DateTimeOffset>> windows = [];
    private readonly Dictionary<string, string> values = [];

    public ValueTask<long> CountInWindowAsync(string key, string member, DateTimeOffset at, TimeSpan window, CancellationToken ct)
    {
        if (!windows.TryGetValue(key, out var members)) windows[key] = members = [];
        members[member] = at;

        // Trim like the Redis version does, or a replay of millions of events would rescan every
        // member it ever saw on every call.
        foreach (var old in members.Where(m => m.Value <= at - window).Select(m => m.Key).ToList()) members.Remove(old);
        return ValueTask.FromResult((long)members.Values.Count(t => t <= at));
    }

    public ValueTask<string?> GetValueAsync(string key, CancellationToken ct) => ValueTask.FromResult(values.GetValueOrDefault(key));

    public ValueTask<bool> SetValueAsync(string key, string value, TimeSpan ttl, bool onlyIfAbsent, CancellationToken ct)
    {
        if (onlyIfAbsent && values.ContainsKey(key)) return ValueTask.FromResult(false);
        values[key] = value;
        return ValueTask.FromResult(true);
    }

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

/// <summary>
/// A user's normal reading rate (D3): an exponentially weighted mean and standard deviation of
/// reads per minute, over minutes in which they read anything.
/// </summary>
public sealed record UserBaseline(double MeanPerMinute, double StdPerMinute, long ActiveMinutes);

/// <summary>Where D3 gets baselines from: PostgreSQL in the Worker, a dictionary in tests and replay.</summary>
public interface IUserBaselines
{
    ValueTask<UserBaseline?> GetAsync(Guid userId, CancellationToken ct);
}

public sealed class NoBaselines : IUserBaselines
{
    public static NoBaselines Instance { get; } = new();

    public ValueTask<UserBaseline?> GetAsync(Guid userId, CancellationToken ct) => ValueTask.FromResult<UserBaseline?>(null);
}

public sealed class InMemoryBaselines(Dictionary<Guid, UserBaseline>? baselines = null) : IUserBaselines
{
    public Dictionary<Guid, UserBaseline> Baselines { get; } = baselines ?? [];

    public ValueTask<UserBaseline?> GetAsync(Guid userId, CancellationToken ct) => ValueTask.FromResult(Baselines.GetValueOrDefault(userId));
}
