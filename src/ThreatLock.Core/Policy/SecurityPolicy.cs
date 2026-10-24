using ThreatLock.Core.Detection;
using ThreatLock.Core.Identity;

namespace ThreatLock.Core.Policy;

/// <summary>What a detector's anomalies lead to, per org (SPEC §9.1).</summary>
public enum DetectorMode
{
    /// <summary>The detector doesn't run for this org at all.</summary>
    Off,

    /// <summary>Record the anomaly, tell nobody. For tuning a noisy detector.</summary>
    Observe,

    /// <summary>Record and notify admins (M6).</summary>
    Notify,

    /// <summary>Record, revoke the user's sessions and notify admins (M6).</summary>
    Respond,
}

public static class ResponseActions
{
    public const string RevokeSessions = "revoke_sessions";
    public const string RevokeAndLock = "revoke_and_lock";

    public static IReadOnlyList<string> All { get; } = [RevokeSessions, RevokeAndLock];
}

/// <summary>Per-detector settings. <see cref="Thresholds"/> holds detector-specific numbers, e.g. <c>maxSpeedKmh</c>.</summary>
public sealed record DetectorPolicy(DetectorMode Mode, Severity MinSeverity = Severity.Low, Dictionary<string, double>? Thresholds = null)
{
    public double Threshold(string name, double fallback) =>
        Thresholds is not null && Thresholds.TryGetValue(name, out var value) ? value : fallback;
}

/// <summary>What "respond" does (SPEC §10.3). Executed by the response orchestrator in M6.</summary>
public sealed record ResponsePolicy(string Action = ResponseActions.RevokeSessions, Severity LockOnSeverity = Severity.Critical);

/// <summary>
/// One org's security policy (SPEC §9). Stored as a versioned JSON document; every anomaly
/// records the version that judged it, so "why did this happen?" is always answerable.
/// Policy is *data*, not code: each org changes its own behaviour without a deployment.
/// </summary>
public sealed record SecurityPolicy(
    string[] TrustedNetworks,
    Guid[] ExcludedUserIds,
    string[] ExcludedRoles,
    string[] NotifyRoles,
    Dictionary<string, DetectorPolicy> Detectors,
    ResponsePolicy Response)
{
    /// <summary>The policy of an org that never edited it (SPEC §9.3). Impossible travel only notifies: it's the noisiest.</summary>
    public static SecurityPolicy Default { get; } = new(
        TrustedNetworks: [],
        ExcludedUserIds: [],
        ExcludedRoles: [],
        NotifyRoles: [Roles.Owner, Roles.Admin, Roles.SecurityAdmin],
        Detectors: new()
        {
            [DetectorIds.Tor] = new(DetectorMode.Respond, Severity.High),
            [DetectorIds.ImpossibleTravel] = new(DetectorMode.Notify, Severity.Low, new()
            {
                [ImpossibleTravelSettings.MaxSpeedKmhKey] = ImpossibleTravelSettings.Default.MaxSpeedKmh,
                [ImpossibleTravelSettings.MinDistanceKmKey] = ImpossibleTravelSettings.Default.MinDistanceKm,
            }),
        },
        Response: new());

    /// <summary>A detector the policy doesn't mention falls back to the default policy's entry, else observe-only.</summary>
    public DetectorPolicy For(string detectorId) =>
        Detectors.GetValueOrDefault(detectorId)
        ?? Default.Detectors.GetValueOrDefault(detectorId)
        ?? new DetectorPolicy(DetectorMode.Observe);
}
