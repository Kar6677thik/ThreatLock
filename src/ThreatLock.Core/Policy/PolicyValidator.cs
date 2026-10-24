using System.Net;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Identity;

namespace ThreatLock.Core.Policy;

/// <summary>
/// Checks a policy before it's saved. A typo in a security policy is a security bug (an invalid
/// CIDR that silently matches nothing, an unknown role that excludes no one), so the API rejects
/// it with field-level messages instead of storing it.
/// </summary>
public static class PolicyValidator
{
    public const int MaxListLength = 100;

    private static readonly HashSet<string> KnownDetectors = [DetectorIds.Tor, DetectorIds.ImpossibleTravel];

    /// <summary>Allowed threshold names and ranges, per detector.</summary>
    private static readonly Dictionary<string, Dictionary<string, (double Min, double Max)>> Thresholds = new()
    {
        [DetectorIds.ImpossibleTravel] = new()
        {
            [ImpossibleTravelSettings.MaxSpeedKmhKey] = (100, 20_000),
            [ImpossibleTravelSettings.MinDistanceKmKey] = (0, 5_000),
        },
    };

    /// <summary>Field path → messages. Empty means valid.</summary>
    public static Dictionary<string, string[]> Validate(SecurityPolicy policy)
    {
        var errors = new Dictionary<string, List<string>>();
        void Add(string field, string message)
        {
            if (!errors.TryGetValue(field, out var list)) errors[field] = list = [];
            list.Add(message);
        }

        if (policy.TrustedNetworks.Length > MaxListLength) Add("trustedNetworks", $"At most {MaxListLength} networks.");
        foreach (var cidr in policy.TrustedNetworks)
        {
            if (!PolicyEvaluator.TryParseNetwork(cidr, out var network))
            {
                Add("trustedNetworks", $"'{cidr}' is not a CIDR network such as 203.0.113.0/24.");
            }
            else if (network.PrefixLength == 0)
            {
                // 0.0.0.0/0 would trust the entire internet and silently switch detection off.
                Add("trustedNetworks", $"'{cidr}' trusts every address; that disables detection.");
            }
        }

        if (policy.ExcludedUserIds.Length > MaxListLength) Add("excludedUserIds", $"At most {MaxListLength} users.");
        foreach (var role in policy.ExcludedRoles.Where(r => !Roles.IsKnown(r))) Add("excludedRoles", $"Unknown role '{role}'.");
        foreach (var role in policy.NotifyRoles.Where(r => !Roles.IsKnown(r))) Add("notifyRoles", $"Unknown role '{role}'.");
        if (policy.NotifyRoles.Length == 0) Add("notifyRoles", "At least one role must be notified.");

        foreach (var (id, detector) in policy.Detectors)
        {
            if (!KnownDetectors.Contains(id))
            {
                Add($"detectors.{id}", "Unknown detector.");
                continue;
            }

            if (!Enum.IsDefined(detector.Mode)) Add($"detectors.{id}.mode", "Unknown mode.");
            if (!Enum.IsDefined(detector.MinSeverity)) Add($"detectors.{id}.minSeverity", "Unknown severity.");

            var allowed = Thresholds.GetValueOrDefault(id) ?? [];
            foreach (var (name, value) in detector.Thresholds ?? [])
            {
                if (!allowed.TryGetValue(name, out var range)) Add($"detectors.{id}.thresholds.{name}", "Unknown threshold.");
                else if (double.IsNaN(value) || value < range.Min || value > range.Max)
                {
                    Add($"detectors.{id}.thresholds.{name}", $"Must be between {range.Min} and {range.Max}.");
                }
            }
        }

        if (!ResponseActions.All.Contains(policy.Response.Action)) Add("response.action", $"Use one of: {string.Join(", ", ResponseActions.All)}.");
        if (!Enum.IsDefined(policy.Response.LockOnSeverity)) Add("response.lockOnSeverity", "Unknown severity.");

        return errors.ToDictionary(e => e.Key, e => e.Value.ToArray());
    }
}
