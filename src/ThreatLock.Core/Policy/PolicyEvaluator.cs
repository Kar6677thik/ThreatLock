using System.Net;
using ThreatLock.Core.Detection;

namespace ThreatLock.Core.Policy;

public enum DecisionOutcome { Suppressed, Observed, Notified, Responded }

/// <summary>The verdict on one anomaly, with the rule that produced it.</summary>
public sealed record Decision(DecisionOutcome Outcome, string Reason);

public static class DecisionReasons
{
    public const string DetectorOff = "detector_off";
    public const string UserExcluded = "user_excluded";
    public const string RoleExcluded = "role_excluded";
    public const string TrustedNetwork = "trusted_network";
    public const string BelowMinSeverity = "below_min_severity";
    public const string ModeObserve = "mode_observe";
    public const string ModeNotify = "mode_notify";
    public const string ModeRespond = "mode_respond";
}

/// <summary>
/// The decision framework (SPEC §9.2): turns a detection into a decision using the org's policy.
/// Rules are checked in a fixed order and the first match wins, so every decision has exactly
/// one reason, and that reason is stored with the anomaly.
/// </summary>
public static class PolicyEvaluator
{
    public static Decision Decide(DetectionSignal signal, SecurityPolicy policy, IReadOnlyCollection<string> userRoles)
    {
        var detector = policy.For(signal.Detector);

        // 1. Defensive: the processor shouldn't run an "off" detector at all.
        if (detector.Mode == DetectorMode.Off) return new(DecisionOutcome.Suppressed, DecisionReasons.DetectorOff);

        // 2–3. Exclusions, e.g. a pentest account or service accounts.
        if (policy.ExcludedUserIds.Contains(signal.UserId)) return new(DecisionOutcome.Suppressed, DecisionReasons.UserExcluded);
        if (userRoles.Any(role => policy.ExcludedRoles.Contains(role, StringComparer.Ordinal)))
        {
            return new(DecisionOutcome.Suppressed, DecisionReasons.RoleExcluded);
        }

        // 4. Every address involved is the org's own network (e.g. corporate VPN egress). "Every",
        //    not "any": Bangalore office → unknown country is still worth a look.
        if (signal.Ips.Count > 0 && signal.Ips.All(ip => IsTrusted(ip, policy.TrustedNetworks)))
        {
            return new(DecisionOutcome.Suppressed, DecisionReasons.TrustedNetwork);
        }

        // 5. Too minor for this org's appetite: record, don't act.
        if (signal.Severity < detector.MinSeverity) return new(DecisionOutcome.Observed, DecisionReasons.BelowMinSeverity);

        // 6. Otherwise the detector's mode decides.
        return detector.Mode switch
        {
            DetectorMode.Observe => new(DecisionOutcome.Observed, DecisionReasons.ModeObserve),
            DetectorMode.Notify => new(DecisionOutcome.Notified, DecisionReasons.ModeNotify),
            _ => new(DecisionOutcome.Responded, DecisionReasons.ModeRespond),
        };
    }

    public static bool IsTrusted(string ip, IEnumerable<string> trustedNetworks)
    {
        if (!IPAddress.TryParse(ip, out var address)) return false;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return trustedNetworks.Any(cidr => TryParseNetwork(cidr, out var network) && network.Contains(address));
    }

    /// <summary>
    /// Parses "203.0.113.0/24", and also a bare address ("203.0.113.7") as a single-host network
    /// (/32 or /128): admins often know just their VPN's one egress IP.
    /// </summary>
    public static bool TryParseNetwork(string text, out IPNetwork network)
    {
        if (IPNetwork.TryParse(text, out network)) return true;
        if (!IPAddress.TryParse(text, out var host)) return false;

        network = new IPNetwork(host, host.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);
        return true;
    }
}
