using System.Text.Json.Nodes;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Policy;

namespace ThreatLock.Core.Tests.Policy;

/// <summary>Each rule of SPEC §9.2, and that the first matching rule wins.</summary>
public class PolicyEvaluatorTests
{
    private static readonly Guid User = Guid.NewGuid();

    private static DetectionSignal Signal(string detector = DetectorIds.Tor, Severity severity = Severity.High, params string[] ips) =>
        new(detector, Guid.NewGuid(), User, Guid.NewGuid(), severity, "key", new JsonObject(), Guid.NewGuid(),
            ips.Length == 0 ? ["198.51.100.77"] : ips);

    private static SecurityPolicy With(DetectorMode mode, Severity minSeverity = Severity.Low) =>
        SecurityPolicy.Default with { Detectors = new() { [DetectorIds.Tor] = new(mode, minSeverity) } };

    private static readonly string[] Member = ["member"];

    [Fact]
    public void Default_policy_responds_to_tor_and_only_notifies_on_impossible_travel()
    {
        Assert.Equal(DecisionOutcome.Responded, PolicyEvaluator.Decide(Signal(), SecurityPolicy.Default, Member).Outcome);
        Assert.Equal(DecisionOutcome.Notified,
            PolicyEvaluator.Decide(Signal(DetectorIds.ImpossibleTravel, Severity.Medium), SecurityPolicy.Default, Member).Outcome);
    }

    [Theory]
    [InlineData(DetectorMode.Observe, DecisionOutcome.Observed, DecisionReasons.ModeObserve)]
    [InlineData(DetectorMode.Notify, DecisionOutcome.Notified, DecisionReasons.ModeNotify)]
    [InlineData(DetectorMode.Respond, DecisionOutcome.Responded, DecisionReasons.ModeRespond)]
    [InlineData(DetectorMode.Off, DecisionOutcome.Suppressed, DecisionReasons.DetectorOff)]
    public void Mode_decides_when_no_earlier_rule_matches(DetectorMode mode, DecisionOutcome outcome, string reason)
    {
        Assert.Equal(new Decision(outcome, reason), PolicyEvaluator.Decide(Signal(), With(mode), Member));
    }

    [Fact]
    public void Excluded_user_is_suppressed_even_in_respond_mode()
    {
        var policy = With(DetectorMode.Respond) with { ExcludedUserIds = [User] };

        Assert.Equal(new Decision(DecisionOutcome.Suppressed, DecisionReasons.UserExcluded), PolicyEvaluator.Decide(Signal(), policy, Member));
    }

    [Fact]
    public void Any_excluded_role_suppresses()
    {
        var policy = With(DetectorMode.Respond) with { ExcludedRoles = ["security_admin"] };

        Assert.Equal(DecisionReasons.RoleExcluded, PolicyEvaluator.Decide(Signal(), policy, ["member", "security_admin"]).Reason);
        Assert.Equal(DecisionReasons.ModeRespond, PolicyEvaluator.Decide(Signal(), policy, Member).Reason);
    }

    [Fact]
    public void Trusted_network_suppresses_only_if_every_ip_is_trusted()
    {
        var policy = SecurityPolicy.Default with { TrustedNetworks = ["203.0.113.0/24", "2001:db8::/32"] };

        var bothVpn = Signal(DetectorIds.ImpossibleTravel, Severity.Medium, "203.0.113.10", "2001:db8::5");
        var oneOutside = Signal(DetectorIds.ImpossibleTravel, Severity.Medium, "203.0.113.10", "198.51.100.7");

        Assert.Equal(DecisionReasons.TrustedNetwork, PolicyEvaluator.Decide(bothVpn, policy, Member).Reason);
        Assert.Equal(DecisionReasons.ModeNotify, PolicyEvaluator.Decide(oneOutside, policy, Member).Reason);
    }

    [Fact]
    public void Below_min_severity_is_observed_not_acted_on()
    {
        var decision = PolicyEvaluator.Decide(Signal(severity: Severity.Medium), With(DetectorMode.Respond, Severity.High), Member);

        Assert.Equal(new Decision(DecisionOutcome.Observed, DecisionReasons.BelowMinSeverity), decision);
    }

    [Fact]
    public void Earlier_rules_win_over_later_ones()
    {
        // Excluded user (rule 2) beats trusted network (rule 4) beats severity (rule 5).
        var policy = With(DetectorMode.Respond, Severity.Critical) with { ExcludedUserIds = [User], TrustedNetworks = ["198.51.100.0/24"] };

        Assert.Equal(DecisionReasons.UserExcluded, PolicyEvaluator.Decide(Signal(), policy, Member).Reason);
        Assert.Equal(DecisionReasons.TrustedNetwork, PolicyEvaluator.Decide(Signal(), policy with { ExcludedUserIds = [] }, Member).Reason);
    }

    [Fact]
    public void A_detector_missing_from_the_policy_uses_the_default_entry()
    {
        var policy = SecurityPolicy.Default with { Detectors = [] };

        Assert.Equal(DecisionOutcome.Responded, PolicyEvaluator.Decide(Signal(), policy, Member).Outcome);
    }

    [Theory]
    [InlineData("::ffff:203.0.113.10", true)]   // IPv4-mapped IPv6 is the same address
    [InlineData("203.0.114.1", false)]
    [InlineData("not-an-ip", false)]
    public void Trusted_network_matching_handles_odd_inputs(string ip, bool expected)
    {
        Assert.Equal(expected, PolicyEvaluator.IsTrusted(ip, ["203.0.113.0/24"]));
    }

    [Fact]
    public void A_bare_address_trusts_exactly_that_host()
    {
        Assert.True(PolicyEvaluator.IsTrusted("203.0.113.7", ["203.0.113.7"]));
        Assert.False(PolicyEvaluator.IsTrusted("203.0.113.8", ["203.0.113.7"]));
    }
}
