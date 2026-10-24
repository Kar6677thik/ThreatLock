using ThreatLock.Core.Detection;
using ThreatLock.Core.Policy;

namespace ThreatLock.Core.Tests.Policy;

public class PolicyValidatorTests
{
    private static Dictionary<string, string[]> Errors(SecurityPolicy policy) => PolicyValidator.Validate(policy);

    [Fact]
    public void The_default_policy_is_valid()
    {
        Assert.Empty(Errors(SecurityPolicy.Default));
    }

    [Theory]
    [InlineData("203.0.113.0/24", true)]
    [InlineData("2001:db8::/32", true)]
    [InlineData("203.0.113.7", true)]          // a bare address means just that host (/32)
    [InlineData("203.0.113.0/33", false)]
    [InlineData("office vpn", false)]
    [InlineData("0.0.0.0/0", false)]           // would trust everyone
    public void Trusted_networks_must_be_real_and_narrower_than_everything(string cidr, bool valid)
    {
        var errors = Errors(SecurityPolicy.Default with { TrustedNetworks = [cidr] });

        Assert.Equal(valid, !errors.ContainsKey("trustedNetworks"));
    }

    [Fact]
    public void Unknown_roles_detectors_thresholds_and_actions_are_rejected()
    {
        var policy = SecurityPolicy.Default with
        {
            ExcludedRoles = ["superuser"],
            NotifyRoles = [],
            Detectors = new()
            {
                ["mind_reader"] = new(DetectorMode.Respond),
                [DetectorIds.ImpossibleTravel] = new(DetectorMode.Notify, Severity.Low, new() { ["warpFactor"] = 9, ["maxSpeedKmh"] = 5 }),
            },
            Response = new("delete_account"),
        };

        var errors = Errors(policy);

        Assert.Contains("excludedRoles", errors.Keys);
        Assert.Contains("notifyRoles", errors.Keys);
        Assert.Contains("detectors.mind_reader", errors.Keys);
        Assert.Contains("detectors.impossible_travel.thresholds.warpFactor", errors.Keys);
        Assert.Contains("detectors.impossible_travel.thresholds.maxSpeedKmh", errors.Keys);   // below 100 km/h
        Assert.Contains("response.action", errors.Keys);
    }

    [Fact]
    public void Per_org_thresholds_change_what_impossible_travel_detects()
    {
        var strict = SecurityPolicy.Default.For(DetectorIds.ImpossibleTravel) with { Thresholds = new() { ["minDistanceKm"] = 100 } };

        var settings = ImpossibleTravelSettings.Default.For(strict);

        Assert.Equal((100, 900), (settings.MinDistanceKm, settings.MaxSpeedKmh));
    }
}
