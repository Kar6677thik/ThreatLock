using System.Net.Http.Json;
using ThreatLock.Api.Admin;
using ThreatLock.Api.Auth;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Policy;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>
/// Policy → decision through the real Worker (SPEC §9): each rule in the evaluation order, as
/// seen on the anomaly an admin would look at.
/// </summary>
public class DecisionEndToEndTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private ThreatLockApiFactory Api => containers.Api;

    private async Task LoginFromAsync(string ip, TestUser user)
    {
        using var client = Api.CreateSimulatedClient(ip);
        (await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(user.User.Email, user.Password), Ct)).EnsureSuccessStatusCode();
    }

    private static Task<AnomalyView> SingleAnomalyAsync(TestUser admin, Guid userId, string detector) =>
        Eventually.GetAsync(async () =>
        {
            var list = await admin.Client.GetFromJsonAsync<List<AnomalyView>>($"/api/admin/anomalies?detector={detector}", Ct);
            return list!.SingleOrDefault(a => a.UserId == userId);
        }, what: $"{detector} anomaly");

    [Fact]
    public async Task With_the_default_policy_tor_is_responded_to()
    {
        var owner = await Api.RegisterOrgAsync();
        var victim = await Api.CreateUserAsync(owner, "Victim");

        await LoginFromAsync(TestGeoIpLookup.TorExitIp, victim);

        var anomaly = await SingleAnomalyAsync(owner, victim.User.Id, DetectorIds.Tor);
        Assert.Equal(("responded", DecisionReasons.ModeRespond, 0), (anomaly.Decision, anomaly.DecisionReason, anomaly.PolicyVersion));
    }

    [Fact]
    public async Task With_the_default_policy_impossible_travel_only_notifies()
    {
        var owner = await Api.RegisterOrgAsync();
        var traveller = await Api.CreateUserAsync(owner, "Traveller");

        await LoginFromAsync(TestGeoIpLookup.BangaloreIp, traveller);
        await LoginFromAsync(TestGeoIpLookup.LondonIp, traveller);

        var anomaly = await SingleAnomalyAsync(owner, traveller.User.Id, DetectorIds.ImpossibleTravel);
        Assert.Equal(("notified", DecisionReasons.ModeNotify), (anomaly.Decision, anomaly.DecisionReason));
    }

    [Fact]
    public async Task Observe_mode_records_without_acting_and_names_the_policy_version()
    {
        var owner = await Api.RegisterOrgAsync();
        var policy = await PolicyTests.ChangeAsync(owner, p => p with
        {
            Detectors = new(p.Detectors) { [DetectorIds.Tor] = new(DetectorMode.Observe) },
        });
        var victim = await Api.CreateUserAsync(owner, "Victim");

        await LoginFromAsync(TestGeoIpLookup.TorExitIp, victim);

        var anomaly = await SingleAnomalyAsync(owner, victim.User.Id, DetectorIds.Tor);
        Assert.Equal(("observed", policy.Version), (anomaly.Decision, anomaly.PolicyVersion));
    }

    [Fact]
    public async Task Excluded_users_are_suppressed_but_still_recorded()
    {
        var owner = await Api.RegisterOrgAsync();
        var pentester = await Api.CreateUserAsync(owner, "Pentester");
        await PolicyTests.ChangeAsync(owner, p => p with { ExcludedUserIds = [pentester.User.Id] });

        await LoginFromAsync(TestGeoIpLookup.TorExitIp, pentester);

        var anomaly = await SingleAnomalyAsync(owner, pentester.User.Id, DetectorIds.Tor);
        Assert.Equal(("suppressed", DecisionReasons.UserExcluded), (anomaly.Decision, anomaly.DecisionReason));
    }

    [Fact]
    public async Task Excluded_roles_are_suppressed()
    {
        var owner = await Api.RegisterOrgAsync();
        var security = await Api.CreateUserAsync(owner, "Sec", "security_admin");
        await PolicyTests.ChangeAsync(owner, p => p with { ExcludedRoles = ["security_admin"] });

        await LoginFromAsync(TestGeoIpLookup.TorExitIp, security);

        var anomaly = await SingleAnomalyAsync(owner, security.User.Id, DetectorIds.Tor);
        Assert.Equal(DecisionReasons.RoleExcluded, anomaly.DecisionReason);
    }

    [Fact]
    public async Task Travel_between_two_trusted_vpn_exits_is_suppressed()
    {
        var owner = await Api.RegisterOrgAsync();
        var commuter = await Api.CreateUserAsync(owner, "VpnUser");
        await PolicyTests.ChangeAsync(owner, p => p with { TrustedNetworks = [TestGeoIpLookup.BangaloreIp, TestGeoIpLookup.LondonIp] });

        await LoginFromAsync(TestGeoIpLookup.BangaloreIp, commuter);
        await LoginFromAsync(TestGeoIpLookup.LondonIp, commuter);

        var anomaly = await SingleAnomalyAsync(owner, commuter.User.Id, DetectorIds.ImpossibleTravel);
        Assert.Equal(("suppressed", DecisionReasons.TrustedNetwork), (anomaly.Decision, anomaly.DecisionReason));
    }

    [Fact]
    public async Task A_detector_switched_off_produces_no_anomaly_at_all()
    {
        var owner = await Api.RegisterOrgAsync();
        await PolicyTests.ChangeAsync(owner, p => p with
        {
            Detectors = new(p.Detectors) { [DetectorIds.Tor] = new(DetectorMode.Off) },
        });
        var victim = await Api.CreateUserAsync(owner, "Victim");
        await LoginFromAsync(TestGeoIpLookup.TorExitIp, victim);

        // Marker: impossible travel by another user (still on) proves the Tor login was processed.
        var marker = await Api.CreateUserAsync(owner, "Marker");
        await LoginFromAsync(TestGeoIpLookup.BangaloreIp, marker);
        await LoginFromAsync(TestGeoIpLookup.LondonIp, marker);
        await SingleAnomalyAsync(owner, marker.User.Id, DetectorIds.ImpossibleTravel);

        var tor = await owner.Client.GetFromJsonAsync<List<AnomalyView>>("/api/admin/anomalies?detector=tor", Ct);
        Assert.Empty(tor!);
    }

    [Fact]
    public async Task Per_org_thresholds_change_what_counts_as_impossible()
    {
        // Bangalore → Chennai is ~290 km: below the default 500 km floor, above a 100 km one.
        var owner = await Api.RegisterOrgAsync();
        await PolicyTests.ChangeAsync(owner, p => p with
        {
            Detectors = new(p.Detectors)
            {
                [DetectorIds.ImpossibleTravel] = new(DetectorMode.Notify, Severity.Low, new() { ["minDistanceKm"] = 100 }),
            },
        });
        var commuter = await Api.CreateUserAsync(owner, "Commuter");

        await LoginFromAsync(TestGeoIpLookup.BangaloreIp, commuter);
        await LoginFromAsync(TestGeoIpLookup.ChennaiIp, commuter);

        var anomaly = await SingleAnomalyAsync(owner, commuter.User.Id, DetectorIds.ImpossibleTravel);
        Assert.Equal("IN", anomaly.Evidence.GetProperty("to").GetProperty("country").GetString());
    }

    [Fact]
    public async Task Anomalies_can_be_filtered_by_decision()
    {
        var owner = await Api.RegisterOrgAsync();
        var a = await Api.CreateUserAsync(owner, "A");
        var b = await Api.CreateUserAsync(owner, "B");
        await LoginFromAsync(TestGeoIpLookup.TorExitIp, a);          // responded
        await LoginFromAsync(TestGeoIpLookup.BangaloreIp, b);
        await LoginFromAsync(TestGeoIpLookup.LondonIp, b);           // notified
        await SingleAnomalyAsync(owner, a.User.Id, DetectorIds.Tor);
        await SingleAnomalyAsync(owner, b.User.Id, DetectorIds.ImpossibleTravel);

        var notified = await owner.Client.GetFromJsonAsync<List<AnomalyView>>("/api/admin/anomalies?decision=notified", Ct);

        Assert.All(notified!, x => Assert.Equal("notified", x.Decision));
        Assert.Contains(notified!, x => x.UserId == b.User.Id);
        Assert.DoesNotContain(notified!, x => x.UserId == a.User.Id);
    }
}
