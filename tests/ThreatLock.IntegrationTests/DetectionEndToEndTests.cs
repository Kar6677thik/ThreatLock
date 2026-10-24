using System.Net;
using System.Net.Http.Json;
using ThreatLock.Api.Admin;
using ThreatLock.Api.Auth;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>
/// The whole M4 pipeline with real processes: API → PostgreSQL + Redis stream → Worker →
/// detectors → anomalies → admin API (SPEC §5.2).
/// </summary>
public class DetectionEndToEndTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private ThreatLockApiFactory Api => containers.Api;

    private static Task<List<AnomalyView>> AnomaliesAsync(TestUser admin, string detector, int atLeast = 1) =>
        Eventually.GetAsync(async () =>
        {
            var list = await admin.Client.GetFromJsonAsync<List<AnomalyView>>($"/api/admin/anomalies?detector={detector}", Ct);
            return list!.Count >= atLeast ? list : null;
        }, what: $"{atLeast} {detector} anomaly");

    private async Task<string> LoginFromAsync(string ip, TestUser user)
    {
        using var client = Api.CreateSimulatedClient(ip);
        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(user.User.Email, user.Password), Ct);
        return (await response.Content.ReadFromJsonAsync<LoginResponse>(Ct))!.AccessToken;
    }

    [Fact]
    public async Task D1_login_and_activity_through_a_tor_exit_become_one_anomaly()
    {
        var owner = await Api.RegisterOrgAsync();
        var victim = await Api.CreateUserAsync(owner, "Victim");
        var token = await LoginFromAsync(TestGeoIpLookup.TorExitIp, victim);
        using var attacker = Api.CreateSimulatedClient(TestGeoIpLookup.TorExitIp, token);
        await attacker.GetAsync("/api/notes/export", Ct);

        // Two events (login + export), same session, same dedupe key: one anomaly holding both.
        var anomaly = Assert.Single(await Eventually.GetAsync(async () =>
        {
            var list = await AnomaliesAsync(owner, "tor");
            return list[0].EventCount >= 2 ? list : null;
        }, what: "tor anomaly with both events"));
        Assert.Equal(("high", victim.User.Id, "Victim"), (anomaly.Severity, anomaly.UserId, anomaly.UserName));
        Assert.Equal(TestGeoIpLookup.TorExitIp, anomaly.Evidence.GetProperty("ip").GetString());
        Assert.True(anomaly.Evidence.GetProperty("simulated").GetBoolean());
    }

    [Fact]
    public async Task D2_bangalore_then_london_minutes_later_is_impossible_travel()
    {
        var owner = await Api.RegisterOrgAsync();
        var victim = await Api.CreateUserAsync(owner, "Traveller");
        var token = await LoginFromAsync(TestGeoIpLookup.BangaloreIp, victim);
        using var fromLondon = Api.CreateSimulatedClient(TestGeoIpLookup.LondonIp, token);
        await fromLondon.GetAsync("/api/notes", Ct);

        var anomaly = Assert.Single(await AnomaliesAsync(owner, "impossible_travel"));
        Assert.Equal("IN", anomaly.Evidence.GetProperty("from").GetProperty("country").GetString());
        Assert.Equal("GB", anomaly.Evidence.GetProperty("to").GetProperty("country").GetString());
        Assert.True(anomaly.Evidence.GetProperty("distanceKm").GetDouble() > 7000);
    }

    [Fact]
    public async Task Nearby_cities_are_not_impossible_travel()
    {
        var owner = await Api.RegisterOrgAsync();
        var user = await Api.CreateUserAsync(owner, "Commuter");
        var token = await LoginFromAsync(TestGeoIpLookup.BangaloreIp, user);
        using var fromChennai = Api.CreateSimulatedClient(TestGeoIpLookup.ChennaiIp, token);
        await fromChennai.GetAsync("/api/notes", Ct);
        // Absence is hard to test: "no anomaly yet" might just mean "not processed yet". So a
        // *different* user triggers a marker anomaly afterwards. One consumer reads the stream in
        // order, so once the marker exists, the commuter's events have been processed too.
        var markerUser = await Api.CreateUserAsync(owner, "Marker");
        await LoginFromAsync(TestGeoIpLookup.TorExitIp, markerUser);
        await AnomaliesAsync(owner, "tor");

        var travel = await owner.Client.GetFromJsonAsync<List<AnomalyView>>("/api/admin/anomalies?detector=impossible_travel", Ct);
        Assert.Empty(travel!);
    }

    [Fact]
    public async Task Anomalies_are_visible_only_to_admins_of_the_same_org()
    {
        var owner = await Api.RegisterOrgAsync();
        var member = await Api.CreateUserAsync(owner, "Member");
        await LoginFromAsync(TestGeoIpLookup.TorExitIp, member);
        var anomaly = (await AnomaliesAsync(owner, "tor"))[0];
        var otherOrg = await Api.RegisterOrgAsync("Other");

        Assert.Equal(HttpStatusCode.Forbidden, (await member.Client.GetAsync("/api/admin/anomalies", Ct)).StatusCode);
        Assert.Empty((await otherOrg.Client.GetFromJsonAsync<List<AnomalyView>>("/api/admin/anomalies", Ct))!);
        Assert.Equal(HttpStatusCode.NotFound, (await otherOrg.Client.GetAsync($"/api/admin/anomalies/{anomaly.Id}", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await owner.Client.GetAsync($"/api/admin/anomalies/{anomaly.Id}", Ct)).StatusCode);
    }
}
