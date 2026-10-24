using System.Net;
using System.Net.Http.Json;
using ThreatLock.Api.Auth;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>
/// The whole loop through the real API and Worker (SPEC §5.2): suspicious request → anomaly →
/// decision → response job → sessions revoked → the attacker's next request is refused.
/// </summary>
public class ResponseEndToEndTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private ThreatLockApiFactory Api => containers.Api;

    private async Task<LoginResponse> LoginFromAsync(string ip, TestUser user)
    {
        using var client = Api.CreateSimulatedClient(ip);
        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(user.User.Email, user.Password), Ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<LoginResponse>(Ct))!;
    }

    [Fact]
    public async Task A_tor_login_gets_every_session_of_the_user_revoked_and_the_admins_notified()
    {
        var owner = await Api.RegisterOrgAsync();
        var victim = await Api.CreateUserAsync(owner, "Victim");          // the real user, signed in at work
        Assert.Equal(HttpStatusCode.OK, (await victim.Client.GetAsync("/api/notes", Ct)).StatusCode);

        var attacker = await LoginFromAsync(TestGeoIpLookup.TorExitIp, victim);   // stolen password, via Tor
        using var attackerClient = Api.CreateClient(attacker.AccessToken);

        await Eventually.TrueAsync(async () =>
            (await attackerClient.GetAsync("/api/notes", Ct)).StatusCode == HttpStatusCode.Unauthorized, what: "attacker revoked");
        Assert.Equal(HttpStatusCode.Unauthorized, (await victim.Client.GetAsync("/api/notes", Ct)).StatusCode);

        var anomalyId = await containers.ScalarAsync<Guid>(
            "SELECT id FROM anomalies WHERE user_id = $1 AND detector = 'tor'", victim.User.Id);
        await Eventually.TrueAsync(async () =>
            await containers.ScalarAsync<string>("SELECT status FROM response_jobs WHERE anomaly_id = $1", anomalyId) == "succeeded",
            what: "job succeeded");
        Assert.Equal(2L, await containers.ScalarAsync<long>(
            "SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_by_anomaly_id = $2", victim.User.Id, anomalyId));
        Assert.NotNull(await containers.ScalarAsync<DateTimeOffset?>("SELECT responded_at FROM anomalies WHERE id = $1", anomalyId));
        Assert.Equal(1L, await containers.ScalarAsync<long>(
            "SELECT count(*) FROM notifications WHERE anomaly_id = $1 AND recipient_user_id = $2", anomalyId, owner.User.Id));
    }

    [Fact]
    public async Task A_notify_decision_tells_the_admins_but_leaves_the_sessions_alone()
    {
        var owner = await Api.RegisterOrgAsync();
        var traveller = await Api.CreateUserAsync(owner, "Traveller");

        await LoginFromAsync(TestGeoIpLookup.BangaloreIp, traveller);
        var london = await LoginFromAsync(TestGeoIpLookup.LondonIp, traveller);   // impossible travel: notify by default

        var anomalyId = await Eventually.GetAsync(() => containers.ScalarAsync<Guid?>(
            "SELECT id FROM anomalies WHERE user_id = $1 AND detector = 'impossible_travel'", traveller.User.Id), what: "anomaly");
        await Eventually.TrueAsync(async () =>
            await containers.ScalarAsync<long>("SELECT count(*) FROM notifications WHERE anomaly_id = $1", anomalyId!.Value) == 1,
            what: "notification");

        using var londonClient = Api.CreateClient(london.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await londonClient.GetAsync("/api/notes", Ct)).StatusCode);
        Assert.Null(await containers.ScalarAsync<DateTimeOffset?>("SELECT responded_at FROM anomalies WHERE id = $1", anomalyId!.Value));
    }
}
