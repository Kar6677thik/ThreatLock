using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using ThreatLock.Api.Admin;
using ThreatLock.Api.Auth;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Policy;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>What admins and users see of responses: locks, the inbox, jobs and the anomaly timeline (SPEC §10, §13).</summary>
public class ResponseApiTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private ThreatLockApiFactory Api => containers.Api;

    private async Task<HttpResponseMessage> LoginFromAsync(string ip, TestUser user, string? password = null)
    {
        using var client = Api.CreateSimulatedClient(ip);
        return await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(user.User.Email, password ?? user.Password), Ct);
    }

    private async Task<AnomalyView> RespondedTorAnomalyAsync(TestUser owner, TestUser victim)
    {
        (await LoginFromAsync(TestGeoIpLookup.TorExitIp, victim)).EnsureSuccessStatusCode();
        var id = await Eventually.GetAsync(() => containers.ScalarAsync<Guid?>(
            "SELECT a.id FROM anomalies a JOIN response_jobs j ON j.anomaly_id = a.id WHERE a.user_id = $1 AND j.status = 'succeeded'",
            victim.User.Id), what: "response finished");
        return (await owner.Client.GetFromJsonAsync<AnomalyView>($"/api/admin/anomalies/{id}", Ct))!;
    }

    [Fact]
    public async Task Revoke_and_lock_refuses_login_with_a_clear_reason_until_an_admin_unlocks()
    {
        var owner = await Api.RegisterOrgAsync();
        await PolicyTests.ChangeAsync(owner, p => p with { Response = new ResponsePolicy(ResponseActions.RevokeAndLock) });
        var victim = await Api.CreateUserAsync(owner, "Victim");

        await RespondedTorAnomalyAsync(owner, victim);

        var locked = await LoginFromAsync(TestGeoIpLookup.BangaloreIp, victim);
        Assert.Equal(HttpStatusCode.Forbidden, locked.StatusCode);
        var problem = await locked.Content.ReadFromJsonAsync<JsonElement>(Ct);
        Assert.Equal(AuthEndpoints.AccountLockedCode, problem.GetProperty("code").GetString());

        // Without the password you learn nothing: same 401 as any wrong password.
        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginFromAsync(TestGeoIpLookup.BangaloreIp, victim, "wrong password!!")).StatusCode);

        var users = await owner.Client.GetFromJsonAsync<List<AdminUserView>>("/api/admin/users", Ct);
        Assert.Equal(DetectorIds.Tor, users!.Single(u => u.Id == victim.User.Id).SecurityLockedReason);

        Assert.Equal(HttpStatusCode.NoContent, (await owner.Client.PostAsync($"/api/admin/users/{victim.User.Id}/unlock", null, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await LoginFromAsync(TestGeoIpLookup.BangaloreIp, victim)).StatusCode);
    }

    [Fact]
    public async Task Only_security_admins_of_the_same_org_can_unlock()
    {
        var owner = await Api.RegisterOrgAsync();
        var admin = await Api.CreateUserAsync(owner, "Admin", "admin");
        var victim = await Api.CreateUserAsync(owner, "Victim");
        var otherOrg = await Api.RegisterOrgAsync("Other");

        Assert.Equal(HttpStatusCode.Forbidden, (await admin.Client.PostAsync($"/api/admin/users/{victim.User.Id}/unlock", null, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await otherOrg.Client.PostAsync($"/api/admin/users/{victim.User.Id}/unlock", null, Ct)).StatusCode);
    }

    [Fact]
    public async Task The_inbox_shows_each_admin_their_own_notifications_without_ips()
    {
        var owner = await Api.RegisterOrgAsync();
        var admin = await Api.CreateUserAsync(owner, "Admin", "admin");
        var victim = await Api.CreateUserAsync(owner, "Victim");
        var member = await Api.CreateUserAsync(owner, "Member");
        var anomaly = await RespondedTorAnomalyAsync(owner, victim);

        var inbox = await owner.Client.GetFromJsonAsync<Inbox>("/api/admin/notifications", Ct);
        var item = Assert.Single(inbox!.Items);
        Assert.Equal((1, "Tor exit node: Victim", anomaly.Id), (inbox.Unread, item.Title, item.AnomalyId));
        Assert.DoesNotContain(TestGeoIpLookup.TorExitIp, item.Title, StringComparison.Ordinal);

        // Another admin can't touch the owner's entry; it's simply not theirs.
        Assert.Equal(HttpStatusCode.NotFound, (await admin.Client.PostAsync($"/api/admin/notifications/{item.Id}/read", null, Ct)).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await owner.Client.PostAsync($"/api/admin/notifications/{item.Id}/read", null, Ct)).StatusCode);
        Assert.Equal(0, (await owner.Client.GetFromJsonAsync<Inbox>("/api/admin/notifications", Ct))!.Unread);
        Assert.Equal(1, (await admin.Client.GetFromJsonAsync<Inbox>("/api/admin/notifications", Ct))!.Unread);
        Assert.Equal(HttpStatusCode.Forbidden, (await member.Client.GetAsync("/api/admin/notifications", Ct)).StatusCode);
    }

    [Fact]
    public async Task The_anomaly_detail_shows_the_response_timeline()
    {
        var owner = await Api.RegisterOrgAsync();
        var victim = await Api.CreateUserAsync(owner, "Victim");

        var anomaly = await RespondedTorAnomalyAsync(owner, victim);

        Assert.NotNull(anomaly.RespondedAt);
        Assert.Equal(("revoke_sessions", "succeeded", 1), (anomaly.Response!.Action, anomaly.Response.Status, anomaly.Response.Attempts));
        Assert.NotNull(anomaly.Response.RevokedAt);
        Assert.NotNull(anomaly.Response.NotifiedAt);
        Assert.Equal(2, anomaly.RevokedSessions);   // the victim's own session and the Tor one
    }

    [Fact]
    public async Task Dead_jobs_are_listed_and_can_be_retried_once()
    {
        var owner = await Api.RegisterOrgAsync();
        var victim = await Api.CreateUserAsync(owner, "Victim");
        var member = await Api.CreateUserAsync(owner, "Member");
        var otherOrg = await Api.RegisterOrgAsync("Other");
        var anomaly = await RespondedTorAnomalyAsync(owner, victim);
        await using (var db = containers.Db())
        {
            // As if it had failed five times.
            await using var kill = db.CreateCommand("UPDATE response_jobs SET status = 'dead', last_error = 'TimeoutException: boom' WHERE id = $1");
            kill.Parameters.AddWithValue(anomaly.Response!.Id);
            await kill.ExecuteNonQueryAsync(Ct);
        }

        var dead = await owner.Client.GetFromJsonAsync<List<ResponseJobView>>("/api/admin/response-jobs", Ct);
        Assert.Equal(anomaly.Response!.Id, Assert.Single(dead!).Id);
        Assert.Equal(HttpStatusCode.Forbidden, (await member.Client.GetAsync("/api/admin/response-jobs", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await otherOrg.Client.PostAsync($"/api/admin/response-jobs/{anomaly.Response.Id}/retry", null, Ct)).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await owner.Client.PostAsync($"/api/admin/response-jobs/{anomaly.Response.Id}/retry", null, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await owner.Client.PostAsync($"/api/admin/response-jobs/{anomaly.Response.Id}/retry", null, Ct)).StatusCode);

        await Eventually.TrueAsync(async () =>
            await containers.ScalarAsync<string>("SELECT status FROM response_jobs WHERE id = $1", anomaly.Response.Id) == "succeeded",
            what: "retried job succeeded");
        // The steps had already run before the job "died": the retry didn't repeat them.
        Assert.Equal(1L, await containers.ScalarAsync<long>("SELECT count(*) FROM notifications WHERE anomaly_id = $1", anomaly.Id));
        Assert.Equal(HttpStatusCode.BadRequest, (await owner.Client.GetAsync("/api/admin/response-jobs?status=bogus", Ct)).StatusCode);
    }
}
