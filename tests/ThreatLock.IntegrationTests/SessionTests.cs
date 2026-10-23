using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Time.Testing;
using ThreatLock.Api.Admin;
using ThreatLock.Api.Auth;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>Server-side sessions, refresh rotation and revocation (SPEC §6.2–6.6, ADR-0002).</summary>
public class SessionTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private ThreatLockApiFactory Api => containers.Api;

    [Fact]
    public async Task Login_sets_a_locked_down_refresh_cookie()
    {
        var owner = await Api.RegisterOrgAsync();

        var login = await RawAuth.LoginAsync(Api, owner.User.Email, owner.Password);
        var attributes = login.SetCookieHeader.ToLowerInvariant();

        Assert.Contains("httponly", attributes, StringComparison.Ordinal);
        Assert.Contains("secure", attributes, StringComparison.Ordinal);
        Assert.Contains("samesite=strict", attributes, StringComparison.Ordinal);
        Assert.Contains("path=/api/auth", attributes, StringComparison.Ordinal);
        Assert.True(login.RefreshCookie.Length >= 43);   // 32 random bytes, base64url
    }

    [Fact]
    public async Task Refresh_rotates_the_cookie_and_returns_a_working_access_token()
    {
        var owner = await Api.RegisterOrgAsync();
        var login = await RawAuth.LoginAsync(Api, owner.User.Email, owner.Password);

        var response = await RawAuth.RefreshAsync(Api, login.RefreshCookie);
        var body = await response.Content.ReadFromJsonAsync<LoginResponse>(Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var rotated = RawAuth.NewRefreshCookie(response);
        Assert.NotNull(rotated);
        Assert.NotEqual(login.RefreshCookie, rotated);
        Assert.Equal(TestTokens.Claim(login.Body.AccessToken, "sid"), TestTokens.Claim(body!.AccessToken, "sid"));
        using var client = Api.CreateClient(body.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/me", Ct)).StatusCode);
    }

    [Fact]
    public async Task Refresh_requires_the_csrf_header()
    {
        var owner = await Api.RegisterOrgAsync();
        var login = await RawAuth.LoginAsync(Api, owner.User.Email, owner.Password);

        var response = await RawAuth.RefreshAsync(Api, login.RefreshCookie, csrfHeader: false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not-a-real-token")]
    public async Task Refresh_without_a_valid_cookie_is_401(string? cookie)
    {
        var response = await RawAuth.RefreshAsync(Api, cookie);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Reusing_a_rotated_refresh_token_within_the_grace_window_is_a_harmless_409()
    {
        // Default grace is 5 s: this is two tabs refreshing at once, not theft.
        var owner = await Api.RegisterOrgAsync();
        var login = await RawAuth.LoginAsync(Api, owner.User.Email, owner.Password);
        Assert.Equal(HttpStatusCode.OK, (await RawAuth.RefreshAsync(Api, login.RefreshCookie)).StatusCode);

        var late = await RawAuth.RefreshAsync(Api, login.RefreshCookie);

        Assert.Equal(HttpStatusCode.Conflict, late.StatusCode);
        using var client = Api.CreateClient(login.Body.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/me", Ct)).StatusCode);   // session survives
    }

    [Fact]
    public async Task Concurrent_refreshes_with_the_same_cookie_produce_exactly_one_new_token()
    {
        var owner = await Api.RegisterOrgAsync();
        var login = await RawAuth.LoginAsync(Api, owner.User.Email, owner.Password);

        var responses = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => RawAuth.RefreshAsync(Api, login.RefreshCookie)));

        Assert.Single(responses, r => r.StatusCode == HttpStatusCode.OK);
        Assert.All(responses.Where(r => r.StatusCode != HttpStatusCode.OK), r => Assert.Equal(HttpStatusCode.Conflict, r.StatusCode));
    }

    [Fact]
    public async Task Reusing_an_old_refresh_token_after_the_grace_window_revokes_the_whole_session()
    {
        // Grace 0: any second use is treated as two parties holding the token.
        await using var api = new ThreatLockApiFactory(containers, new Dictionary<string, string?> { ["Auth:RefreshReuseGrace"] = "00:00:00" });
        var owner = await api.RegisterOrgAsync();
        var victim = await RawAuth.LoginAsync(api, owner.User.Email, owner.Password);
        var stolenCookie = victim.RefreshCookie;

        // The victim refreshes normally and gets a new access token...
        var victimRefresh = await RawAuth.RefreshAsync(api, victim.RefreshCookie);
        var victimToken = (await victimRefresh.Content.ReadFromJsonAsync<LoginResponse>(Ct))!.AccessToken;

        // ...then the attacker replays the stolen (now old) cookie.
        var replay = await RawAuth.RefreshAsync(api, stolenCookie);

        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        using var victimClient = api.CreateClient(victimToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await victimClient.GetAsync("/api/me", Ct)).StatusCode);
        // The newest refresh token in the chain is dead too: the session itself is gone.
        Assert.Equal(HttpStatusCode.Unauthorized, (await RawAuth.RefreshAsync(api, RawAuth.NewRefreshCookie(victimRefresh))).StatusCode);
    }

    [Fact]
    public async Task Refresh_picks_up_role_changes_without_a_new_login()
    {
        var owner = await Api.RegisterOrgAsync();
        await Api.CreateUserAsync(owner, "Ben");
        var users = await owner.Client.GetFromJsonAsync<List<AdminUserView>>("/api/admin/users", Ct);
        var ben = users!.Single(u => u.DisplayName == "Ben");
        var login = await RawAuth.LoginAsync(Api, ben.Email, TestData.Password);

        await owner.Client.PutAsJsonAsync($"/api/admin/users/{ben.Id}/roles", new SetRolesRequest(["admin"]), Ct);
        var refreshed = await (await RawAuth.RefreshAsync(Api, login.RefreshCookie)).Content.ReadFromJsonAsync<LoginResponse>(Ct);

        Assert.Contains("admin", refreshed!.User.Roles);
    }

    [Fact]
    public async Task Logout_kills_the_token_and_the_refresh_cookie()
    {
        var owner = await Api.RegisterOrgAsync();
        var login = await RawAuth.LoginAsync(Api, owner.User.Email, owner.Password);
        using var client = Api.CreateClient(login.Body.AccessToken);

        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/api/auth/logout", null, Ct)).StatusCode);

        var after = await client.GetAsync("/api/me", Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        Assert.Contains("session_revoked", after.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Unauthorized, (await RawAuth.RefreshAsync(Api, login.RefreshCookie)).StatusCode);
    }

    [Fact]
    public async Task My_sessions_lists_devices_and_can_sign_one_out()
    {
        var owner = await Api.RegisterOrgAsync();
        var laptop = await Api.LoginAsync(owner.User.Email, owner.Password);
        var phone = await Api.LoginAsync(owner.User.Email, owner.Password);

        var sessions = await laptop.Client.GetFromJsonAsync<List<SessionView>>("/api/me/sessions", Ct);
        var phoneSid = Guid.Parse(TestTokens.Claim(phone.AccessToken, "sid"));

        Assert.Equal(3, sessions!.Count);   // registration + laptop + phone
        Assert.Single(sessions, s => s.Current);
        Assert.Equal(HttpStatusCode.NoContent, (await laptop.Client.DeleteAsync($"/api/me/sessions/{phoneSid}", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await phone.Client.GetAsync("/api/me", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await laptop.Client.GetAsync("/api/me", Ct)).StatusCode);
    }

    [Fact]
    public async Task You_cannot_sign_out_someone_elses_session()
    {
        var alice = await Api.RegisterOrgAsync("Alice");
        var bob = await Api.CreateUserAsync(alice, "Bob");
        var bobSid = TestTokens.Claim(bob.AccessToken, "sid");

        var response = await alice.Client.DeleteAsync($"/api/me/sessions/{bobSid}", Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await bob.Client.GetAsync("/api/me", Ct)).StatusCode);
    }

    [Fact]
    public async Task Admin_revoke_signs_the_user_out_everywhere_and_is_idempotent()
    {
        var owner = await Api.RegisterOrgAsync();
        var victim = await Api.CreateUserAsync(owner, "Victim");          // session 1
        var second = await Api.LoginAsync(victim.User.Email, victim.Password);   // session 2
        var bystander = await Api.CreateUserAsync(owner, "Bystander");

        var first = await owner.Client.PostAsync($"/api/admin/users/{victim.User.Id}/revoke-sessions", null, Ct);
        var again = await owner.Client.PostAsync($"/api/admin/users/{victim.User.Id}/revoke-sessions", null, Ct);

        Assert.Equal(2, (await first.Content.ReadFromJsonAsync<RevokeSessionsResponse>(Ct))!.RevokedSessions);
        Assert.Equal(0, (await again.Content.ReadFromJsonAsync<RevokeSessionsResponse>(Ct))!.RevokedSessions);
        Assert.Equal(HttpStatusCode.Unauthorized, (await victim.Client.GetAsync("/api/me", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await second.Client.GetAsync("/api/me", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await bystander.Client.GetAsync("/api/me", Ct)).StatusCode);
    }

    [Fact]
    public async Task Admins_can_see_a_users_sessions()
    {
        var owner = await Api.RegisterOrgAsync();
        var victim = await Api.CreateUserAsync(owner, "Victim");

        var sessions = await owner.Client.GetFromJsonAsync<List<SessionView>>($"/api/admin/users/{victim.User.Id}/sessions", Ct);

        Assert.Single(sessions!);
        Assert.False(sessions![0].Current);
    }

    [Fact]
    public async Task An_idle_session_expires()
    {
        // Idle timeout (2 min) shorter than the token (5 min): any 401 here can only come from the
        // session check, not from the token itself expiring.
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        await using var api = new ThreatLockApiFactory(containers, new Dictionary<string, string?>
        {
            ["Auth:SessionIdleTimeout"] = "00:02:00",
        }) { Clock = clock };
        var owner = await api.RegisterOrgAsync();
        using var client = api.CreateClient(owner.AccessToken);

        clock.Advance(TimeSpan.FromMinutes(3));
        var response = await client.GetAsync("/api/me", Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("session_revoked", response.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
    }
}
