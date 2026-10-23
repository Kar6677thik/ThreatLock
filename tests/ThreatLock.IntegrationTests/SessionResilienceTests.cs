using System.Net;
using System.Net.Http.Json;
using ThreatLock.Api.Auth;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>
/// What happens to the session check when its stores fail (SPEC §6.5): Redis down means slower
/// but still correct; Redis *and* PostgreSQL down means 503, never "let it through".
/// </summary>
public class SessionResilienceTests(ContainersFixture containers)
{
    private const string UnreachableRedis = "127.0.0.1:1";
    private const string UnreachablePostgres = "Host=127.0.0.1;Port=1;Database=x;Username=x;Password=x;Timeout=2";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Without_Redis_sessions_still_work_and_revocation_is_still_immediate()
    {
        await using var api = new ThreatLockApiFactory(containers.Postgres.GetConnectionString(), UnreachableRedis);
        var owner = await api.RegisterOrgAsync();

        Assert.Equal(HttpStatusCode.OK, (await owner.Client.GetAsync("/api/notes", Ct)).StatusCode);

        using var copy = api.CreateClient(owner.AccessToken);
        await owner.Client.PostAsync("/api/auth/logout", null, Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, (await copy.GetAsync("/api/notes", Ct)).StatusCode);
    }

    [Fact]
    public async Task With_Redis_and_PostgreSQL_down_requests_fail_closed_with_503()
    {
        await using var api = new ThreatLockApiFactory(UnreachablePostgres, UnreachableRedis);
        var token = TestTokens.Create(Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), sessionId: Guid.NewGuid().ToString());
        using var client = api.CreateClient(token);

        var response = await client.GetAsync("/api/me", Ct);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task A_session_revoked_while_Redis_was_down_stays_revoked_when_Redis_returns()
    {
        // Revoke through an API instance that can't reach Redis (PostgreSQL only)...
        await using var noRedis = new ThreatLockApiFactory(containers.Postgres.GetConnectionString(), UnreachableRedis);
        var owner = await containers.Api.RegisterOrgAsync();
        using (var viaNoRedis = noRedis.CreateClient(owner.AccessToken))
        {
            await viaNoRedis.PostAsync("/api/auth/logout", null, Ct);
        }

        // ...then use the token against the normal instance. Nothing was cached for this session
        // before, so the miss falls through to PostgreSQL, which knows it's revoked.
        using var client = containers.Api.CreateClient(owner.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/me", Ct)).StatusCode);
    }

    [Fact]
    public async Task Login_records_device_and_user_agent_and_drops_malformed_device_ids()
    {
        var owner = await containers.Api.RegisterOrgAsync();

        var good = await RawAuth.LoginAsync(containers.Api, owner.User.Email, owner.Password,
            new Dictionary<string, string> { ["X-Device-Id"] = "3f1c9a2e-laptop", ["User-Agent"] = "TestBrowser/1.0" });
        var bad = await RawAuth.LoginAsync(containers.Api, owner.User.Email, owner.Password,
            new Dictionary<string, string> { ["X-Device-Id"] = "<script>alert(1)</script>" });

        using var client = containers.Api.CreateClient(good.Body.AccessToken);
        var sessions = await client.GetFromJsonAsync<List<SessionView>>("/api/me/sessions", Ct);
        var goodSession = sessions!.Single(s => s.Id.ToString() == TestTokens.Claim(good.Body.AccessToken, "sid"));
        var badSession = sessions!.Single(s => s.Id.ToString() == TestTokens.Claim(bad.Body.AccessToken, "sid"));

        Assert.Equal(("3f1c9a2e-laptop", "TestBrowser/1.0"), (goodSession.DeviceId, goodSession.UserAgent));
        Assert.Null(badSession.DeviceId);
    }
}
