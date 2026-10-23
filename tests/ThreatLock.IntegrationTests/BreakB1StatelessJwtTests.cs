using System.Net;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>
/// Break B1 (SPEC §15): with stateless JWTs, "signing someone out" changes nothing on the
/// server that a token depends on, so a copied token keeps working until it expires.
/// <para>
/// These tests assert the *vulnerable* M2 behaviour on purpose, so the failure is recorded and
/// reproducible. M3 adds server-side sessions; these expectations then hold only for
/// <c>Auth:Mode=StatelessJwt</c>, and the default mode must reject the token.
/// </para>
/// </summary>
public class BreakB1StatelessJwtTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private ThreatLockApiFactory Api => containers.Api;

    [Fact]
    public async Task B1_a_stolen_token_still_works_after_the_victim_logs_out()
    {
        var victim = await Api.RegisterOrgAsync("Victim");
        using var attacker = Api.CreateClient(victim.AccessToken);   // a copied token

        var logout = await victim.Client.PostAsync("/api/auth/logout", null, Ct);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await attacker.GetAsync("/api/notes", Ct)).StatusCode);
    }

    [Fact]
    public async Task B1_a_stolen_token_still_works_after_an_admin_revokes_the_users_sessions()
    {
        var owner = await Api.RegisterOrgAsync("Owner");
        var victim = await Api.CreateUserAsync(owner, "Victim");
        await victim.CreateNoteAsync("Quarterly numbers");
        using var attacker = Api.CreateClient(victim.AccessToken);

        var revoke = await owner.Client.PostAsync($"/api/admin/users/{victim.User.Id}/revoke-sessions", null, Ct);
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);

        var stolen = await attacker.GetAsync("/api/notes/export", Ct);
        Assert.Equal(HttpStatusCode.OK, stolen.StatusCode);
    }
}
