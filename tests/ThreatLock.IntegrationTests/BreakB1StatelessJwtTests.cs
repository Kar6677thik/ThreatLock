using System.Net;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>
/// Break B1 (SPEC §15), both halves.
/// <para>
/// <b>Break:</b> with <c>Auth:Mode=StatelessJwt</c> nothing the server checks changes when a user
/// logs out or is revoked, so a copied token keeps working until it expires. These tests assert
/// the vulnerable behaviour on purpose, so the failure stays reproducible.
/// </para>
/// <b>Prove:</b> in the default <c>SessionChecked</c> mode the same steps make the copied token
/// fail on the very next request.
/// </summary>
public sealed class BreakB1StatelessJwtTests(ContainersFixture containers) : IAsyncDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly ThreatLockApiFactory stateless = new(containers, new Dictionary<string, string?>
    {
        ["Auth:Mode"] = "StatelessJwt",
        ["Auth:AccessTokenMinutes"] = "60",
    });

    public ValueTask DisposeAsync() => stateless.DisposeAsync();

    public static TheoryData<string> Revocations => ["victim-logs-out", "admin-revokes"];

    [Theory]
    [MemberData(nameof(Revocations))]
    public async Task Break_stateless_mode_a_stolen_token_survives(string revocation)
    {
        var attackerStatus = await StealThenRevokeAsync(stateless, revocation);

        Assert.Equal(HttpStatusCode.OK, attackerStatus);
    }

    [Theory]
    [MemberData(nameof(Revocations))]
    public async Task Prove_session_checked_mode_a_stolen_token_dies_on_the_next_request(string revocation)
    {
        var attackerStatus = await StealThenRevokeAsync(containers.Api, revocation);

        Assert.Equal(HttpStatusCode.Unauthorized, attackerStatus);
    }

    /// <summary>Victim signs in, attacker copies the token, then the session is revoked.</summary>
    private static async Task<HttpStatusCode> StealThenRevokeAsync(ThreatLockApiFactory api, string revocation)
    {
        var owner = await api.RegisterOrgAsync("Owner");
        var victim = await api.CreateUserAsync(owner, "Victim");
        await victim.CreateNoteAsync("Quarterly numbers");
        using var attacker = api.CreateClient(victim.AccessToken);   // a copied token
        Assert.Equal(HttpStatusCode.OK, (await attacker.GetAsync("/api/notes/export", Ct)).StatusCode);

        var response = revocation == "victim-logs-out"
            ? await victim.Client.PostAsync("/api/auth/logout", null, Ct)
            : await owner.Client.PostAsync($"/api/admin/users/{victim.User.Id}/revoke-sessions", null, Ct);
        Assert.True(response.IsSuccessStatusCode);

        return (await attacker.GetAsync("/api/notes/export", Ct)).StatusCode;
    }
}
