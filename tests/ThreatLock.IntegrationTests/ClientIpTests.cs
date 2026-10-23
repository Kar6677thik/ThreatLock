using System.Net;
using System.Net.Http.Json;
using ThreatLock.Api.Auth;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>
/// ADR-0007: X-Forwarded-For is believed only when the connection comes from a configured
/// proxy. Otherwise a client could simply claim any IP it likes.
/// </summary>
public class ClientIpTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly Dictionary<string, string?> TrustPodNetwork = new() { ["Network:KnownNetworks:0"] = "10.0.0.0/8" };

    [Theory]
    [InlineData("10.0.0.5", "203.0.113.9")]     // from the trusted proxy: use the forwarded client IP
    [InlineData("192.0.2.1", "192.0.2.1")]      // from anyone else: ignore the header, use the peer
    public async Task Forwarded_for_is_trusted_only_from_known_proxies(string peer, string expectedIp)
    {
        await using var api = new ThreatLockApiFactory(containers, TrustPodNetwork) { RemoteIp = IPAddress.Parse(peer) };
        var owner = await api.RegisterOrgAsync();

        var login = await RawAuth.LoginAsync(api, owner.User.Email, owner.Password,
            new Dictionary<string, string> { ["X-Forwarded-For"] = "203.0.113.9" });

        Assert.Equal(expectedIp, await SessionIpAsync(api, login.Body.AccessToken));
    }

    [Fact]
    public async Task Only_the_last_hop_counts_so_a_client_cannot_prepend_a_fake_address()
    {
        // The client sends "X-Forwarded-For: 198.51.100.66"; the trusted proxy appends the real
        // client address. With ForwardLimit = 1 only the proxy's entry is used.
        await using var api = new ThreatLockApiFactory(containers, TrustPodNetwork) { RemoteIp = IPAddress.Parse("10.0.0.5") };
        var owner = await api.RegisterOrgAsync();

        var login = await RawAuth.LoginAsync(api, owner.User.Email, owner.Password,
            new Dictionary<string, string> { ["X-Forwarded-For"] = "198.51.100.66, 203.0.113.9" });

        Assert.Equal("203.0.113.9", await SessionIpAsync(api, login.Body.AccessToken));
    }

    private static async Task<string?> SessionIpAsync(ThreatLockApiFactory api, string accessToken)
    {
        using var client = api.CreateClient(accessToken);
        var sessions = await client.GetFromJsonAsync<List<SessionView>>("/api/me/sessions", Ct);
        return sessions!.Single(s => s.Current).Ip;
    }
}
