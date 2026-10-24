using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using ThreatLock.Api.Admin;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Policy;
using ThreatLock.Infrastructure.Policy;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>The policy API: versions, optimistic concurrency, validation, access (SPEC §9, §13).</summary>
public class PolicyTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static JsonSerializerOptions Json => PolicyJson.Options;   // enums as "respond", "high"
    private ThreatLockApiFactory Api => containers.Api;

    public static async Task<PolicyView> GetAsync(TestUser admin) =>
        (await admin.Client.GetFromJsonAsync<PolicyView>("/api/admin/policy", Json, Ct))!;

    public static Task<HttpResponseMessage> PutAsync(TestUser admin, int expectedVersion, SecurityPolicy policy) =>
        admin.Client.PutAsJsonAsync("/api/admin/policy", new PolicyUpdate(expectedVersion, policy), Json, Ct);

    /// <summary>Saves a change to the current policy and returns the new version.</summary>
    public static async Task<PolicyView> ChangeAsync(TestUser admin, Func<SecurityPolicy, SecurityPolicy> change)
    {
        var current = await GetAsync(admin);
        var response = await PutAsync(admin, current.Version, change(current.Policy));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<PolicyView>(Json, Ct))!;
    }

    [Fact]
    public void Policy_json_uses_readable_names()
    {
        var json = JsonSerializer.Serialize(SecurityPolicy.Default, Json);

        Assert.Contains("\"mode\":\"respond\"", json, StringComparison.Ordinal);
        Assert.Contains("\"minSeverity\":\"high\"", json, StringComparison.Ordinal);
        Assert.Contains("\"action\":\"revoke_sessions\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_new_org_starts_with_the_default_policy_as_version_0()
    {
        var owner = await Api.RegisterOrgAsync();

        var policy = await GetAsync(owner);

        Assert.Equal(0, policy.Version);
        Assert.Equal(DetectorMode.Respond, policy.Policy.For(DetectorIds.Tor).Mode);
        Assert.Equal(DetectorMode.Notify, policy.Policy.For(DetectorIds.ImpossibleTravel).Mode);
    }

    [Fact]
    public async Task Saving_creates_a_new_version_and_keeps_the_history()
    {
        var owner = await Api.RegisterOrgAsync("Asha");

        var v1 = await ChangeAsync(owner, p => p with { TrustedNetworks = ["203.0.113.0/24"] });
        var v2 = await ChangeAsync(owner, p => p with { TrustedNetworks = ["203.0.113.0/24", "198.51.100.7"] });

        Assert.Equal((1, 2), (v1.Version, v2.Version));
        Assert.Equal("Asha", v2.UpdatedBy);
        var versions = await owner.Client.GetFromJsonAsync<List<PolicyVersionView>>("/api/admin/policy/versions", Ct);
        Assert.Equal([2, 1], versions!.Select(v => v.Version));
        var old = await owner.Client.GetFromJsonAsync<PolicyView>("/api/admin/policy/versions/1", Json, Ct);
        Assert.Equal(["203.0.113.0/24"], old!.Policy.TrustedNetworks);
    }

    [Fact]
    public async Task Saving_from_a_stale_version_is_refused_instead_of_overwriting()
    {
        var owner = await Api.RegisterOrgAsync();
        var security = await Api.CreateUserAsync(owner, "Sec", "security_admin");
        var both = await GetAsync(owner);   // both admins load version 0

        var first = await PutAsync(owner, both.Version, both.Policy with { ExcludedRoles = ["admin"] });
        var second = await PutAsync(security, both.Version, both.Policy with { TrustedNetworks = ["203.0.113.0/24"] });

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);   // a lost update, prevented
        Assert.Equal(["admin"], (await GetAsync(owner)).Policy.ExcludedRoles);
    }

    [Fact]
    public async Task Concurrent_saves_from_the_same_version_let_exactly_one_win()
    {
        var owner = await Api.RegisterOrgAsync();
        var start = await GetAsync(owner);

        var responses = await Task.WhenAll(Enumerable.Range(0, 5).Select(i =>
            PutAsync(owner, start.Version, start.Policy with { TrustedNetworks = [$"203.0.113.{i}"] })));

        Assert.Single(responses, r => r.StatusCode == HttpStatusCode.OK);
        Assert.All(responses.Where(r => r.StatusCode != HttpStatusCode.OK), r => Assert.Equal(HttpStatusCode.Conflict, r.StatusCode));
    }

    [Fact]
    public async Task Invalid_policies_are_rejected_with_field_errors()
    {
        var owner = await Api.RegisterOrgAsync();
        var current = await GetAsync(owner);

        var response = await PutAsync(owner, current.Version, current.Policy with { TrustedNetworks = ["0.0.0.0/0", "office"], NotifyRoles = [] });
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var fields = problem.RootElement.GetProperty("errors").EnumerateObject().Select(p => p.Name).ToList();
        Assert.Contains("trustedNetworks", fields);
        Assert.Contains("notifyRoles", fields);
        Assert.Equal(0, (await GetAsync(owner)).Version);
    }

    [Fact]
    public async Task Integer_enums_are_rejected()
    {
        // "mode": 3 is ambiguous and fragile; the API only accepts names.
        var owner = await Api.RegisterOrgAsync();
        var raw = """{"expectedVersion":0,"policy":{"trustedNetworks":[],"excludedUserIds":[],"excludedRoles":[],"notifyRoles":["owner"],"detectors":{"tor":{"mode":3}},"response":{}}}""";

        var response = await owner.Client.PutAsync("/api/admin/policy", new StringContent(raw, System.Text.Encoding.UTF8, "application/json"), Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Only_security_admins_and_owners_can_read_or_edit_policy()
    {
        var owner = await Api.RegisterOrgAsync();
        var admin = await Api.CreateUserAsync(owner, "Admin", "admin");
        var security = await Api.CreateUserAsync(owner, "Sec", "security_admin");

        Assert.Equal(HttpStatusCode.Forbidden, (await admin.Client.GetAsync("/api/admin/policy", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await security.Client.GetAsync("/api/admin/policy", Ct)).StatusCode);
    }

    [Fact]
    public async Task Policies_are_per_org()
    {
        var alice = await Api.RegisterOrgAsync("Alice");
        var mallory = await Api.RegisterOrgAsync("Mallory");
        await ChangeAsync(alice, p => p with { TrustedNetworks = ["203.0.113.0/24"] });

        Assert.Equal(0, (await GetAsync(mallory)).Version);
        Assert.Equal(HttpStatusCode.NotFound, (await mallory.Client.GetAsync("/api/admin/policy/versions/1", Ct)).StatusCode);
    }
}
