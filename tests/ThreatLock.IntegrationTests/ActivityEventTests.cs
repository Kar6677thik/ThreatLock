using System.Net;
using System.Net.Http.Json;
using ThreatLock.Api.Auth;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>What the API records as activity events, and how (SPEC §7.1–7.2, ADR-0007).</summary>
public class ActivityEventTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private ThreatLockApiFactory Api => containers.Api;

    private Task<long> CountAsync(Guid userId, string type) =>
        containers.ScalarAsync<long>("SELECT count(*) FROM activity_events WHERE user_id = $1 AND type = $2", userId, type);

    [Fact]
    public async Task Reading_a_note_records_an_event_with_ip_geo_device_and_simulation_flag()
    {
        var owner = await Api.RegisterOrgAsync();
        var note = await owner.CreateNoteAsync("Plan");
        using var client = Api.CreateSimulatedClient(TestGeoIpLookup.LondonIp, owner.AccessToken);
        client.DefaultRequestHeaders.Add("X-Device-Id", "laptop-1234");

        await client.GetAsync($"/api/notes/{note.Id}", Ct);

        await using var db = containers.Db();
        await using var command = db.CreateCommand(
            "SELECT host(ip), geo->>'city', device_id, metadata->>'simulated', metadata->>'noteId', published_at IS NOT NULL, session_id IS NOT NULL " +
            "FROM activity_events WHERE user_id = $1 AND type = 'note_read'");
        command.Parameters.AddWithValue(owner.User.Id);
        await using var reader = await command.ExecuteReaderAsync(Ct);
        Assert.True(await reader.ReadAsync(Ct));
        Assert.Equal(TestGeoIpLookup.LondonIp, reader.GetString(0));
        Assert.Equal("London", reader.GetString(1));
        Assert.Equal("laptop-1234", reader.GetString(2));
        Assert.Equal("true", reader.GetString(3));
        Assert.Equal(note.Id.ToString(), reader.GetString(4));
        Assert.True(reader.GetBoolean(5));   // reached the stream
        Assert.True(reader.GetBoolean(6));
    }

    [Fact]
    public async Task Every_note_action_and_export_is_recorded()
    {
        var owner = await Api.RegisterOrgAsync();
        var note = await owner.CreateNoteAsync("Plan");
        await owner.Client.GetAsync("/api/notes", Ct);
        await owner.Client.PutAsJsonAsync($"/api/notes/{note.Id}", new { title = "Plan v2", body = "", shared = false }, Ct);
        await owner.Client.GetAsync("/api/notes/export", Ct);
        await owner.Client.DeleteAsync($"/api/notes/{note.Id}", Ct);

        foreach (var type in new[] { "login_succeeded", "note_created", "note_listed", "note_updated", "export_requested", "note_deleted" })
        {
            Assert.Equal(1, await CountAsync(owner.User.Id, type));
        }
    }

    [Fact]
    public async Task Wrong_password_is_recorded_for_the_user_but_unknown_emails_are_not()
    {
        var owner = await Api.RegisterOrgAsync();
        using var client = Api.CreateClient();
        await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(owner.User.Email, "wrong password!!"), Ct);
        await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(TestData.UniqueEmail(), "wrong password!!"), Ct);

        Assert.Equal(1, await CountAsync(owner.User.Id, "login_failed"));
        // An unknown email has no org to belong to, so it never becomes an event.
        Assert.Equal(0, await containers.ScalarAsync<long>("SELECT count(*) FROM activity_events WHERE user_id IS NULL"));
    }

    [Fact]
    public async Task Refresh_reuse_and_revocations_are_recorded()
    {
        await using var api = new ThreatLockApiFactory(containers, new Dictionary<string, string?> { ["Auth:RefreshReuseGrace"] = "00:00:00" });
        var owner = await api.RegisterOrgAsync();
        // Not the owner: from M8, reuse is detector D5's Critical signal, and the response signs
        // that user out everywhere, which would take the owner's admin session with it.
        var member = await api.CreateUserAsync(owner, "Member");
        var login = await RawAuth.LoginAsync(api, member.User.Email, member.Password);
        await RawAuth.RefreshAsync(api, login.RefreshCookie);
        await RawAuth.RefreshAsync(api, login.RefreshCookie);   // reuse → session revoked
        var victim = await api.CreateUserAsync(owner, "Victim");
        await owner.Client.PostAsync($"/api/admin/users/{victim.User.Id}/revoke-sessions", null, Ct);

        Assert.Equal(1, await CountAsync(member.User.Id, "token_refreshed"));
        Assert.Equal(1, await CountAsync(member.User.Id, "refresh_token_reused"));
        Assert.Equal(1, await CountAsync(victim.User.Id, "session_revoked"));
    }

    [Theory]
    [InlineData(null)]                           // no key at all
    [InlineData("wrong-key-wrong-key-wrong")]    // wrong key
    public async Task The_simulation_header_is_ignored_without_the_right_key(string? key)
    {
        var owner = await Api.RegisterOrgAsync();
        using var client = Api.CreateClient(owner.AccessToken);
        client.DefaultRequestHeaders.Add("X-Simulated-Client-Ip", TestGeoIpLookup.LondonIp);
        if (key is not null) client.DefaultRequestHeaders.Add("X-Simulator-Key", key);

        await client.GetAsync("/api/notes", Ct);

        var ip = await containers.ScalarAsync<string>(
            "SELECT host(ip) FROM activity_events WHERE user_id = $1 AND type = 'note_listed'", owner.User.Id);
        Assert.NotEqual(TestGeoIpLookup.LondonIp, ip);
    }

    [Fact]
    public async Task Simulation_disabled_ignores_even_the_right_key()
    {
        await using var api = new ThreatLockApiFactory(containers, new Dictionary<string, string?> { ["Simulation:Enabled"] = "false" });
        var owner = await api.RegisterOrgAsync();
        using var client = api.CreateSimulatedClient(TestGeoIpLookup.LondonIp, owner.AccessToken);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/notes", Ct)).StatusCode);

        var ip = await containers.ScalarAsync<string>(
            "SELECT host(ip) FROM activity_events WHERE user_id = $1 AND type = 'note_listed'", owner.User.Id);
        Assert.NotEqual(TestGeoIpLookup.LondonIp, ip);
    }

    [Fact]
    public async Task Recording_failures_never_fail_the_users_request()
    {
        // Redis unreachable: the event can't be published, but the request still succeeds and the
        // event is saved for the sweeper.
        await using var api = new ThreatLockApiFactory(containers.Postgres.GetConnectionString(), "127.0.0.1:1");
        var owner = await api.RegisterOrgAsync();

        Assert.Equal(HttpStatusCode.OK, (await owner.Client.GetAsync("/api/notes", Ct)).StatusCode);
        Assert.Equal(1, await CountAsync(owner.User.Id, "note_listed"));
    }
}
