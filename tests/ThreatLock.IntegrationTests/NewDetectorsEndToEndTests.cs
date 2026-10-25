using System.Net;
using System.Net.Http.Json;
using ThreatLock.Api.Admin;
using ThreatLock.Api.Auth;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Policy;
using ThreatLock.Infrastructure.Detection;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>D3 scraping, D4 new device + export and D5 session hijack through the real API and Worker (SPEC §8.2).</summary>
public class NewDetectorsEndToEndTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private ThreatLockApiFactory Api => containers.Api;

    private const string Chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
    private const string Firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0";

    /// <summary>A client that looks like one browser on one machine.</summary>
    private HttpClient Browser(string deviceId, string userAgent = Chrome, string? token = null)
    {
        var client = token is null ? Api.CreateClient() : Api.CreateClient(token);
        client.DefaultRequestHeaders.Add("X-Device-Id", deviceId);
        client.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
        return client;
    }

    private static async Task<LoginResponse> LoginAsync(HttpClient client, TestUser user)
    {
        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(user.User.Email, user.Password), Ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<LoginResponse>(Ct))!;
    }

    private static Task<AnomalyView> AnomalyAsync(TestUser admin, Guid userId, string detector) =>
        Eventually.GetAsync(async () =>
            (await admin.Client.GetFromJsonAsync<List<AnomalyView>>($"/api/admin/anomalies?detector={detector}", Ct))!
                .FirstOrDefault(a => a.UserId == userId), what: $"{detector} anomaly");

    private static string Device() => $"dev-{Guid.NewGuid():N}";

    [Fact]
    public async Task D3_reading_three_times_the_floor_is_scraping_and_gets_the_session_revoked()
    {
        var owner = await Api.RegisterOrgAsync();
        var scraper = await Api.CreateUserAsync(owner, "Scraper");
        var note = await owner.CreateNoteAsync("Shared plan", shared: true);

        // 181 reads in a minute: over 3× the 60/min floor, so High even with no baseline yet.
        for (var i = 0; i < 181; i++) (await scraper.Client.GetAsync($"/api/notes/{note.Id}", Ct)).EnsureSuccessStatusCode();

        await AnomalyAsync(owner, scraper.User.Id, DetectorIds.Scraping);   // the first one: Low while cold, so only observed
        var anomaly = await Eventually.GetAsync(async () =>
            (await owner.Client.GetFromJsonAsync<List<AnomalyView>>($"/api/admin/anomalies?detector={DetectorIds.Scraping}", Ct))!
                .FirstOrDefault(a => a.UserId == scraper.User.Id && a.Severity == "high"), what: "high scraping anomaly");
        Assert.Equal("responded", anomaly.Decision);
        Assert.True(anomaly.Evidence.GetProperty("coldStart").GetBoolean());
        await Eventually.TrueAsync(async () => (await scraper.Client.GetAsync("/api/notes", Ct)).StatusCode == HttpStatusCode.Unauthorized,
            what: "scraper revoked");
    }

    [Fact]
    public async Task D3_an_ongoing_scrape_is_one_anomaly_holding_at_most_100_event_ids()
    {
        var owner = await Api.RegisterOrgAsync();
        // Observe only, so the scraper isn't revoked halfway and keeps generating events.
        await PolicyTests.ChangeAsync(owner, p => p with
        {
            Detectors = new(p.Detectors) { [DetectorIds.Scraping] = new(DetectorMode.Observe, Severity.Medium) },
        });
        var scraper = await Api.CreateUserAsync(owner, "Scraper");
        var note = await owner.CreateNoteAsync("Shared plan", shared: true);

        for (var i = 0; i < 175; i++) (await scraper.Client.GetAsync($"/api/notes/{note.Id}", Ct)).EnsureSuccessStatusCode();

        await Eventually.TrueAsync(async () =>
            (await owner.Client.GetFromJsonAsync<List<AnomalyView>>($"/api/admin/anomalies?detector={DetectorIds.Scraping}", Ct))!
                .SingleOrDefault(a => a.UserId == scraper.User.Id)?.EventCount == 100, what: "capped at 100 event ids");
    }

    [Fact]
    public async Task D3_baselines_are_learnt_from_events_once_per_minute()
    {
        var owner = await Api.RegisterOrgAsync();
        var reader = await Api.CreateUserAsync(owner, "Reader");
        var now = DateTimeOffset.UtcNow;
        var start = new DateTimeOffset(now.UtcTicks - now.UtcTicks % TimeSpan.TicksPerMinute, TimeSpan.Zero).AddMinutes(-40);
        await using (var db = containers.Db())
        {
            // 30 active minutes of 10 reads each, written straight into the events table.
            await using var insert = db.CreateCommand(
                """
                INSERT INTO activity_events (id, org_id, user_id, type, occurred_at)
                SELECT gen_random_uuid(), $1, $2, 'note_read', $3 + make_interval(mins => m) + make_interval(secs => r)
                FROM generate_series(0, 29) m, generate_series(1, 10) r
                """);
            insert.Parameters.AddWithValue(owner.User.OrgId);
            insert.Parameters.AddWithValue(reader.User.Id);
            insert.Parameters.AddWithValue(start);
            await insert.ExecuteNonQueryAsync(Ct);
        }

        await using var data = containers.Db();
        var store = new UserBaselineStore(data, TimeProvider.System);
        await store.UpdateAsync(now, Ct);
        var first = await store.GetAsync(reader.User.Id, Ct);
        await store.UpdateAsync(now, Ct);   // again: the watermark makes this a no-op

        Assert.Equal((10.0, 0.0, 30L), (Math.Round(first!.MeanPerMinute, 6), Math.Round(first.StdPerMinute, 6), first.ActiveMinutes));
        Assert.Equal(30L, await containers.ScalarAsync<long>("SELECT active_minutes FROM user_baselines WHERE user_id = $1", reader.User.Id));
    }

    [Fact]
    public async Task D4_a_second_device_that_exports_right_after_its_first_login_is_flagged()
    {
        var owner = await Api.RegisterOrgAsync();
        var user = await Api.CreateUserAsync(owner, "Alex");
        using (var laptop = Browser(Device())) await LoginAsync(laptop, user);   // their usual machine

        var attackerDevice = Device();
        using var attacker = Browser(attackerDevice, Firefox);
        var login = await LoginAsync(attacker, user);
        using var session = Browser(attackerDevice, Firefox, login.AccessToken);
        (await session.GetAsync("/api/notes/export", Ct)).EnsureSuccessStatusCode();

        var anomaly = await AnomalyAsync(owner, user.User.Id, DetectorIds.NewDeviceExport);
        Assert.Equal(("responded", "high", attackerDevice), (anomaly.Decision, anomaly.Severity, anomaly.Evidence.GetProperty("deviceId").GetString()));
        Assert.Equal(2L, await containers.ScalarAsync<long>("SELECT count(*) FROM user_devices WHERE user_id = $1", user.User.Id));
    }

    [Fact]
    public async Task D4_a_users_very_first_device_exporting_is_normal_onboarding()
    {
        var owner = await Api.RegisterOrgAsync();
        var user = await Api.CreateUserAsync(owner, "Newcomer");
        var device = Device();
        using var browser = Browser(device);
        var login = await LoginAsync(browser, user);
        using var session = Browser(device, Chrome, login.AccessToken);
        (await session.GetAsync("/api/notes/export", Ct)).EnsureSuccessStatusCode();

        // Marker: a Tor login by someone else proves the export event was processed.
        var marker = await Api.CreateUserAsync(owner, "Marker");
        using (var tor = Api.CreateSimulatedClient(TestGeoIpLookup.TorExitIp)) await LoginAsync(tor, marker);
        await AnomalyAsync(owner, marker.User.Id, DetectorIds.Tor);

        Assert.Empty((await owner.Client.GetFromJsonAsync<List<AnomalyView>>($"/api/admin/anomalies?detector={DetectorIds.NewDeviceExport}", Ct))!);
    }

    [Fact]
    public async Task D5_a_copied_token_used_from_another_machine_is_a_hijack_and_is_revoked()
    {
        var owner = await Api.RegisterOrgAsync();
        var victim = await Api.CreateUserAsync(owner, "Victim");
        var device = Device();
        using var browser = Browser(device);
        var login = await LoginAsync(browser, victim);
        using (var own = Browser(device, Chrome, login.AccessToken)) (await own.GetAsync("/api/notes", Ct)).EnsureSuccessStatusCode();

        // The attacker has the access token, but not the victim's device id or browser.
        using var stolen = Browser(Device(), Firefox, login.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await stolen.GetAsync("/api/notes", Ct)).StatusCode);

        var anomaly = await AnomalyAsync(owner, victim.User.Id, DetectorIds.SessionHijack);
        Assert.Equal(("responded", "fingerprint_changed", "Firefox/Linux"),
            (anomaly.Decision, anomaly.Evidence.GetProperty("signal").GetString(), anomaly.Evidence.GetProperty("actualUserAgentFamily").GetString()));
        await Eventually.TrueAsync(async () => (await stolen.GetAsync("/api/notes", Ct)).StatusCode == HttpStatusCode.Unauthorized,
            what: "stolen token revoked");
    }

    [Fact]
    public async Task D5_refresh_token_reuse_is_critical_and_locks_the_account()
    {
        await using var api = new ThreatLockApiFactory(containers, new Dictionary<string, string?> { ["Auth:RefreshReuseGrace"] = "00:00:00" });
        var owner = await api.RegisterOrgAsync();
        var victim = await api.CreateUserAsync(owner, "Victim");
        var login = await RawAuth.LoginAsync(api, victim.User.Email, victim.Password);
        await RawAuth.RefreshAsync(api, login.RefreshCookie);
        await RawAuth.RefreshAsync(api, login.RefreshCookie);   // the thief, or the victim, second

        var anomaly = await AnomalyAsync(owner, victim.User.Id, DetectorIds.SessionHijack);
        Assert.Equal(("critical", "responded"), (anomaly.Severity, anomaly.Decision));
        await Eventually.TrueAsync(async () =>
        {
            using var client = api.CreateClient();
            var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(victim.User.Email, victim.Password), Ct);
            return response.StatusCode == HttpStatusCode.Forbidden;   // critical ≥ lockOnSeverity: locked
        }, what: "victim locked");
    }

    [Fact]
    public async Task The_last_owner_is_never_locked_only_signed_out()
    {
        await using var api = new ThreatLockApiFactory(containers, new Dictionary<string, string?> { ["Auth:RefreshReuseGrace"] = "00:00:00" });
        var owner = await api.RegisterOrgAsync();
        var login = await RawAuth.LoginAsync(api, owner.User.Email, owner.Password);
        await RawAuth.RefreshAsync(api, login.RefreshCookie);
        await RawAuth.RefreshAsync(api, login.RefreshCookie);

        var anomalyId = await Eventually.GetAsync(() => containers.ScalarAsync<Guid?>(
            "SELECT a.id FROM anomalies a JOIN response_jobs j ON j.anomaly_id = a.id WHERE a.user_id = $1 AND j.status = 'succeeded'",
            owner.User.Id), what: "response done");

        Assert.Null(await containers.ScalarAsync<DateTimeOffset?>("SELECT security_locked_at FROM users WHERE id = $1", owner.User.Id));
        Assert.Equal("last_owner", await containers.ScalarAsync<string>(
            "SELECT details->>'lockSkipped' FROM audit_log WHERE idempotency_key = $1", $"response:{anomalyId}"));
        using var client = api.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(owner.User.Email, owner.Password), Ct)).StatusCode);
    }

    [Fact]
    public async Task Orgs_can_tune_the_new_detectors()
    {
        var owner = await Api.RegisterOrgAsync();
        var saved = await PolicyTests.ChangeAsync(owner, p => p with
        {
            Detectors = new(p.Detectors)
            {
                [DetectorIds.Scraping] = new(DetectorMode.Notify, Severity.Medium, new() { [ScrapingSettings.FloorKey] = 120 }),
                [DetectorIds.NewDeviceExport] = new(DetectorMode.Observe, Severity.High, new() { [NewDeviceExportSettings.WindowMinutesKey] = 60 }),
                [DetectorIds.SessionHijack] = new(DetectorMode.Off),
            },
        });
        Assert.Equal(DetectorMode.Off, saved.Policy.Detectors[DetectorIds.SessionHijack].Mode);

        var bad = await PolicyTests.PutAsync(owner, saved.Version, saved.Policy with
        {
            Detectors = new(saved.Policy.Detectors)
            {
                [DetectorIds.Scraping] = new(DetectorMode.Respond, Severity.Medium, new() { [ScrapingSettings.KKey] = 0 }),
            },
        });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
    }
}
