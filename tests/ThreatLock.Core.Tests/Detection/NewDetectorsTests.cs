using System.Text.Json.Nodes;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Events;
using ThreatLock.Core.Policy;
using static ThreatLock.Core.Tests.Detection.DetectorTestData;

namespace ThreatLock.Core.Tests.Detection;

/// <summary>D3–D5 (SPEC §8.2), driven entirely by event time.</summary>
public class NewDetectorsTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static ActivityEvent At(DateTimeOffset at, string type, string? device = "device-1", string? agent = Chrome, Guid? session = null,
        JsonObject? metadata = null) =>
        new(Guid.CreateVersion7(), Org, User, session ?? Session, type, at, "203.0.113.10", Bangalore, device, agent, "req", metadata);

    private const string Chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
    private const string ChromeUpdated = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36";
    private const string Firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0";

    // ---------- D3 scraping ----------

    private static async Task<List<DetectionSignal>> ReadsAsync(int count, TimeSpan spread, DetectionContext context, ScrapingDetector? detector = null)
    {
        detector ??= new ScrapingDetector();
        var signals = new List<DetectionSignal>();
        for (var i = 0; i < count; i++)
        {
            signals.AddRange(await detector.EvaluateAsync(At(T0 + spread * i / count, EventTypes.NoteRead), context, Ct));
        }

        return signals;
    }

    [Fact]
    public async Task Sixty_reads_a_minute_is_the_cold_start_ceiling()
    {
        Assert.Empty(await ReadsAsync(60, TimeSpan.FromSeconds(59), Context()));

        var signals = await ReadsAsync(61, TimeSpan.FromSeconds(59), Context());

        var signal = Assert.Single(signals);
        Assert.Equal((DetectorIds.Scraping, Severity.Medium), (signal.Detector, signal.Severity));
        Assert.True(signal.Evidence["coldStart"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Reads_spread_over_minutes_do_not_add_up()
    {
        // 200 reads over 5 minutes is 40 a minute: never more than 60 in any one-minute window.
        Assert.Empty(await ReadsAsync(200, TimeSpan.FromMinutes(5), Context()));
    }

    [Fact]
    public async Task A_scraper_at_300_a_minute_raises_a_medium_and_a_high_anomaly()
    {
        var signals = await ReadsAsync(300, TimeSpan.FromSeconds(59), Context());

        Assert.Equal(2, signals.Select(s => s.DedupeKey).Distinct().Count());
        Assert.Contains(signals, s => s.Severity == Severity.High && s.DedupeKey.EndsWith(":x3", StringComparison.Ordinal));
        Assert.Equal(240, signals.Count);   // every read past the 60th; they collapse into the two anomalies
    }

    [Fact]
    public async Task A_trusted_baseline_raises_the_threshold_for_a_power_user()
    {
        var baselines = new InMemoryBaselines(new() { [User] = new UserBaseline(MeanPerMinute: 50, StdPerMinute: 10, ActiveMinutes: 500) });
        var context = Context() with { Baselines = baselines };   // threshold = max(60, 50 + 4·10) = 90

        Assert.Empty(await ReadsAsync(90, TimeSpan.FromSeconds(59), context));
        Assert.Equal(90.0, ScrapingSettings.Default.ThresholdFor(baselines.Baselines[User]));
    }

    [Fact]
    public async Task A_young_baseline_is_not_trusted_yet()
    {
        var context = Context() with { Baselines = new InMemoryBaselines(new() { [User] = new UserBaseline(200, 50, ActiveMinutes: 10) }) };

        Assert.NotEmpty(await ReadsAsync(61, TimeSpan.FromSeconds(59), context));
    }

    [Fact]
    public async Task A_redelivered_read_is_counted_once()
    {
        var detector = new ScrapingDetector();
        var context = Context();
        var evt = At(T0, EventTypes.NoteRead);
        for (var i = 0; i < 100; i++) await detector.EvaluateAsync(evt, context, Ct);

        Assert.Equal(1, await context.State.CountInWindowAsync($"scrape:{User}", evt.Id.ToString(), T0, ScrapingSettings.Window, Ct));
    }

    [Fact]
    public async Task Org_thresholds_change_the_floor()
    {
        var policy = SecurityPolicy.Default with
        {
            Detectors = new(SecurityPolicy.Default.Detectors)
            {
                [DetectorIds.Scraping] = new(DetectorMode.Respond, Severity.Medium, new() { [ScrapingSettings.FloorKey] = 20 }),
            },
        };

        Assert.NotEmpty(await ReadsAsync(21, TimeSpan.FromSeconds(30), Context() with { Policy = policy }));
    }

    [Fact]
    public void Ewma_converges_on_a_steady_rate_and_learns_its_spread()
    {
        UserBaseline? steady = null;
        for (var i = 0; i < 200; i++) steady = Ewma.Update(steady, 10);
        Assert.Equal(10, steady!.MeanPerMinute, precision: 6);
        Assert.Equal(0, steady.StdPerMinute, precision: 6);

        UserBaseline? varied = null;
        for (var i = 0; i < 2000; i++) varied = Ewma.Update(varied, i % 2 == 0 ? 5 : 15);
        Assert.Equal(10, varied!.MeanPerMinute, precision: 0);
        Assert.InRange(varied.StdPerMinute, 4.5, 5.5);
        Assert.Equal(2000, varied.ActiveMinutes);
    }

    [Fact]
    public void Ewma_caps_outliers_so_a_burst_cannot_train_the_baseline()
    {
        var baseline = new UserBaseline(10, 2, 100);

        var capped = Ewma.Update(baseline, 3000, cap: 60);
        var uncapped = Ewma.Update(baseline, 3000);

        Assert.True(capped.MeanPerMinute < 13);
        Assert.True(uncapped.MeanPerMinute > 150);
    }

    // ---------- D4 new device + export ----------

    private static JsonObject NewDevice(bool value = true) => new() { [NewDeviceExportDetector.NewDeviceMetadata] = value };

    [Fact]
    public async Task An_export_soon_after_a_first_login_on_a_new_device_is_flagged()
    {
        var detector = new NewDeviceExportDetector();
        var context = Context();
        await detector.EvaluateAsync(At(T0, EventTypes.LoginSucceeded, metadata: NewDevice()), context, Ct);

        var signal = Assert.Single(await detector.EvaluateAsync(At(T0.AddMinutes(2), EventTypes.ExportRequested), context, Ct));

        Assert.Equal((Severity.High, $"newdev-export:{User}:device-1"), (signal.Severity, signal.DedupeKey));
        Assert.Equal(2.0, signal.Evidence["minutesSinceFirstLogin"]!.GetValue<double>());
    }

    [Fact]
    public async Task An_export_after_the_window_or_from_a_known_device_is_fine()
    {
        var detector = new NewDeviceExportDetector();
        var context = Context();
        await detector.EvaluateAsync(At(T0, EventTypes.LoginSucceeded, metadata: NewDevice()), context, Ct);
        Assert.Empty(await detector.EvaluateAsync(At(T0.AddMinutes(31), EventTypes.ExportRequested), context, Ct));

        var known = Context();
        await detector.EvaluateAsync(At(T0, EventTypes.LoginSucceeded, metadata: NewDevice(false)), known, Ct);
        Assert.Empty(await detector.EvaluateAsync(At(T0.AddMinutes(1), EventTypes.ExportRequested), known, Ct));
    }

    [Fact]
    public async Task Reading_many_distinct_notes_from_a_new_device_counts_as_bulk()
    {
        var detector = new NewDeviceExportDetector();
        var context = Context();
        await detector.EvaluateAsync(At(T0, EventTypes.LoginSucceeded, metadata: NewDevice()), context, Ct);

        var signals = new List<DetectionSignal>();
        for (var i = 0; i < 80; i++)
        {
            // The same 10 notes over and over don't count; 51 different ones do.
            var noteId = (i < 30 ? i % 10 : i).ToString(System.Globalization.CultureInfo.InvariantCulture);
            signals.AddRange(await detector.EvaluateAsync(
                At(T0.AddSeconds(10 + i), EventTypes.NoteRead, metadata: new JsonObject { ["noteId"] = noteId }), context, Ct));
        }

        Assert.NotEmpty(signals);
        Assert.Equal(51, signals[0].Evidence["distinctNotesRead"]!.GetValue<long>());
    }

    [Fact]
    public async Task Events_without_a_device_id_are_ignored()
    {
        var detector = new NewDeviceExportDetector();
        var context = Context();
        await detector.EvaluateAsync(At(T0, EventTypes.LoginSucceeded, device: null, metadata: NewDevice()), context, Ct);

        Assert.Empty(await detector.EvaluateAsync(At(T0.AddMinutes(1), EventTypes.ExportRequested, device: null), context, Ct));
    }

    // ---------- D5 session hijack ----------

    [Fact]
    public async Task Refresh_token_reuse_is_critical()
    {
        var signal = Assert.Single(await new SessionHijackDetector().EvaluateAsync(At(T0, EventTypes.RefreshTokenReused), Context(), Ct));

        Assert.Equal((Severity.Critical, $"hijack:{Session}"), (signal.Severity, signal.DedupeKey));
    }

    [Fact]
    public async Task The_same_session_from_another_device_is_a_hijack()
    {
        var detector = new SessionHijackDetector();
        var context = Context();
        Assert.Empty(await detector.EvaluateAsync(At(T0, EventTypes.LoginSucceeded), context, Ct));
        Assert.Empty(await detector.EvaluateAsync(At(T0.AddMinutes(1), EventTypes.NoteRead), context, Ct));

        var signal = Assert.Single(await detector.EvaluateAsync(At(T0.AddMinutes(2), EventTypes.NoteRead, device: "attacker-laptop", agent: Firefox), context, Ct));

        Assert.Equal(Severity.High, signal.Severity);
        Assert.Equal(("device-1", "attacker-laptop"), (signal.Evidence["expectedDevice"]!.GetValue<string>(), signal.Evidence["actualDevice"]!.GetValue<string>()));
        Assert.Equal("Firefox/Linux", signal.Evidence["actualUserAgentFamily"]!.GetValue<string>());
    }

    [Fact]
    public async Task A_browser_update_or_a_new_ip_is_not_a_hijack()
    {
        var detector = new SessionHijackDetector();
        var context = Context();
        await detector.EvaluateAsync(At(T0, EventTypes.LoginSucceeded), context, Ct);

        Assert.Empty(await detector.EvaluateAsync(At(T0.AddMinutes(5), EventTypes.NoteRead, agent: ChromeUpdated), context, Ct));
        var moved = At(T0.AddMinutes(6), EventTypes.NoteRead) with { Ip = "198.51.100.200" };
        Assert.Empty(await detector.EvaluateAsync(moved, context, Ct));
    }

    [Fact]
    public async Task Each_session_keeps_its_own_fingerprint()
    {
        var detector = new SessionHijackDetector();
        var context = Context();
        var laptop = Guid.NewGuid();
        var phone = Guid.NewGuid();
        await detector.EvaluateAsync(At(T0, EventTypes.LoginSucceeded, session: laptop), context, Ct);
        await detector.EvaluateAsync(At(T0, EventTypes.LoginSucceeded, device: "phone", agent: Firefox, session: phone), context, Ct);

        Assert.Empty(await detector.EvaluateAsync(At(T0.AddMinutes(1), EventTypes.NoteRead, device: "phone", agent: Firefox, session: phone), context, Ct));
    }

    [Theory]
    [InlineData(Chrome, "Chrome/Windows")]
    [InlineData("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0", "Edge/Windows")]
    [InlineData(Firefox, "Firefox/Linux")]
    [InlineData("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15", "Safari/macOS")]
    [InlineData("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1", "Safari/iOS")]
    [InlineData("Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36", "Chrome/Android")]
    [InlineData("curl/8.15.0", "curl/other")]
    [InlineData(null, "none")]
    public void User_agents_reduce_to_browser_and_os(string? agent, string family) => Assert.Equal(family, UserAgentFamily.Of(agent));

    [Fact]
    public void The_new_detectors_have_valid_default_policies()
    {
        Assert.Empty(PolicyValidator.Validate(SecurityPolicy.Default));
        Assert.All(DetectorIds.All, id => Assert.NotEqual(DetectorMode.Off, SecurityPolicy.Default.For(id).Mode));
    }
}
