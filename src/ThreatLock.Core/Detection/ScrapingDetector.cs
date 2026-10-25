using System.Globalization;
using System.Text.Json.Nodes;
using ThreatLock.Core.Events;
using ThreatLock.Core.Policy;

namespace ThreatLock.Core.Detection;

/// <summary>Tunables for D3 (SPEC §8.2). Orgs override them through policy thresholds.</summary>
/// <param name="K">How many standard deviations above the user's mean counts as abnormal.</param>
/// <param name="FloorPerMinute">The org-wide minimum threshold: nobody is flagged below this, whatever their baseline.</param>
/// <param name="MinActiveMinutes">A baseline built from fewer active minutes isn't trusted yet (cold start: floor only).</param>
public sealed record ScrapingSettings(double K = 4, double FloorPerMinute = 60, double MinActiveMinutes = 30)
{
    public const string KKey = "k";
    public const string FloorKey = "floorPerMinute";
    public const string MinActiveMinutesKey = "minActiveMinutes";

    public static ScrapingSettings Default { get; } = new();

    public static TimeSpan Window { get; } = TimeSpan.FromMinutes(1);

    public ScrapingSettings For(DetectorPolicy policy) => this with
    {
        K = policy.Threshold(KKey, K),
        FloorPerMinute = policy.Threshold(FloorKey, FloorPerMinute),
        MinActiveMinutes = policy.Threshold(MinActiveMinutesKey, MinActiveMinutes),
    };

    /// <summary><c>max(floor, μ + k·σ)</c>, or just the floor until the baseline has enough history.</summary>
    public double ThresholdFor(UserBaseline? baseline) =>
        baseline is { } b && b.ActiveMinutes >= MinActiveMinutes
            ? Math.Max(FloorPerMinute, b.MeanPerMinute + K * b.StdPerMinute)
            : FloorPerMinute;
}

/// <summary>
/// D3 (SPEC §8.2): a user reads notes far faster than they normally do. Counts <c>note_read</c> and
/// <c>note_listed</c> per user in a sliding one-minute window (event time) and compares the count
/// with a personal threshold from their baseline.
/// <para>
/// Every event above the threshold signals; they collapse into one anomaly per session per ten
/// minutes. Above three times the threshold a second, High-severity anomaly is raised. Before
/// the user's baseline is trusted (cold start) the first one is Low, not Medium.
/// </para>
/// Known weaknesses: a scraper that stays under the threshold is invisible, and a baseline can be
/// "trained" upwards slowly. Baseline learning caps outlier minutes to make that harder.
/// </summary>
public sealed class ScrapingDetector(ScrapingSettings? settings = null) : IDetector
{
    private readonly ScrapingSettings defaults = settings ?? ScrapingSettings.Default;

    public string Id => DetectorIds.Scraping;

    public static bool IsRead(string type) => type is EventTypes.NoteRead or EventTypes.NoteListed;

    public async ValueTask<IReadOnlyList<DetectionSignal>> EvaluateAsync(ActivityEvent evt, DetectionContext context, CancellationToken ct)
    {
        if (!IsRead(evt.Type) || evt.UserId is not { } userId) return [];

        var settings = defaults.For(context.EffectivePolicy.For(Id));
        var count = await context.State.CountInWindowAsync($"scrape:{userId}", evt.Id.ToString(), evt.OccurredAt, ScrapingSettings.Window, ct);
        var baseline = await context.EffectiveBaselines.GetAsync(userId, ct);
        var threshold = settings.ThresholdFor(baseline);
        if (count <= threshold) return [];

        var extreme = count > 3 * threshold;
        var coldStart = baseline is null || baseline.ActiveMinutes < settings.MinActiveMinutes;
        // Until we know this user's normal rate, a merely-above-the-floor burst is Low: recorded,
        // but below the default minimum severity, so nobody is signed out for being a heavy reader
        // on day one. The first evaluation run showed exactly that (98 % of power users). An extreme
        // burst (3× the floor) is High either way.
        var severity = extreme ? Severity.High : coldStart ? Severity.Low : Severity.Medium;
        var bucket = evt.OccurredAt.UtcDateTime;
        var tenMinutes = $"{bucket:yyyyMMddHH}{bucket.Minute / 10}";
        var evidence = new JsonObject
        {
            ["readsLastMinute"] = count,
            ["threshold"] = Math.Round(threshold, 1),
            ["baselineMean"] = baseline is null ? null : Math.Round(baseline.MeanPerMinute, 2),
            ["baselineStd"] = baseline is null ? null : Math.Round(baseline.StdPerMinute, 2),
            ["baselineActiveMinutes"] = baseline?.ActiveMinutes,
            ["coldStart"] = coldStart,
            ["ip"] = evt.Ip,
            ["occurredAt"] = evt.OccurredAt.ToString("O", CultureInfo.InvariantCulture),
        };

        return
        [
            new DetectionSignal(Id, evt.OrgId, userId, evt.SessionId, severity,
                $"scrape:{userId}:{evt.SessionId}:{tenMinutes}{(extreme ? ":x3" : "")}", evidence, evt.Id, evt.Ip is null ? [] : [evt.Ip]),
        ];
    }
}

/// <summary>
/// Exponentially weighted mean and variance (concepts.md §3.2). Each new minute moves the mean a
/// fraction <c>alpha</c> of the way towards it, so old behaviour fades instead of counting
/// forever. Pure, so the Worker's hourly update and the tests share it.
/// </summary>
public static class Ewma
{
    public const double Alpha = 0.05;

    /// <summary>
    /// Folds one active minute's read count into the baseline. Counts above <paramref name="cap"/>
    /// are clipped first: a scraping burst that D3 just flagged shouldn't teach the baseline that
    /// bursts are normal.
    /// </summary>
    public static UserBaseline Update(UserBaseline? current, double readsInMinute, double cap = double.PositiveInfinity, double alpha = Alpha)
    {
        var x = Math.Min(readsInMinute, cap);
        if (current is null || current.ActiveMinutes == 0) return new UserBaseline(x, 0, 1);

        var variance = current.StdPerMinute * current.StdPerMinute;
        var diff = x - current.MeanPerMinute;
        var increment = alpha * diff;
        var mean = current.MeanPerMinute + increment;
        variance = (1 - alpha) * (variance + diff * increment);
        return new UserBaseline(mean, Math.Sqrt(variance), current.ActiveMinutes + 1);
    }
}
