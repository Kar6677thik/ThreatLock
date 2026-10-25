using Stopwatch = System.Diagnostics.Stopwatch;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Events;
using ThreatLock.Core.Policy;

namespace ThreatLock.Simulator.Evaluation;

/// <summary>What happened to one scenario instance: the decision on each anomaly it produced.</summary>
public sealed record ScenarioResult(Scenario Scenario, IReadOnlyList<(string Detector, DecisionOutcome Outcome)> Anomalies)
{
    public bool Responded => Anomalies.Any(a => a.Outcome == DecisionOutcome.Responded);
    public bool Notified => !Responded && Anomalies.Any(a => a.Outcome == DecisionOutcome.Notified);

    /// <summary>For malicious instances: an expected detector reached notified or responded.</summary>
    public bool Caught => ScenarioKinds.Expected(Scenario.Kind).Any(d =>
        Anomalies.Any(a => a.Detector == d && a.Outcome is DecisionOutcome.Notified or DecisionOutcome.Responded));

    public bool CaughtAndResponded => ScenarioKinds.Expected(Scenario.Kind).Any(d =>
        Anomalies.Any(a => a.Detector == d && a.Outcome == DecisionOutcome.Responded));
}

/// <summary>Per scenario kind.</summary>
public sealed record KindReport(string Kind, Label Label, int Instances, int Responded, int Notified, int Caught, int CaughtAndResponded,
    IReadOnlyDictionary<string, int> RespondedByDetector);

/// <summary>The evaluation's numbers (SPEC §16.1).</summary>
public sealed record EvaluationReport(
    int Seed,
    int BenignInstances,
    int MaliciousInstances,
    long Events,
    double FalsePositiveRate,
    double NotifiedFalsePositiveRate,
    double Recall,
    double RespondedRecall,
    double Precision,
    IReadOnlyDictionary<string, int> FalsePositivesByDetector,
    IReadOnlyList<KindReport> Kinds,
    double ElapsedSeconds);

/// <summary>
/// The replay harness (ADR-0006): every event of every scenario, in event-time order, straight
/// through the real Core detectors and policy evaluator, with in-memory state. Each scenario
/// gets fresh state (its own user), so instances can't influence each other.
/// <para>
/// It also plays the Worker's other parts: an anomaly is decided once, when its dedupe key is
/// first seen, and D3's reading baseline is folded hourly from the replayed reads exactly as
/// <c>UserBaselineStore</c> does it (complete minutes, outliers capped).
/// </para>
/// </summary>
public static class ReplayHarness
{
    public static IReadOnlyList<IDetector> Detectors() =>
        [new TorExitDetector(), new ImpossibleTravelDetector(), new ScrapingDetector(), new NewDeviceExportDetector(), new SessionHijackDetector()];

    /// <summary>The evaluated org: default policy, plus its corporate VPN's egress networks trusted.</summary>
    public static SecurityPolicy DefaultPolicy { get; } = SecurityPolicy.Default with { TrustedNetworks = Places.VpnNetworks };

    public static async Task<ScenarioResult> RunAsync(Scenario scenario, SecurityPolicy policy, ITorExitList tor, CancellationToken ct)
    {
        var baselines = new InMemoryBaselines();
        var learner = new BaselineLearner(baselines, scenario.UserId, ScrapingSettings.Default.For(policy.For(DetectorIds.Scraping)));
        var context = new DetectionContext(new InMemoryDetectorState(), tor, policy, baselines);
        var anomalies = new Dictionary<string, (string Detector, DecisionOutcome Outcome)>();

        foreach (var evt in scenario.Events.OrderBy(e => e.OccurredAt))
        {
            learner.Observe(evt);
            foreach (var detector in Detectors())
            {
                if (policy.For(detector.Id).Mode == DetectorMode.Off) continue;
                foreach (var signal in await detector.EvaluateAsync(evt, context, ct))
                {
                    if (anomalies.ContainsKey(signal.DedupeKey)) continue;   // decided once, at creation
                    anomalies[signal.DedupeKey] = (signal.Detector, PolicyEvaluator.Decide(signal, policy, []).Outcome);
                }
            }
        }

        return new ScenarioResult(scenario, [.. anomalies.Values]);
    }

    public static async Task<EvaluationReport> EvaluateAsync(int seed, int benign, int malicious, SecurityPolicy policy, CancellationToken ct,
        Action<ScenarioResult>? onResult = null)
    {
        var stopwatch = Stopwatch.StartNew();
        var tor = new StaticTorExitList(Places.TorExits());
        var results = new List<ScenarioResult>();
        long events = 0;
        foreach (var scenario in new DatasetGenerator(seed).Generate(benign, malicious))
        {
            var result = await RunAsync(scenario, policy, tor, ct);
            events += scenario.Events.Count;
            onResult?.Invoke(result);
            // Keep the verdicts, not the millions of events.
            results.Add(result with { Scenario = scenario with { Events = [] } });
        }

        var benignResults = results.Where(r => r.Scenario.Label == Label.Benign).ToList();
        var maliciousResults = results.Where(r => r.Scenario.Label == Label.Malicious).ToList();
        var responded = results.Count(r => r.Responded);

        var kinds = results.GroupBy(r => r.Scenario.Kind).Select(g => new KindReport(
            g.Key, g.First().Scenario.Label, g.Count(), g.Count(r => r.Responded), g.Count(r => r.Notified), g.Count(r => r.Caught),
            g.Count(r => r.CaughtAndResponded),
            g.SelectMany(r => r.Anomalies.Where(a => a.Outcome == DecisionOutcome.Responded).Select(a => a.Detector).Distinct())
                .GroupBy(d => d).ToDictionary(d => d.Key, d => d.Count()))).ToList();

        return new EvaluationReport(
            seed,
            benignResults.Count,
            maliciousResults.Count,
            events,
            Ratio(benignResults.Count(r => r.Responded), benignResults.Count),
            Ratio(benignResults.Count(r => r.Notified), benignResults.Count),
            Ratio(maliciousResults.Count(r => r.Caught), maliciousResults.Count),
            Ratio(maliciousResults.Count(r => r.CaughtAndResponded), maliciousResults.Count),
            // Of the instances we acted on (responded), how many were real attacks.
            Ratio(maliciousResults.Count(r => r.Responded), responded),
            benignResults.SelectMany(r => r.Anomalies.Where(a => a.Outcome == DecisionOutcome.Responded).Select(a => a.Detector).Distinct())
                .GroupBy(d => d).ToDictionary(g => g.Key, g => g.Count()),
            kinds,
            stopwatch.Elapsed.TotalSeconds);
    }

    private static double Ratio(int part, int whole) => whole == 0 ? 0 : (double)part / whole;
}

/// <summary>
/// Folds a user's replayed reads into their D3 baseline every event-time hour, the way the
/// Worker's <c>BaselineUpdater</c> does: complete minutes only, each minute capped at the current
/// threshold before it's learnt.
/// </summary>
public sealed class BaselineLearner(InMemoryBaselines baselines, Guid userId, ScrapingSettings settings)
{
    private readonly SortedDictionary<DateTimeOffset, long> pending = [];
    private DateTimeOffset? lastFold;

    public void Observe(ActivityEvent evt)
    {
        var hour = new DateTimeOffset(evt.OccurredAt.UtcTicks - evt.OccurredAt.UtcTicks % TimeSpan.TicksPerHour, TimeSpan.Zero);
        if (lastFold is null) lastFold = hour;
        if (hour > lastFold) Fold(hour);

        if (!ScrapingDetector.IsRead(evt.Type)) return;
        var minute = new DateTimeOffset(evt.OccurredAt.UtcTicks - evt.OccurredAt.UtcTicks % TimeSpan.TicksPerMinute, TimeSpan.Zero);
        pending[minute] = pending.GetValueOrDefault(minute) + 1;
    }

    private void Fold(DateTimeOffset through)
    {
        var baseline = baselines.Baselines.GetValueOrDefault(userId);
        foreach (var minute in pending.Keys.Where(m => m < through).ToList())
        {
            baseline = Ewma.Update(baseline, pending[minute], cap: settings.ThresholdFor(baseline));
            pending.Remove(minute);
        }

        if (baseline is not null) baselines.Baselines[userId] = baseline;
        lastFold = through;
    }
}
