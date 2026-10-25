using ThreatLock.Core.Detection;
using ThreatLock.Core.Policy;
using ThreatLock.Simulator;
using ThreatLock.Simulator.Evaluation;

namespace ThreatLock.Simulator.Tests;

/// <summary>
/// The CI-sized evaluation (SPEC §17): every scenario kind, replayed through the real detectors and
/// policy. Not a measurement (that's the full run in docs/experiments/Eval-*.md), a tripwire: a
/// change that misses an attack kind or starts signing out benign users fails here.
/// </summary>
public class EvaluationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    // 20 instances of each benign kind, 10 of each malicious kind.
    private static Task<EvaluationReport> SmallRunAsync(SecurityPolicy? policy = null, int seed = 7) =>
        ReplayHarness.EvaluateAsync(seed, ScenarioKinds.Benign.Count * 20, ScenarioKinds.Malicious.Count * 10, policy ?? ReplayHarness.DefaultPolicy, Ct);

    [Fact]
    public async Task Every_attack_kind_is_caught_and_responded_to()
    {
        var report = await SmallRunAsync();

        Assert.Equal(1.0, report.Recall);
        Assert.Equal(1.0, report.RespondedRecall);
        Assert.All(report.Kinds.Where(k => k.Label == Label.Malicious), k => Assert.Equal(k.Instances, k.Caught));
    }

    [Fact]
    public async Task Benign_users_are_left_alone_except_the_expected_migration_export()
    {
        var report = await SmallRunAsync();

        foreach (var kind in report.Kinds.Where(k => k.Label == Label.Benign && k.Kind != ScenarioKinds.NewLaptopExport))
        {
            // Allow one statistical tail per kind (a power user's burst above μ + 4σ), not more.
            Assert.True(kind.Responded <= 1, $"{kind.Kind}: {kind.Responded} of {kind.Instances} signed out");
        }

        // SPEC §16.1: the legitimate "new laptop, export after 5 minutes" is a known false positive.
        Assert.Equal(20, report.Kinds.Single(k => k.Kind == ScenarioKinds.NewLaptopExport).Responded);
    }

    [Fact]
    public async Task The_same_seed_gives_the_same_numbers()
    {
        var first = await SmallRunAsync(seed: 11);
        var second = await SmallRunAsync(seed: 11);

        Assert.Equal(first.Events, second.Events);
        Assert.Equal((first.FalsePositiveRate, first.Recall, first.Precision), (second.FalsePositiveRate, second.Recall, second.Precision));
    }

    [Fact]
    public async Task Without_trusting_the_vpn_and_with_travel_responding_vpn_users_are_signed_out()
    {
        // Break B3 inside the full dataset: the regression guard for "trusted networks still work".
        var policy = SecurityPolicy.Default with
        {
            Detectors = new(SecurityPolicy.Default.Detectors)
            {
                [DetectorIds.ImpossibleTravel] = SecurityPolicy.Default.For(DetectorIds.ImpossibleTravel) with { Mode = DetectorMode.Respond },
            },
        };

        var report = await SmallRunAsync(policy);

        Assert.True(report.Kinds.Single(k => k.Kind == ScenarioKinds.Vpn).Responded > 10);
    }

    [Theory]
    [InlineData(new[] { 1.0, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, 0.50, 5)]
    [InlineData(new[] { 1.0, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, 0.95, 10)]
    [InlineData(new[] { 42.0 }, 0.99, 42)]
    public void Percentiles_use_the_nearest_rank(double[] sorted, double q, double expected) =>
        Assert.Equal(expected, LiveHarness.Percentile(sorted, q));

    [Fact]
    public void Options_are_name_value_pairs()
    {
        var options = Options.Parse(["--seed", "9", "--out", "x.json"]);

        Assert.Equal((9, "x.json", 42), (options.Number("seed", 0), options.Require("out"), options.Number("benign", 42)));
        Assert.Throws<ArgumentException>(() => Options.Parse(["--seed"]));
        Assert.Throws<ArgumentException>(() => options.Require("missing"));
    }
}
