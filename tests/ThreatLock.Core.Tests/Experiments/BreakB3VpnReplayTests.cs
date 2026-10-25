using ThreatLock.Core.Detection;
using ThreatLock.Core.Events;
using ThreatLock.Core.Geo;
using ThreatLock.Core.Policy;

namespace ThreatLock.Core.Tests.Experiments;

/// <summary>
/// Break B3 (SPEC §15) as a replay (ADR-0006): labelled scenarios fed straight into the real D2
/// detector and policy evaluator, with event times spanning a working day. No HTTP, no waiting.
/// <list type="bullet">
/// <item>Benign: employees on a corporate VPN whose egress flips between Bangalore and Frankfurt
/// exits, minutes apart. To GeoIP that's "impossible travel".</item>
/// <item>Malicious: a stolen session used from London minutes after the victim's VPN activity.</item>
/// </list>
/// Three policies: D2 respond without trusted networks (the break), with the VPN's CIDRs trusted
/// (the fix), and the shipped default (D2 notify) with the fix.
/// </summary>
public class BreakB3VpnReplayTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public const int BenignUsers = 500;
    public const int Attacks = 100;
    public const int Seed = 42;

    private const string BangaloreVpn = "198.18.10.0/24";
    private const string FrankfurtVpn = "198.18.20.0/24";

    private static readonly GeoInfo Bangalore = new("IN", "Bengaluru", 12.9716, 77.5946, 50);
    private static readonly GeoInfo Frankfurt = new("DE", "Frankfurt", 50.1109, 8.6821, 50);
    private static readonly GeoInfo London = new("GB", "London", 51.5074, -0.1278, 50);

    private static readonly DateTimeOffset Day = new(2026, 10, 20, 3, 30, 0, TimeSpan.Zero);   // 09:00 in Bangalore

    private sealed record Scenario(Guid UserId, bool Malicious, List<ActivityEvent> Events);

    public sealed record Outcome(string Policy, double FalsePositiveRate, double NotifiedFalsePositiveRate, double Recall, int BenignResponded, int BenignNotified, int AttacksCaught);

    private static ActivityEvent Event(Guid user, DateTimeOffset at, string ip, GeoInfo geo) =>
        new(Guid.CreateVersion7(), Guid.Empty, user, Guid.NewGuid(), EventTypes.NoteRead, at, ip, geo, "device", "Chrome", null, null);

    /// <summary>The same seed always gives the same dataset, so before and after are compared on identical traffic.</summary>
    private static List<Scenario> Dataset()
    {
        var random = new Random(Seed);
        string Vpn(int site) => $"198.18.{(site == 0 ? 10 : 20)}.{random.Next(1, 255)}";
        var scenarios = new List<Scenario>();

        for (var u = 0; u < BenignUsers; u++)
        {
            var user = Guid.NewGuid();
            var events = new List<ActivityEvent>();
            var at = Day.AddMinutes(random.Next(0, 120));
            var site = random.Next(2);
            for (var i = 0; i < 20; i++)
            {
                if (random.NextDouble() < 0.3) site = 1 - site;   // the VPN picked another exit
                events.Add(Event(user, at, Vpn(site), site == 0 ? Bangalore : Frankfurt));
                at = at.AddMinutes(random.Next(2, 31));
            }

            scenarios.Add(new Scenario(user, false, events));
        }

        for (var a = 0; a < Attacks; a++)
        {
            var user = Guid.NewGuid();
            var at = Day.AddMinutes(random.Next(0, 240));
            var events = new List<ActivityEvent>
            {
                Event(user, at, Vpn(0), Bangalore),
                // The thief, on a residential connection in London, minutes later.
                Event(user, at.AddMinutes(random.Next(5, 61)), $"203.0.113.{random.Next(1, 255)}", London),
            };
            scenarios.Add(new Scenario(user, true, events));
        }

        return scenarios;
    }

    private static SecurityPolicy With(DetectorMode travelMode, params string[] trusted) => SecurityPolicy.Default with
    {
        TrustedNetworks = trusted,
        Detectors = new(SecurityPolicy.Default.Detectors)
        {
            [DetectorIds.ImpossibleTravel] = SecurityPolicy.Default.For(DetectorIds.ImpossibleTravel) with { Mode = travelMode },
        },
    };

    /// <summary>Replays every scenario under one policy; each anomaly is decided once, at creation, as in the Worker.</summary>
    public static async Task<Outcome> RunAsync(string name, SecurityPolicy policy)
    {
        var detector = new ImpossibleTravelDetector();
        int benignResponded = 0, benignNotified = 0, caught = 0;
        var scenarios = Dataset();

        foreach (var scenario in scenarios)
        {
            var context = new DetectionContext(new InMemoryDetectorState(), new StaticTorExitList([]), policy);
            var anomalies = new Dictionary<string, Decision>();
            foreach (var evt in scenario.Events)
            {
                foreach (var signal in await detector.EvaluateAsync(evt, context, Ct))
                {
                    anomalies.TryAdd(signal.DedupeKey, PolicyEvaluator.Decide(signal, policy, []));
                }
            }

            var responded = anomalies.Values.Any(d => d.Outcome == DecisionOutcome.Responded);
            var notified = anomalies.Values.Any(d => d.Outcome == DecisionOutcome.Notified);
            if (scenario.Malicious) caught += responded || notified ? 1 : 0;
            else
            {
                benignResponded += responded ? 1 : 0;
                benignNotified += notified ? 1 : 0;
            }
        }

        return new Outcome(name, (double)benignResponded / BenignUsers, (double)benignNotified / BenignUsers, (double)caught / Attacks,
            benignResponded, benignNotified, caught);
    }

    private static async Task ReportAsync(Outcome outcome)
    {
        var path = Environment.GetEnvironmentVariable("B3_REPORT");
        if (!string.IsNullOrEmpty(path)) await File.AppendAllTextAsync(path, $"{outcome}{Environment.NewLine}", Ct);
    }

    [Fact]
    public async Task Break_vpn_users_are_signed_out_when_travel_responds_without_trusted_networks()
    {
        var outcome = await RunAsync("break: D2 respond, no trusted networks", With(DetectorMode.Respond));
        await ReportAsync(outcome);

        Assert.True(outcome.FalsePositiveRate > 0.9, outcome.ToString());
        Assert.Equal(1.0, outcome.Recall);

        // The shipped default (notify) without the fix: nobody is signed out, but admins are told
        // about almost every VPN user. Alert fatigue is a cost too (SPEC §16.1 reports it separately).
        var notifyOnly = await RunAsync("default: D2 notify, no trusted networks", With(DetectorMode.Notify));
        await ReportAsync(notifyOnly);
        Assert.Equal(0.0, notifyOnly.FalsePositiveRate);
        Assert.True(notifyOnly.NotifiedFalsePositiveRate > 0.9);
    }

    [Fact]
    public async Task Prove_trusting_the_vpn_egress_removes_the_false_positives_and_keeps_every_attack()
    {
        var fixedPolicy = await RunAsync("prove: D2 respond, VPN CIDRs trusted", With(DetectorMode.Respond, BangaloreVpn, FrankfurtVpn));
        var shipped = await RunAsync("shipped default: D2 notify, VPN CIDRs trusted", With(DetectorMode.Notify, BangaloreVpn, FrankfurtVpn));
        await ReportAsync(fixedPolicy);
        await ReportAsync(shipped);

        Assert.Equal((0.0, 1.0), (fixedPolicy.FalsePositiveRate, fixedPolicy.Recall));
        Assert.Equal((0.0, 0.0, 1.0), (shipped.FalsePositiveRate, shipped.NotifiedFalsePositiveRate, shipped.Recall));
    }
}
