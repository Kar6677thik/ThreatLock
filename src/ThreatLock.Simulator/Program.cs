using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using ThreatLock.Core;
using ThreatLock.Core.Policy;
using ThreatLock.Simulator;
using ThreatLock.Simulator.Evaluation;

// The Simulator CLI (SPEC §16, ADR-0006). Commands:
//   dataset       write the labelled dataset as JSONL (one scenario per line)
//   replay        offline evaluation: FP rate, recall, precision per detector
//   live          attacks over HTTP against a running stack: time to revoke
//   audit-verify  recompute an org's audit chain locally, independently of the server's verify
using var cancel = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };

var options = Options.Parse(args.Skip(1));
try
{
    return args.FirstOrDefault() switch
    {
        "dataset" => await Commands.DatasetAsync(options, cancel.Token),
        "replay" => await Commands.ReplayAsync(options, cancel.Token),
        "live" => await LiveHarness.RunAsync(options, cancel.Token),
        "audit-verify" => await AuditVerifier.RunAsync(options, cancel.Token),
        _ => Commands.Help(),
    };
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine(ex.Message);
    return 2;
}

namespace ThreatLock.Simulator
{
    /// <summary><c>--name value</c> pairs, nothing fancier.</summary>
    public sealed class Options(Dictionary<string, string> values)
    {
        public static Options Parse(IEnumerable<string> args)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            using var e = args.GetEnumerator();
            while (e.MoveNext())
            {
                if (!e.Current.StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException($"Unexpected argument '{e.Current}'.");
                var name = e.Current[2..];
                values[name] = e.MoveNext() ? e.Current : throw new ArgumentException($"--{name} needs a value.");
            }

            return new Options(values);
        }

        public string? Get(string name) => values.GetValueOrDefault(name);

        public string Require(string name) => Get(name) ?? throw new ArgumentException($"--{name} is required.");

        public int Number(string name, int fallback) =>
            Get(name) is { } value ? int.Parse(value, CultureInfo.InvariantCulture) : fallback;
    }

    public static class Commands
    {
        public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
        {
            WriteIndented = false,
            Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
        };

        public static readonly JsonSerializerOptions IndentedJson = new(Json) { WriteIndented = true };

        public static int Help()
        {
            Console.WriteLine($"{AppInfo.Name} Simulator {AppInfo.Version}");
            Console.WriteLine("""
                Usage:
                  dataset      --out artifacts/dataset.jsonl [--seed 42] [--benign 1000] [--malicious 200]
                  replay       [--seed 42] [--benign 1000] [--malicious 200] [--policy policy.json] [--out report.json]
                  live         --base-url http://127.0.0.1:5080 --sim-key KEY [--kind tor|hijack] [--attacks 200] [--out live.json]
                  audit-verify --base-url URL --email EMAIL --password PASSWORD [--anchor-seq N --anchor-hash HEX]
                """);
            return 1;
        }

        public static async Task<int> DatasetAsync(Options options, CancellationToken ct)
        {
            var path = options.Require("out");
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            await using var file = new StreamWriter(path);
            long events = 0, scenarios = 0;
            foreach (var scenario in new DatasetGenerator(options.Number("seed", 42)).Generate(options.Number("benign", 1000), options.Number("malicious", 200)))
            {
                await file.WriteLineAsync(JsonSerializer.Serialize(scenario, Json).AsMemory(), ct);
                events += scenario.Events.Count;
                scenarios++;
            }

            Console.WriteLine($"Wrote {scenarios} scenarios ({events:N0} events) to {path}");
            return 0;
        }

        public static async Task<int> ReplayAsync(Options options, CancellationToken ct)
        {
            var policy = options.Get("policy") is { } file
                ? JsonSerializer.Deserialize<SecurityPolicy>(await File.ReadAllTextAsync(file, ct), PolicyJsonOptions)!
                : ReplayHarness.DefaultPolicy;
            var errors = PolicyValidator.Validate(policy);
            if (errors.Count > 0) throw new ArgumentException("Invalid policy: " + string.Join("; ", errors.Select(e => $"{e.Key}: {string.Join(" ", e.Value)}")));

            var report = await ReplayHarness.EvaluateAsync(options.Number("seed", 42), options.Number("benign", 1000), options.Number("malicious", 200), policy, ct);
            Console.WriteLine(Markdown(report));
            if (options.Get("out") is { } outPath)
            {
                await File.WriteAllTextAsync(outPath, JsonSerializer.Serialize(report, IndentedJson), ct);
            }

            return 0;
        }

        /// <summary>Same format as the API's policy JSON (SPEC §9.1).</summary>
        public static readonly JsonSerializerOptions PolicyJsonOptions = new(JsonSerializerDefaults.Web)
        {
            Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower, allowIntegerValues: false) },
        };

        public static string Markdown(EvaluationReport r)
        {
            static string Pct(double v) => v.ToString("P1", CultureInfo.InvariantCulture);
            var lines = new List<string>
            {
                $"Seed {r.Seed}: {r.BenignInstances} benign + {r.MaliciousInstances} malicious instances, {r.Events:N0} events, replayed in {r.ElapsedSeconds:F1} s",
                "",
                "| Metric | Value |",
                "| --- | --- |",
                $"| False-positive rate (benign signed out) | {Pct(r.FalsePositiveRate)} |",
                $"| Notified false positives (benign, admins told) | {Pct(r.NotifiedFalsePositiveRate)} |",
                $"| Recall (malicious, expected detector notified or responded) | {Pct(r.Recall)} |",
                $"| Recall, responded only | {Pct(r.RespondedRecall)} |",
                $"| Precision (responded instances that were attacks) | {Pct(r.Precision)} |",
                $"| False positives by detector | {(r.FalsePositivesByDetector.Count == 0 ? "none" : string.Join(", ", r.FalsePositivesByDetector.Select(d => $"{d.Key} {d.Value}")))} |",
                "",
                "| Scenario | Label | Instances | Responded | Notified | Caught | Responded by |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            };
            lines.AddRange(r.Kinds.Select(k =>
                $"| {k.Kind} | {k.Label.ToString().ToLowerInvariant()} | {k.Instances} | {k.Responded} | {k.Notified} | " +
                $"{(k.Label == Label.Malicious ? k.Caught.ToString(CultureInfo.InvariantCulture) : "")} | " +
                $"{string.Join(", ", k.RespondedByDetector.Select(d => $"{d.Key} {d.Value}"))} |"));
            return string.Join(Environment.NewLine, lines);
        }
    }
}
