using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using ThreatLock.Simulator.Evaluation;

namespace ThreatLock.Simulator;

/// <summary>
/// The live harness (SPEC §16.2, ADR-0006): real attacks over HTTP against a running stack, and
/// the client-observed time to revoke: from sending the malicious request (t0) to the first
/// <c>401</c> on the stolen token (t1), polling <c>GET /api/me</c> every 50 ms.
/// <para>
/// Attacks run one after another, each against a fresh user, so they don't queue behind each
/// other. For each one the admin API is read afterwards for the server-side stages: detected,
/// job created, sessions revoked.
/// </para>
/// Uses the keyed simulation header (ADR-0007), so the target must have <c>Simulation:Enabled</c>.
/// Point it only at your own instance.
/// </summary>
public static class LiveHarness
{
    private const string Password = "correct horse battery staple";
    private const string IndiaIp = "49.207.48.1";
    private const string UkIp = "81.2.69.142";
    private static readonly TimeSpan Poll = TimeSpan.FromMilliseconds(50);
    private static readonly TimeSpan GiveUp = TimeSpan.FromSeconds(30);

    public sealed record Attack(int Index, string Kind, double? RevokeMs, double? DetectedMs, double? JobCreatedMs, double? RevokedMs, int ServedBeforeRevoke);

    public sealed record Stats(int Count, int Revoked, double P50, double P95, double P99, double Max, double Mean);

    public sealed record LiveReport(string BaseUrl, string Kind, int Attacks, Stats ClientObserved, Stats? Detected, Stats? Revoked,
        DateTimeOffset StartedAt, double ElapsedSeconds, IReadOnlyList<Attack> Results);

    private sealed record Login(string AccessToken, Me User);

    private sealed record Me(Guid Id, string Email, Guid OrgId);

    private sealed record AnomalyRow(Guid Id, Guid UserId, string Detector, DateTimeOffset DetectedAt);

    private sealed record AnomalyDetail(Guid Id, DateTimeOffset DetectedAt, JobView? Response);

    private sealed record JobView(DateTimeOffset CreatedAt, DateTimeOffset? RevokedAt, DateTimeOffset? FinishedAt);

    public static async Task<int> RunAsync(Options options, CancellationToken ct)
    {
        var baseUrl = new Uri(options.Require("base-url"));
        var simKey = options.Require("sim-key");
        var kind = options.Get("kind") ?? "tor";
        var attacks = options.Number("attacks", 200);
        if (kind is not ("tor" or "hijack")) throw new ArgumentException("--kind must be tor or hijack.");

        using var http = new HttpClient { BaseAddress = baseUrl, Timeout = TimeSpan.FromSeconds(30) };
        var torIp = kind == "tor" ? options.Get("tor-ip") ?? await FirstTorExitAsync(ct) : null;

        var run = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        var owner = await SendAsync<Login>(http, HttpMethod.Post, "/api/auth/register-org", null, simKey, IndiaIp, "owner-device-" + run, DatasetGenerator.Chrome,
            new { orgName = $"Live {kind} {run}", orgSlug = $"live-{kind}-{run}", displayName = "Owner", email = $"owner-{run}@live.test", password = Password }, ct);

        var startedAt = DateTimeOffset.UtcNow;
        var total = Stopwatch.StartNew();
        var results = new List<Attack>();
        for (var i = 1; i <= attacks; i++)
        {
            var attack = kind == "tor"
                ? await TorAttackAsync(http, owner, simKey, torIp!, run, i, ct)
                : await HijackAttackAsync(http, owner, simKey, run, i, ct);
            results.Add(attack);
            if (i % 20 == 0 || i == attacks) Console.WriteLine($"{i}/{attacks}: last {attack.RevokeMs?.ToString("F0", CultureInfo.InvariantCulture) ?? "not revoked"} ms");
        }

        var report = new LiveReport(baseUrl.ToString(), kind, attacks, StatsOf(results.Select(r => r.RevokeMs), attacks),
            StatsOrNull(results.Select(r => r.DetectedMs), attacks), StatsOrNull(results.Select(r => r.RevokedMs), attacks),
            startedAt, total.Elapsed.TotalSeconds, results);

        Console.WriteLine();
        Console.WriteLine(Markdown(report));
        if (options.Get("out") is { } path)
        {
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(report, Commands.IndentedJson), ct);
        }

        return 0;
    }

    /// <summary>D1: a fresh user's password is used from a Tor exit. t0 = sending that login.</summary>
    private static async Task<Attack> TorAttackAsync(HttpClient http, Login owner, string simKey, string torIp, string run, int i, CancellationToken ct)
    {
        var email = $"tor-{i}-{run}@live.test";
        await CreateUserAsync(http, owner, email, $"Tor victim {i}", ct);

        var t0 = DateTimeOffset.UtcNow;
        var clock = Stopwatch.StartNew();
        var stolen = await SendAsync<Login>(http, HttpMethod.Post, "/api/auth/login", null, simKey, torIp, $"tor-device-{run}", DatasetGenerator.Firefox,
            new { email, password = Password }, ct);
        var (revokeMs, served) = await PollUntilRevokedAsync(http, stolen.AccessToken, simKey, torIp, $"tor-device-{run}", DatasetGenerator.Firefox, clock, ct);
        var (detected, job, revoked) = await StagesAsync(http, owner, stolen.User.Id, "tor", t0, ct);
        return new Attack(i, "tor", revokeMs, detected, job, revoked, served);
    }

    /// <summary>D5: a victim's live token is replayed from the UK on another machine. t0 = the thief's first request.</summary>
    private static async Task<Attack> HijackAttackAsync(HttpClient http, Login owner, string simKey, string run, int i, CancellationToken ct)
    {
        var email = $"hijack-{i}-{run}@live.test";
        await CreateUserAsync(http, owner, email, $"Hijack victim {i}", ct);
        var device = $"victim-{i}-{run}";
        var victim = await SendAsync<Login>(http, HttpMethod.Post, "/api/auth/login", null, simKey, IndiaIp, device, DatasetGenerator.Chrome,
            new { email, password = Password }, ct);
        await SendAsync<JsonElement>(http, HttpMethod.Get, "/api/notes", victim.AccessToken, simKey, IndiaIp, device, DatasetGenerator.Chrome, null, ct);

        var thief = $"thief-{run}";
        var t0 = DateTimeOffset.UtcNow;
        var clock = Stopwatch.StartNew();
        await SendRawAsync(http, HttpMethod.Get, "/api/notes", victim.AccessToken, simKey, UkIp, thief, DatasetGenerator.Firefox, null, ct);
        var (revokeMs, served) = await PollUntilRevokedAsync(http, victim.AccessToken, simKey, UkIp, thief, DatasetGenerator.Firefox, clock, ct);
        var (detected, job, revoked) = await StagesAsync(http, owner, victim.User.Id, "session_hijack", t0, ct);
        return new Attack(i, "hijack", revokeMs, detected, job, revoked, served + 1);
    }

    private static async Task<(double? Ms, int Served)> PollUntilRevokedAsync(HttpClient http, string token, string simKey, string ip, string device,
        string agent, Stopwatch clock, CancellationToken ct)
    {
        var served = 0;
        while (clock.Elapsed < GiveUp)
        {
            using var response = await SendRawAsync(http, HttpMethod.Get, "/api/me", token, simKey, ip, device, agent, null, ct);
            if (response.StatusCode == HttpStatusCode.Unauthorized) return (clock.Elapsed.TotalMilliseconds, served);
            served++;
            await Task.Delay(Poll, ct);
        }

        return (null, served);
    }

    /// <summary>Server-side stages from the admin API, relative to the client's t0 (same machine, same clock).</summary>
    private static async Task<(double? Detected, double? Job, double? Revoked)> StagesAsync(HttpClient http, Login owner, Guid userId, string detector,
        DateTimeOffset t0, CancellationToken ct)
    {
        var list = await SendAsync<List<AnomalyRow>>(http, HttpMethod.Get, $"/api/admin/anomalies?detector={detector}&limit=50", owner.AccessToken,
            null, null, null, null, null, ct);
        var row = list.FirstOrDefault(a => a.UserId == userId);
        if (row is null) return (null, null, null);
        var detail = await SendAsync<AnomalyDetail>(http, HttpMethod.Get, $"/api/admin/anomalies/{row.Id}", owner.AccessToken, null, null, null, null, null, ct);
        double Ms(DateTimeOffset? at) => at is { } value ? (value - t0).TotalMilliseconds : double.NaN;
        return (Ms(detail.DetectedAt), Ms(detail.Response?.CreatedAt), Ms(detail.Response?.RevokedAt));
    }

    private static async Task CreateUserAsync(HttpClient http, Login owner, string email, string name, CancellationToken ct) =>
        await SendAsync<JsonElement>(http, HttpMethod.Post, "/api/admin/users", owner.AccessToken, null, null, null, null,
            new { email, displayName = name, password = Password }, ct);

    private static async Task<T> SendAsync<T>(HttpClient http, HttpMethod method, string path, string? token, string? simKey, string? ip,
        string? device, string? agent, object? body, CancellationToken ct)
    {
        using var response = await SendRawAsync(http, method, path, token, simKey, ip, device, agent, body, ct);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"{method} {path} → {(int)response.StatusCode}: {await response.Content.ReadAsStringAsync(ct)}");
        }

        return (await response.Content.ReadFromJsonAsync<T>(Commands.Json, ct))!;
    }

    private static async Task<HttpResponseMessage> SendRawAsync(HttpClient http, HttpMethod method, string path, string? token, string? simKey,
        string? ip, string? device, string? agent, object? body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, path);
        if (token is not null) request.Headers.Authorization = new("Bearer", token);
        if (simKey is not null && ip is not null)
        {
            request.Headers.Add("X-Simulator-Key", simKey);
            request.Headers.Add("X-Simulated-Client-Ip", ip);
        }

        if (device is not null) request.Headers.Add("X-Device-Id", device);
        if (agent is not null) request.Headers.UserAgent.ParseAdd(agent);
        if (body is not null) request.Content = JsonContent.Create(body);
        return await http.SendAsync(request, ct);
    }

    private static async Task<string> FirstTorExitAsync(CancellationToken ct)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        var list = await http.GetStringAsync(new Uri("https://check.torproject.org/torbulkexitlist"), ct);
        return list.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).First(l => !l.StartsWith('#'));
    }

    public static Stats StatsOf(IEnumerable<double?> values, int count)
    {
        var sorted = values.OfType<double>().Where(v => !double.IsNaN(v)).Order().ToArray();
        if (sorted.Length == 0) return new Stats(count, 0, double.NaN, double.NaN, double.NaN, double.NaN, double.NaN);
        return new Stats(count, sorted.Length, Percentile(sorted, 0.50), Percentile(sorted, 0.95), Percentile(sorted, 0.99), sorted[^1], sorted.Average());
    }

    private static Stats? StatsOrNull(IEnumerable<double?> values, int count) => StatsOf(values, count) is { Revoked: > 0 } s ? s : null;

    /// <summary>Nearest-rank percentile: the value at or below which <paramref name="q"/> of the measurements fall (concepts.md §6.1).</summary>
    public static double Percentile(double[] sorted, double q) => sorted[Math.Clamp((int)Math.Ceiling(q * sorted.Length) - 1, 0, sorted.Length - 1)];

    private static string Markdown(LiveReport r)
    {
        static string Row(string name, Stats? s) => s is null
            ? $"| {name} | n/a | | | | | |"
            : string.Create(CultureInfo.InvariantCulture, $"| {name} | {s.Revoked}/{s.Count} | {s.P50:F0} | {s.P95:F0} | {s.P99:F0} | {s.Max:F0} | {s.Mean:F0} |");
        return string.Join(Environment.NewLine,
            $"{r.Attacks} {r.Kind} attacks against {r.BaseUrl} in {r.ElapsedSeconds:F0} s",
            "",
            "| Measured from t0 (ms) | n | p50 | p95 | p99 | max | mean |",
            "| --- | --- | --- | --- | --- | --- | --- |",
            Row("Anomaly detected (server)", r.Detected),
            Row("Sessions revoked (server)", r.Revoked),
            Row("**Client sees 401 (headline)**", r.ClientObserved));
    }
}
