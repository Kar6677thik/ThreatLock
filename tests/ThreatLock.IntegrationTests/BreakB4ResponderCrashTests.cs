using ThreatLock.Core.Identity;
using ThreatLock.Infrastructure.Response;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>
/// Break B4 (SPEC §15): 100 response jobs, each one "crashing" the Worker once at a different
/// step, then being retried after its lease expires. Counts the notifications admins end up with.
/// </summary>
public class BreakB4ResponderCrashTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public const int Crashes = 100;

    /// <param name="StaleCache">Sessions revoked in PostgreSQL whose Redis entry still says "active".</param>
    public sealed record Outcome(int Anomalies, long Notifications, long Expected, long Duplicates, int StaleCache);

    /// <summary>
    /// Three admins: the owner, a plain admin, and one person who is both admin and security admin.
    /// Every anomaly should reach each of them exactly once: 3 notifications.
    /// </summary>
    public static async Task<Outcome> RunAsync(ResponseHarness h)
    {
        var (org, users) = await h.SeedOrgAsync([Roles.Owner], [Roles.Admin], [Roles.Admin, Roles.SecurityAdmin], []);
        var victim = users[3];
        ResponseStep[] steps = [ResponseStep.Revoked, ResponseStep.CacheMarked, ResponseStep.Notified];
        var sessions = new List<Guid>();

        for (var i = 0; i < Crashes; i++)
        {
            sessions.Add(await h.AddSessionAsync(org, victim, cachedActive: true));
            await h.RespondedAnomalyAsync(org, victim);

            h.Faults.CrashOnceAfter(steps[i % steps.Length]);
            var job = await h.Jobs.ClaimAsync(Ct);
            await Assert.ThrowsAsync<SimulatedCrashException>(() => h.Executor.ExecuteAsync(job!, Ct));

            // Killed, not failed: nothing records the crash. The lease runs out and the job is retried.
            h.Clock.Advance(TimeSpan.FromSeconds(61));
            var retry = await h.Jobs.ClaimAsync(Ct);
            Assert.Equal(job!.Id, retry!.Id);
            await h.Executor.ExecuteAsync(retry, Ct);
        }

        var notifications = await h.ScalarAsync<long>("SELECT count(*) FROM notifications WHERE org_id = $1", org);
        var distinct = await h.ScalarAsync<long>(
            "SELECT count(*) FROM (SELECT DISTINCT anomaly_id, recipient_user_id FROM notifications WHERE org_id = $1) d", org);
        var stale = 0;
        foreach (var sid in sessions)
        {
            if (await h.Redis.StringGetAsync($"tl:sess:{sid}") == "a") stale++;
        }

        return new Outcome(Crashes, notifications, Crashes * 3, notifications - distinct, stale);
    }

    /// <summary>scripts/experiments/b4-responder-crashes.sh sets B4_REPORT to collect the numbers.</summary>
    internal static async Task ReportAsync(string variant, Outcome outcome)
    {
        var path = Environment.GetEnvironmentVariable("B4_REPORT");
        if (!string.IsNullOrEmpty(path)) await File.AppendAllTextAsync(path, $"{variant}: {outcome}{Environment.NewLine}", Ct);
    }

    [Fact]
    public async Task Break_the_naive_responder_duplicates_notifications_after_a_crash()
    {
        await using var h = await ResponseHarness.CreateAsync(containers);

        var outcome = await RunAsync(h);
        await ReportAsync("naive", outcome);

        Assert.True(outcome.Notifications > outcome.Expected, $"expected duplicates, got {outcome}");
        Assert.True(outcome.Duplicates > 0);
        Assert.True(outcome.StaleCache > 0, "a crash between the revoke and the Redis write should leave a stale 'active'");
    }
}
