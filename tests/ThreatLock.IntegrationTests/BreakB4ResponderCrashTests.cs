using ThreatLock.Core.Identity;
using ThreatLock.Infrastructure.Response;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>
/// Break B4 (SPEC §15): 100 response jobs, each one "crashing" the Worker once at a different
/// step, then being retried after its lease expires. Counts what the admins end up with.
/// <para>
/// The Break half lives at the git tag <c>break/b4-naive-responder</c>, where the same run gave
/// 532 deliveries instead of 300 and 34 stale cache entries. This is the Prove half.
/// </para>
/// </summary>
public class BreakB4ResponderCrashTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public const int Crashes = 100;

    /// <param name="Deliveries">Anomalies delivered to inboxes, counting each grouped one (<c>SUM(count)</c>).</param>
    /// <param name="Rows">Inbox entries: fewer than deliveries, because repeats are grouped.</param>
    /// <param name="StaleCache">Sessions revoked in PostgreSQL whose Redis entry still says "active".</param>
    public sealed record Outcome(int Anomalies, long Deliveries, long Rows, long Expected, long Duplicates, int StaleCache);

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

        var deliveries = await h.ScalarAsync<long>("SELECT COALESCE(SUM(count), 0) FROM notifications WHERE org_id = $1", org);
        var rows = await h.ScalarAsync<long>("SELECT count(*) FROM notifications WHERE org_id = $1", org);
        var stale = 0;
        foreach (var sid in sessions)
        {
            if (await h.Redis.StringGetAsync($"tl:sess:{sid}") == "a") stale++;
        }

        return new Outcome(Crashes, deliveries, rows, Crashes * 3, deliveries - Crashes * 3, stale);
    }

    /// <summary>scripts/experiments/b4-responder-crashes.sh sets B4_REPORT to collect the numbers.</summary>
    internal static async Task ReportAsync(string variant, Outcome outcome)
    {
        var path = Environment.GetEnvironmentVariable("B4_REPORT");
        if (!string.IsNullOrEmpty(path)) await File.AppendAllTextAsync(path, $"{variant}: {outcome}{Environment.NewLine}", Ct);
    }

    [Fact]
    public async Task Prove_idempotent_steps_deliver_each_anomaly_once_per_person_despite_crashes()
    {
        await using var h = await ResponseHarness.CreateAsync(containers);

        var outcome = await RunAsync(h);
        await ReportAsync("idempotent", outcome);

        Assert.Equal((outcome.Expected, 0L, 0), (outcome.Deliveries, outcome.Duplicates, outcome.StaleCache));
        Assert.True(outcome.Rows < outcome.Deliveries, "repeats about one user within an hour should be grouped");
    }
}
