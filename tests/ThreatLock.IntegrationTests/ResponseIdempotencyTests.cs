using ThreatLock.Core.Identity;
using ThreatLock.Core.Response;
using ThreatLock.Infrastructure.Response;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>
/// Each response step is safe to repeat (SPEC §10.2, §17): crash after any step, rerun the job,
/// and the end state is exactly what one clean run produces.
/// </summary>
public class ResponseIdempotencyTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<ClaimedJob> ClaimAsync(ResponseHarness h) => (await h.Jobs.ClaimAsync(Ct))!;

    /// <summary>Runs the job, crashing once after <paramref name="crashAfter"/>, then retries it after the lease.</summary>
    private static async Task RunWithCrashAsync(ResponseHarness h, ResponseStep? crashAfter)
    {
        var job = await ClaimAsync(h);
        if (crashAfter is { } step)
        {
            h.Faults.CrashOnceAfter(step);
            await Assert.ThrowsAsync<SimulatedCrashException>(() => h.Executor.ExecuteAsync(job, Ct));
            h.Clock.Advance(TimeSpan.FromSeconds(61));
            job = await ClaimAsync(h);
        }

        await h.Executor.ExecuteAsync(job, Ct);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(ResponseStep.Revoked)]
    [InlineData(ResponseStep.CacheMarked)]
    [InlineData(ResponseStep.Notified)]
    public async Task A_crash_after_any_step_ends_in_the_same_state_as_a_clean_run(ResponseStep? crashAfter)
    {
        await using var h = await ResponseHarness.CreateAsync(containers);
        var (org, users) = await h.SeedOrgAsync([Roles.Owner], [Roles.Admin, Roles.SecurityAdmin], []);
        var victim = users[2];
        var stolen = await h.AddSessionAsync(org, victim, cachedActive: true);
        var anomaly = await h.RespondedAnomalyAsync(org, victim);
        h.Clock.Advance(TimeSpan.FromSeconds(5));
        var fresh = await h.AddSessionAsync(org, victim);   // the real user signs in again after the detection

        await RunWithCrashAsync(h, crashAfter);

        Assert.True(await h.ScalarAsync<bool>("SELECT revoked_at IS NOT NULL FROM sessions WHERE id = $1", stolen));
        Assert.Equal("r", (string?)await h.Redis.StringGetAsync($"tl:sess:{stolen}"));
        Assert.False(await h.ScalarAsync<bool>("SELECT revoked_at IS NOT NULL FROM sessions WHERE id = $1", fresh));   // cutoff
        Assert.Equal(2L, await h.ScalarAsync<long>("SELECT count(*) FROM notifications WHERE anomaly_id = $1", anomaly.Id));
        Assert.Equal(JobStatuses.Succeeded, await h.ScalarAsync<string>("SELECT status FROM response_jobs WHERE id = $1", anomaly.JobId!.Value));
        Assert.NotNull(await h.ScalarAsync<DateTimeOffset?>("SELECT responded_at FROM anomalies WHERE id = $1", anomaly.Id));
    }

    [Fact]
    public async Task Two_workers_running_the_same_job_at_once_still_notify_once()
    {
        // A lease can expire while the first Worker is still busy (a long GC pause, a slow
        // network): then two Workers run one job concurrently. The step markers, read under
        // FOR UPDATE, make the second one skip what the first did.
        await using var h = await ResponseHarness.CreateAsync(containers);
        var (org, users) = await h.SeedOrgAsync([Roles.Owner], [Roles.Admin], []);
        await h.AddSessionAsync(org, users[2]);
        var anomaly = await h.RespondedAnomalyAsync(org, users[2]);

        var first = await ClaimAsync(h);
        h.Clock.Advance(TimeSpan.FromSeconds(61));
        var second = await ClaimAsync(h);
        await Task.WhenAll(h.Executor.ExecuteAsync(first, Ct), h.Executor.ExecuteAsync(second, Ct));

        Assert.Equal(2L, await h.ScalarAsync<long>("SELECT COALESCE(SUM(count), 0) FROM notifications WHERE org_id = $1", org));
        Assert.Equal(1L, await h.ScalarAsync<long>("SELECT count(*) FROM sessions WHERE revoked_by_anomaly_id = $1", anomaly.Id));
    }

    [Fact]
    public async Task Repeated_anomalies_about_one_user_are_grouped_until_read()
    {
        await using var h = await ResponseHarness.CreateAsync(containers);
        var (org, users) = await h.SeedOrgAsync([Roles.Owner], []);
        var (owner, victim) = (users[0], users[1]);

        await h.RespondedAnomalyAsync(org, victim, JobActions.Notify);
        await RunWithCrashAsync(h, null);
        h.Clock.Advance(TimeSpan.FromMinutes(10));
        var second = await h.RespondedAnomalyAsync(org, victim, JobActions.Notify);
        await RunWithCrashAsync(h, null);

        Assert.Equal(1L, await h.ScalarAsync<long>("SELECT count(*) FROM notifications WHERE recipient_user_id = $1", owner));
        Assert.Equal(2, await h.ScalarAsync<int>("SELECT count FROM notifications WHERE recipient_user_id = $1", owner));
        Assert.Equal(second.Id, await h.ScalarAsync<Guid>("SELECT last_anomaly_id FROM notifications WHERE recipient_user_id = $1", owner));

        // Once the admin has read it, the next anomaly opens a new entry.
        await using (var read = h.Db.CreateCommand("UPDATE notifications SET read_at = now() WHERE recipient_user_id = $1"))
        {
            read.Parameters.AddWithValue(owner);
            await read.ExecuteNonQueryAsync(Ct);
        }

        await h.RespondedAnomalyAsync(org, victim, JobActions.Notify);
        await RunWithCrashAsync(h, null);
        Assert.Equal(2L, await h.ScalarAsync<long>("SELECT count(*) FROM notifications WHERE recipient_user_id = $1", owner));
    }

    [Fact]
    public async Task Grouping_ends_after_an_hour()
    {
        await using var h = await ResponseHarness.CreateAsync(containers);
        var (org, users) = await h.SeedOrgAsync([Roles.Owner], []);

        await h.RespondedAnomalyAsync(org, users[1], JobActions.Notify);
        await RunWithCrashAsync(h, null);
        h.Clock.Advance(ResponseExecutor.GroupingWindow + TimeSpan.FromSeconds(1));
        await h.RespondedAnomalyAsync(org, users[1], JobActions.Notify);
        await RunWithCrashAsync(h, null);

        Assert.Equal(2L, await h.ScalarAsync<long>("SELECT count(*) FROM notifications WHERE recipient_user_id = $1", users[0]));
    }

    [Fact]
    public async Task Revoke_and_lock_closes_every_session_and_a_retry_after_unlock_does_not_relock()
    {
        await using var h = await ResponseHarness.CreateAsync(containers);
        var (org, users) = await h.SeedOrgAsync([Roles.Owner], []);
        var victim = users[1];
        var anomaly = await h.RespondedAnomalyAsync(org, victim, JobActions.RevokeAndLock);
        h.Clock.Advance(TimeSpan.FromSeconds(5));
        var afterDetection = await h.AddSessionAsync(org, victim);   // could be the attacker logging in again

        // Crash after notifying, then an admin unlocks before the retry runs.
        var job = await ClaimAsync(h);
        h.Faults.CrashOnceAfter(ResponseStep.Notified);
        await Assert.ThrowsAsync<SimulatedCrashException>(() => h.Executor.ExecuteAsync(job, Ct));
        Assert.Equal("tor", await h.ScalarAsync<string>("SELECT security_locked_reason FROM users WHERE id = $1", victim));
        Assert.True(await h.ScalarAsync<bool>("SELECT revoked_at IS NOT NULL FROM sessions WHERE id = $1", afterDetection));

        await using (var unlock = h.Db.CreateCommand("UPDATE users SET security_locked_at = NULL, security_locked_reason = NULL WHERE id = $1"))
        {
            unlock.Parameters.AddWithValue(victim);
            await unlock.ExecuteNonQueryAsync(Ct);
        }

        h.Clock.Advance(TimeSpan.FromSeconds(61));
        await h.Executor.ExecuteAsync(await ClaimAsync(h), Ct);

        Assert.Null(await h.ScalarAsync<DateTimeOffset?>("SELECT security_locked_at FROM users WHERE id = $1", victim));
        Assert.Equal(JobStatuses.Succeeded, await h.ScalarAsync<string>("SELECT status FROM response_jobs WHERE id = $1", anomaly.JobId!.Value));
    }
}
