using System.Collections.Concurrent;
using ThreatLock.Core.Response;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>
/// The job queue itself (SPEC §10.1): claiming under concurrency, leases, backoff and dead jobs.
/// Each test has its own database, so the shared Worker never claims these jobs.
/// </summary>
public class ResponseJobQueueTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task The_job_is_created_with_the_anomaly_and_only_once()
    {
        await using var h = await ResponseHarness.CreateAsync(containers);
        var (org, users) = await h.SeedOrgAsync(["owner"]);

        var first = await h.RespondedAnomalyAsync(org, users[0]);

        Assert.NotNull(first.JobId);
        Assert.Equal(1L, await h.ScalarAsync<long>("SELECT count(*) FROM response_jobs WHERE anomaly_id = $1", first.Id));
        Assert.Equal(h.Clock.GetUtcNow(), await h.ScalarAsync<DateTimeOffset>("SELECT cutoff FROM response_jobs WHERE id = $1", first.JobId!.Value));
    }

    [Fact]
    public async Task Concurrent_claimers_never_get_the_same_job()
    {
        await using var h = await ResponseHarness.CreateAsync(containers);
        var (org, users) = await h.SeedOrgAsync(["owner"]);
        for (var i = 0; i < 30; i++) await h.RespondedAnomalyAsync(org, users[0], JobActions.Notify);

        // Six "Workers" drain the queue at once. SKIP LOCKED makes each skip rows the others
        // hold, so every job is claimed exactly once and nobody waits.
        var claimed = new ConcurrentBag<Guid>();
        await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Task.Run(async () =>
        {
            while (await h.Jobs.ClaimAsync(Ct) is { } job)
            {
                claimed.Add(job.Id);
                await h.Jobs.CompleteAsync(job, Ct);
            }
        }, Ct)));

        Assert.Equal(30, claimed.Count);
        Assert.Equal(30, claimed.Distinct().Count());
    }

    [Fact]
    public async Task A_crashed_workers_job_is_reclaimed_when_its_lease_expires()
    {
        await using var h = await ResponseHarness.CreateAsync(containers);
        var (org, users) = await h.SeedOrgAsync(["owner"]);
        var anomaly = await h.RespondedAnomalyAsync(org, users[0]);

        var first = await h.Jobs.ClaimAsync(Ct);
        // ...and the Worker dies without completing or failing it.

        h.Clock.Advance(TimeSpan.FromSeconds(59));
        Assert.Null(await h.Jobs.ClaimAsync(Ct));   // still leased to the dead Worker

        h.Clock.Advance(TimeSpan.FromSeconds(2));
        var second = await h.Jobs.ClaimAsync(Ct);

        Assert.Equal(anomaly.JobId, first!.Id);
        Assert.Equal((first.Id, 2), (second!.Id, second.Attempts));
    }

    [Fact]
    public async Task Failures_back_off_and_the_fifth_makes_the_job_dead()
    {
        await using var h = await ResponseHarness.CreateAsync(containers);
        var (org, users) = await h.SeedOrgAsync(["owner"]);
        var anomaly = await h.RespondedAnomalyAsync(org, users[0]);

        var job = await h.Jobs.ClaimAsync(Ct);
        Assert.Equal(JobStatuses.Pending, await h.Jobs.FailAsync(job!, new InvalidOperationException("redis down"), Ct));
        Assert.Null(await h.Jobs.ClaimAsync(Ct));   // backing off: 2 s (+ up to 20 %)

        h.Clock.Advance(TimeSpan.FromSeconds(2.5));
        for (var attempt = 2; attempt <= ResponseBackoff.MaxAttempts; attempt++)
        {
            job = await h.Jobs.ClaimAsync(Ct);
            Assert.Equal(attempt, job!.Attempts);
            var status = await h.Jobs.FailAsync(job, new InvalidOperationException("redis down"), Ct);
            Assert.Equal(attempt == ResponseBackoff.MaxAttempts ? JobStatuses.Dead : JobStatuses.Pending, status);
            h.Clock.Advance(TimeSpan.FromSeconds(75));   // past the longest backoff (60 s + 20 %)
        }

        Assert.Null(await h.Jobs.ClaimAsync(Ct));   // dead jobs wait for an admin
        Assert.Equal("InvalidOperationException: redis down",
            await h.ScalarAsync<string>("SELECT last_error FROM response_jobs WHERE id = $1", anomaly.JobId!.Value));
    }
}
