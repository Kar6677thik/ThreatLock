using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using StackExchange.Redis;
using ThreatLock.Core.Events;
using ThreatLock.Infrastructure.Detection;
using ThreatLock.Infrastructure.Events;
using ThreatLock.IntegrationTests.Infrastructure;
using ThreatLock.Worker.Events;

namespace ThreatLock.IntegrationTests;

/// <summary>
/// The failure modes of the event pipeline (SPEC §7.2–7.3, ADR-0003, concepts.md §2.2–2.4):
/// lost publishes, duplicate deliveries, crashed consumers, poison messages. Tests that need
/// special timing run their own Worker on their own stream, so they can't disturb other tests.
/// </summary>
public class StreamReliabilityTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>A real org and user (anomalies have an FK to orgs) and a Tor event for them.</summary>
    private async Task<ActivityEvent> TorEventAsync()
    {
        var owner = await containers.Api.RegisterOrgAsync();
        return new ActivityEvent(Guid.CreateVersion7(), owner.User.OrgId, owner.User.Id, Guid.NewGuid(), EventTypes.NoteRead,
            DateTimeOffset.UtcNow, TestGeoIpLookup.TorExitIp, null, null, null, null, new JsonObject());
    }

    private Task<long> AnomalyCountAsync(Guid orgId) =>
        containers.ScalarAsync<long>("SELECT count(*) FROM anomalies WHERE org_id = $1", orgId);

    private static async Task XAddAsync(IDatabase redis, string stream, ActivityEvent evt) =>
        await redis.StreamAddAsync(stream, [new("id", evt.Id.ToString()), new("event", EventJson.Serialize(evt))]);

    private static Dictionary<string, string?> OwnStream(string stream) => new()
    {
        ["Events:StreamName"] = stream,
        ["Events:MaxDeliveries"] = "2",
        ["Events:ClaimIdle"] = "00:00:00.300",
        ["Events:ClaimInterval"] = "00:00:00.100",
    };

    [Fact]
    public async Task Events_that_missed_the_stream_are_published_by_the_sweeper()
    {
        // The API can't reach Redis, so events are saved with published_at = null...
        await using var api = new ThreatLockApiFactory(containers.Postgres.GetConnectionString(), "127.0.0.1:1");
        var owner = await api.RegisterOrgAsync();
        await owner.Client.GetAsync("/api/notes", Ct);
        Assert.Equal(0, await containers.ScalarAsync<long>(
            "SELECT count(*) FROM activity_events WHERE user_id = $1 AND published_at IS NOT NULL", owner.User.Id));

        // ...and the Worker's sweeper (which can reach Redis) publishes them.
        await Eventually.TrueAsync(async () => await containers.ScalarAsync<long>(
            "SELECT count(*) FROM activity_events WHERE user_id = $1 AND published_at IS NULL", owner.User.Id) == 0,
            what: "sweeper to publish");
    }

    [Fact]
    public async Task A_duplicate_delivery_does_not_duplicate_the_anomaly()
    {
        var redis = await containers.RedisAsync();
        var evt = await TorEventAsync();

        await XAddAsync(redis, "tl:events", evt);
        await XAddAsync(redis, "tl:events", evt);   // at-least-once: the same event twice

        await Eventually.TrueAsync(async () => await AnomalyCountAsync(evt.OrgId) == 1, what: "anomaly");
        // Give the second copy time to be processed too, then check it was absorbed.
        var marker = await TorEventAsync();
        await XAddAsync(redis, "tl:events", marker);
        await Eventually.TrueAsync(async () => await AnomalyCountAsync(marker.OrgId) == 1, what: "marker");

        Assert.Equal(1, await AnomalyCountAsync(evt.OrgId));
        Assert.Equal(1, await containers.ScalarAsync<int>(
            "SELECT cardinality(event_ids) FROM anomalies WHERE org_id = $1", evt.OrgId));
    }

    [Fact]
    public async Task Messages_left_pending_by_a_crashed_consumer_are_reclaimed_and_processed()
    {
        var stream = $"tl:test:{Guid.NewGuid():N}";
        var redis = await containers.RedisAsync();
        var evt = await TorEventAsync();
        await redis.StreamCreateConsumerGroupAsync(stream, "detectors", "0", createStream: true);
        await XAddAsync(redis, stream, evt);

        // A consumer reads the message and "crashes" before acknowledging it.
        var stolen = await redis.StreamReadGroupAsync(stream, "detectors", "crashed-consumer", ">", 10);
        Assert.Single(stolen);

        var worker = await containers.StartWorkerAsync(OwnStream(stream));
        try
        {
            await Eventually.TrueAsync(async () => await AnomalyCountAsync(evt.OrgId) == 1, what: "reclaimed message to be processed");
            await Eventually.TrueAsync(async () => (await redis.StreamPendingAsync(stream, "detectors")).PendingMessageCount == 0, what: "ack");
        }
        finally
        {
            await worker.StopAsync(Ct);
            worker.Dispose();
        }
    }

    [Fact]
    public async Task A_poison_message_is_dead_lettered_after_max_deliveries()
    {
        var stream = $"tl:test:{Guid.NewGuid():N}";
        var redis = await containers.RedisAsync();
        await redis.StreamAddAsync(stream, [new("id", "poison"), new("event", "{ this is not json")]);

        var worker = await containers.StartWorkerAsync(OwnStream(stream));
        try
        {
            await Eventually.TrueAsync(async () => await redis.StreamLengthAsync($"{stream}:dead") == 1, what: "dead letter");
            var dead = (await redis.StreamRangeAsync($"{stream}:dead"))[0];
            Assert.Equal("poison", dead["id"].ToString());
            Assert.Equal("2", dead["deliveries"].ToString());
            await Eventually.TrueAsync(async () => (await redis.StreamPendingAsync(stream, "detectors")).PendingMessageCount == 0, what: "ack");
        }
        finally
        {
            await worker.StopAsync(Ct);
            worker.Dispose();
        }
    }

    [Fact]
    public async Task The_tor_list_survives_a_restart_without_internet_via_the_snapshot()
    {
        // Own Redis database (index 3) so deleting the set can't affect other tests.
        var redisDb3 = $"{containers.Redis.GetConnectionString()},defaultDatabase=3";
        var worker = await containers.StartWorkerAsync(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Redis"] = redisDb3,
            ["Events:StreamName"] = $"tl:test:{Guid.NewGuid():N}",
        });
        try
        {
            var redis = (await ConnectionMultiplexer.ConnectAsync(redisDb3)).GetDatabase();
            await Eventually.TrueAsync(() => redis.SetContainsAsync("tl:tor:exits", TestGeoIpLookup.TorExitIp), what: "initial load");

            await redis.KeyDeleteAsync("tl:tor:exits");   // Redis lost its data...
            var restored = await worker.Services.GetRequiredService<TorExitListLoader>().RestoreSnapshotAsync(Ct);

            Assert.True(restored >= 1);
            Assert.True(await redis.SetContainsAsync("tl:tor:exits", TestGeoIpLookup.TorExitIp));
        }
        finally
        {
            await worker.StopAsync(Ct);
            worker.Dispose();
        }
    }

    [Fact]
    public void Tor_list_parsing_skips_comments_blanks_and_garbage()
    {
        var ips = TorExitListLoader.Parse("# header\n\n171.25.193.25\r\nnot-an-ip\n2001:db8::1\n171.25.193.25\n");

        Assert.Equal(["171.25.193.25", "2001:db8::1"], ips);
    }

    [Fact]
    public async Task Retention_deletes_events_older_than_30_days_and_keeps_the_rest()
    {
        var owner = await containers.Api.RegisterOrgAsync();
        await using (var db = containers.Db())
        {
            await using var insert = db.CreateCommand(
                "INSERT INTO activity_events (id, org_id, user_id, type, occurred_at) VALUES ($1, $2, $3, 'note_read', now() - interval '31 days')");
            insert.Parameters.AddWithValue(Guid.CreateVersion7());
            insert.Parameters.AddWithValue(owner.User.OrgId);
            insert.Parameters.AddWithValue(owner.User.Id);
            await insert.ExecuteNonQueryAsync(Ct);
        }

        var purger = containers.Worker.Services.GetServices<IHostedService>().OfType<RetentionPurger>().Single();
        await purger.PurgeAsync(Ct);

        Assert.Equal(0, await containers.ScalarAsync<long>(
            "SELECT count(*) FROM activity_events WHERE user_id = $1 AND occurred_at < now() - interval '30 days'", owner.User.Id));
        Assert.True(await containers.ScalarAsync<long>("SELECT count(*) FROM activity_events WHERE user_id = $1", owner.User.Id) >= 1);
    }
}
