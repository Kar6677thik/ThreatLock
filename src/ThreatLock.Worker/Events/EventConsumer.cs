using ThreatLock.Infrastructure.Observability;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Npgsql;
using StackExchange.Redis;
using ThreatLock.Infrastructure.Events;
using ThreatLock.Worker.Detection;

namespace ThreatLock.Worker.Events;

/// <summary>
/// Reads activity events from the Redis stream as part of a consumer group (SPEC §7.3,
/// concepts.md §2.4).
/// <list type="number">
/// <item>On start, re-processes this consumer's own pending messages (left over from a crash).</item>
/// <item>Then reads new messages (<c>XREADGROUP ... &gt;</c>), processes each, and only then
/// acknowledges it (<c>XACK</c>). Ack-after-processing is what makes delivery at-least-once.</item>
/// <item>Periodically reclaims messages another consumer took but never acknowledged, and
/// dead-letters any message that has failed <see cref="EventStreamOptions.MaxDeliveries"/> times.</item>
/// </list>
/// </summary>
public sealed partial class EventConsumer(
    IConnectionMultiplexer redis,
    EventProcessor processor,
    IOptions<EventStreamOptions> options,
    ThreatLockMetrics metrics,
    TimeProvider time,
    ILogger<EventConsumer> logger) : BackgroundService
{
    // StackExchange.Redis multiplexes one connection for everything, so it can't issue a
    // *blocking* XREADGROUP (it would stall every other command). We poll instead; this interval is
    // part of the detection latency budget, so it's short.
    private static readonly TimeSpan IdlePoll = TimeSpan.FromMilliseconds(100);
    private const int BatchSize = 100;

    private EventStreamOptions Stream => options.Value;
    private string Consumer => Stream.ResolvedConsumerName;
    private IDatabase Db => redis.GetDatabase();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await EnsureGroupAsync(stoppingToken);
        LogStarted(Stream.StreamName, Stream.ConsumerGroup, Consumer);

        // "0" = my pending entries (delivered to me before, never acknowledged).
        while (await ReadAndHandleAsync("0", stoppingToken) > 0) { }

        var nextClaim = time.GetUtcNow();
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (time.GetUtcNow() >= nextClaim)
                {
                    await ReclaimAsync(stoppingToken);
                    await SampleLagAsync();
                    nextClaim = time.GetUtcNow() + Stream.ClaimInterval;
                }

                // ">" = messages never delivered to anyone in the group.
                if (await ReadAndHandleAsync(">", stoppingToken) == 0)
                {
                    await Task.Delay(IdlePoll, time, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (ex is RedisException or TimeoutException)
            {
                LogRedisDown(ex);
                await Task.Delay(TimeSpan.FromSeconds(2), time, stoppingToken);
            }
        }
    }

    private async Task<int> ReadAndHandleAsync(string position, CancellationToken ct)
    {
        var entries = await Db.StreamReadGroupAsync(Stream.StreamName, Stream.ConsumerGroup, Consumer, position, BatchSize);
        foreach (var entry in entries)
        {
            await HandleAsync(entry, ct);
        }

        return entries.Length;
    }

    /// <summary>
    /// Processes one message. On failure the message is deliberately left unacknowledged: it stays
    /// in the pending list and is retried by <see cref="ReclaimAsync"/> after
    /// <see cref="EventStreamOptions.ClaimIdle"/>, until it either succeeds or is dead-lettered.
    /// </summary>
    private async Task HandleAsync(StreamEntry entry, CancellationToken ct)
    {
        try
        {
            var evt = EventJson.Deserialize(entry["event"].ToString());
            await processor.ProcessAsync(evt, ct);
            await Db.StreamAcknowledgeAsync(Stream.StreamName, Stream.ConsumerGroup, entry.Id);
        }
        catch (Exception ex) when (ex is JsonException or NpgsqlException or RedisException or TimeoutException or NotSupportedException)
        {
            LogHandleFailed(ex, entry.Id.ToString());
        }
    }

    /// <summary>The consumer group's lag (Redis 7+): how far the detectors are behind the API.</summary>
    private async Task SampleLagAsync()
    {
        var groups = await Db.StreamGroupInfoAsync(Stream.StreamName);
        if (groups.FirstOrDefault(g => g.Name == Stream.ConsumerGroup) is { Lag: { } lag }) metrics.SetStreamLag(lag);
    }

    /// <summary>Takes over abandoned messages, and dead-letters the ones that keep failing.</summary>
    private async Task ReclaimAsync(CancellationToken ct)
    {
        var minIdleMs = (long)Stream.ClaimIdle.TotalMilliseconds;
        var pending = await Db.StreamPendingMessagesAsync(Stream.StreamName, Stream.ConsumerGroup, BatchSize, RedisValue.Null);
        var stale = pending.Where(p => p.IdleTimeInMilliseconds >= minIdleMs).ToList();

        foreach (var poison in stale.Where(p => p.DeliveryCount >= Stream.MaxDeliveries))
        {
            await DeadLetterAsync(poison);
            metrics.EventDeadLettered();
        }

        var retry = stale.Where(p => p.DeliveryCount < Stream.MaxDeliveries).Select(p => p.MessageId).ToArray();
        if (retry.Length == 0) return;

        // XCLAIM moves ownership to us and bumps the delivery count. The min-idle argument means
        // that if the original consumer just recovered and acknowledged it, we claim nothing.
        var claimed = await Db.StreamClaimAsync(Stream.StreamName, Stream.ConsumerGroup, Consumer, minIdleMs, retry);
        foreach (var entry in claimed.Where(e => !e.IsNull))
        {
            await HandleAsync(entry, ct);
        }
    }

    private async Task DeadLetterAsync(StreamPendingMessageInfo poison)
    {
        var original = await Db.StreamRangeAsync(Stream.StreamName, poison.MessageId, poison.MessageId);
        NameValueEntry[] fields = original.Length == 1
            ? [.. original[0].Values, new("deliveries", poison.DeliveryCount), new("dead_lettered_at", time.GetUtcNow().ToString("O"))]
            : [new("missing_message_id", poison.MessageId)];

        // Copy first, acknowledge second: a crash in between leaves a duplicate in the dead-letter
        // stream, never a lost message.
        await Db.StreamAddAsync(Stream.DeadLetterStreamName, fields);
        await Db.StreamAcknowledgeAsync(Stream.StreamName, Stream.ConsumerGroup, poison.MessageId);
        LogDeadLettered(poison.MessageId.ToString(), poison.DeliveryCount);
    }

    private async Task EnsureGroupAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                // Position "0": a brand-new group starts at the beginning of the stream, so events
                // written before the Worker's first start are still processed.
                await Db.StreamCreateConsumerGroupAsync(Stream.StreamName, Stream.ConsumerGroup, "0", createStream: true);
                return;
            }
            catch (RedisServerException ex) when (ex.Message.Contains("BUSYGROUP", StringComparison.Ordinal))
            {
                return;   // the group already exists: normal on every start after the first
            }
            catch (Exception ex) when (ex is RedisException or TimeoutException)
            {
                LogRedisDown(ex);
                await Task.Delay(TimeSpan.FromSeconds(2), time, ct);
            }
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Consuming {Stream} as {Group}/{Consumer}")]
    private partial void LogStarted(string stream, string group, string consumer);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Could not process stream message {MessageId}; it will be retried")]
    private partial void LogHandleFailed(Exception ex, string messageId);

    [LoggerMessage(Level = LogLevel.Error, Message = "Dead-lettered stream message {MessageId} after {Deliveries} deliveries")]
    private partial void LogDeadLettered(string messageId, int deliveries);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Redis unavailable to the event consumer; retrying")]
    private partial void LogRedisDown(Exception ex);
}
