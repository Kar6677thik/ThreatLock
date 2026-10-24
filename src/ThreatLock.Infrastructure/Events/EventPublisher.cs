using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using StackExchange.Redis;
using ThreatLock.Core.Events;

namespace ThreatLock.Infrastructure.Events;

/// <summary>
/// Gets activity events from the API to the Worker (SPEC §7.2):
/// <list type="number">
/// <item>Insert the event into <c>activity_events</c> with <c>published_at = null</c>.</item>
/// <item><c>XADD</c> it to the Redis stream (the fast path).</item>
/// <item>Set <c>published_at</c>.</item>
/// </list>
/// If step 2 or 3 fails, the row stays unpublished and the Worker's sweeper retries it. So an event
/// can reach the stream twice (sweeper and API both succeeded), never zero times once step 1
/// committed: at-least-once delivery, and consumers are idempotent on the event id.
/// </summary>
public sealed partial class EventPublisher(
    NpgsqlDataSource db,
    IConnectionMultiplexer redis,
    IOptions<EventStreamOptions> options,
    TimeProvider time,
    ILogger<EventPublisher> logger)
{
    private EventStreamOptions Stream => options.Value;

    /// <summary>
    /// Records an event. Never throws: failing to record telemetry must not fail the user's
    /// request (SPEC §7.2). Failures are logged instead.
    /// </summary>
    public async Task RecordAsync(ActivityEvent evt, CancellationToken ct)
    {
        try
        {
            await InsertAsync(evt, ct);
        }
        catch (Exception ex) when (ex is NpgsqlException or TimeoutException)
        {
            LogInsertFailed(ex, evt.Type, evt.Id);
            return;
        }

        await TryPublishAsync(evt, ct);
    }

    /// <summary>XADD + mark published. Returns false (and logs) if either step fails.</summary>
    public async Task<bool> TryPublishAsync(ActivityEvent evt, CancellationToken ct)
    {
        try
        {
            await redis.GetDatabase().StreamAddAsync(
                Stream.StreamName,
                [new NameValueEntry("id", evt.Id.ToString()), new NameValueEntry("event", EventJson.Serialize(evt))],
                maxLength: Stream.MaxLength,
                useApproximateMaxLength: true);
        }
        catch (Exception ex) when (ex is RedisException or TimeoutException)
        {
            LogPublishFailed(ex, evt.Id);
            return false;
        }

        try
        {
            await using var command = db.CreateCommand("UPDATE activity_events SET published_at = $1 WHERE id = $2");
            command.Parameters.AddWithValue(time.GetUtcNow());
            command.Parameters.AddWithValue(evt.Id);
            await command.ExecuteNonQueryAsync(ct);
            return true;
        }
        catch (Exception ex) when (ex is NpgsqlException or TimeoutException)
        {
            // Already on the stream; the sweeper will publish it again. Harmless duplicate.
            LogMarkFailed(ex, evt.Id);
            return false;
        }
    }

    /// <summary>
    /// The outbox relay: publishes events that were saved but never reached the stream (Redis was
    /// down, the API crashed between insert and XADD...). Returns how many it published.
    /// </summary>
    public async Task<int> SweepAsync(int batchSize, CancellationToken ct)
    {
        var pending = new List<ActivityEvent>();
        await using (var command = db.CreateCommand(
            """
            SELECT id, org_id, user_id, session_id, type, occurred_at, ip, geo, device_id, user_agent, request_id, metadata
            FROM activity_events
            WHERE published_at IS NULL AND occurred_at < $1
            ORDER BY occurred_at
            LIMIT $2
            """))
        {
            command.Parameters.AddWithValue(time.GetUtcNow() - Stream.SweepMinAge);
            command.Parameters.AddWithValue(batchSize);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                pending.Add(new ActivityEvent(
                    reader.GetGuid(0),
                    reader.GetGuid(1),
                    reader.IsDBNull(2) ? null : reader.GetGuid(2),
                    reader.IsDBNull(3) ? null : reader.GetGuid(3),
                    reader.GetString(4),
                    reader.GetFieldValue<DateTimeOffset>(5),
                    reader.IsDBNull(6) ? null : reader.GetFieldValue<System.Net.IPAddress>(6).ToString(),
                    reader.IsDBNull(7) ? null : JsonSerializer.Deserialize<ThreatLock.Core.Geo.GeoInfo>(reader.GetString(7), EventJson.Options),
                    reader.IsDBNull(8) ? null : reader.GetString(8),
                    reader.IsDBNull(9) ? null : reader.GetString(9),
                    reader.IsDBNull(10) ? null : reader.GetString(10),
                    reader.IsDBNull(11) ? null : System.Text.Json.Nodes.JsonNode.Parse(reader.GetString(11))?.AsObject()));
            }
        }

        var published = 0;
        foreach (var evt in pending)
        {
            if (!await TryPublishAsync(evt, ct)) break;   // Redis still down: stop, try again next sweep
            published++;
        }

        return published;
    }

    private async Task InsertAsync(ActivityEvent evt, CancellationToken ct)
    {
        await using var command = db.CreateCommand(
            """
            INSERT INTO activity_events
                (id, org_id, user_id, session_id, type, occurred_at, ip, geo, device_id, user_agent, request_id, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12::jsonb)
            """);
        command.Parameters.AddWithValue(evt.Id);
        command.Parameters.AddWithValue(evt.OrgId);
        command.Parameters.AddWithValue((object?)evt.UserId ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)evt.SessionId ?? DBNull.Value);
        command.Parameters.AddWithValue(evt.Type);
        command.Parameters.AddWithValue(evt.OccurredAt);
        command.Parameters.AddWithValue((object?)evt.IpAddress ?? DBNull.Value);
        command.Parameters.AddWithValue(evt.Geo is null ? DBNull.Value : JsonSerializer.Serialize(evt.Geo, EventJson.Options));
        command.Parameters.AddWithValue((object?)evt.DeviceId ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)evt.UserAgent ?? DBNull.Value);
        command.Parameters.AddWithValue((object?)evt.RequestId ?? DBNull.Value);
        command.Parameters.AddWithValue(evt.Metadata is null ? DBNull.Value : evt.Metadata.ToJsonString());
        await command.ExecuteNonQueryAsync(ct);
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Could not record {EventType} event {EventId}; it is lost")]
    private partial void LogInsertFailed(Exception ex, string eventType, Guid eventId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Event {EventId} saved but not published to the stream; the sweeper will retry")]
    private partial void LogPublishFailed(Exception ex, Guid eventId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Event {EventId} published but not marked; the sweeper may publish it again")]
    private partial void LogMarkFailed(Exception ex, Guid eventId);
}
