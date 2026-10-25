using Microsoft.Extensions.Options;
using Npgsql;
using StackExchange.Redis;
using ThreatLock.Infrastructure.Detection;
using ThreatLock.Infrastructure.Events;

namespace ThreatLock.Worker.Events;

/// <summary>
/// The outbox relay (SPEC §7.2): every few seconds, publishes events that were saved but never
/// reached the stream.
/// </summary>
public sealed partial class EventSweeper(EventPublisher publisher, IOptions<EventStreamOptions> options, TimeProvider time, ILogger<EventSweeper> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(options.Value.SweepInterval, time);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                var published = await publisher.SweepAsync(500, stoppingToken);
                if (published > 0) LogSwept(published);
            }
            catch (Exception ex) when (ex is NpgsqlException or RedisException or TimeoutException)
            {
                LogSweepFailed(ex);
            }
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Sweeper published {Count} events that had missed the stream")]
    private partial void LogSwept(int count);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Event sweep failed; retrying next interval")]
    private partial void LogSweepFailed(Exception ex);
}

/// <summary>Keeps the Tor exit list fresh (SPEC §8.2 D1): at startup, then every hour.</summary>
public sealed partial class TorListRefresher(TorExitListLoader loader, IOptions<TorOptions> options, TimeProvider time, ILogger<TorListRefresher> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!await TryRefreshAsync(stoppingToken))
        {
            // No internet (or the Tor Project is down): fall back to the last list we saved.
            try
            {
                if (await loader.RestoreSnapshotAsync(stoppingToken) == 0) LogNoList();
            }
            catch (Exception ex) when (ex is NpgsqlException or RedisException or TimeoutException)
            {
                LogRefreshFailed(ex);
            }
        }

        using var timer = new PeriodicTimer(options.Value.RefreshInterval, time);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            await TryRefreshAsync(stoppingToken);
        }
    }

    private async Task<bool> TryRefreshAsync(CancellationToken ct)
    {
        try
        {
            await loader.RefreshAsync(ct);
            return true;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or TaskCanceledException
                                       or NpgsqlException or RedisException or TimeoutException)
        {
            LogRefreshFailed(ex);
            return false;
        }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Could not refresh the Tor exit list")]
    private partial void LogRefreshFailed(Exception ex);

    [LoggerMessage(Level = LogLevel.Error, Message = "No Tor exit list available (download failed and no snapshot); detector D1 is blind")]
    private partial void LogNoList();
}

/// <summary>
/// Deletes activity events older than the retention period (SPEC §7.4). They contain IP addresses,
/// which are personal data; keeping them forever "just in case" is a privacy liability.
/// Deletes in batches so one run never holds a long lock on a big table.
/// </summary>
public sealed partial class RetentionPurger(NpgsqlDataSource db, IOptions<EventStreamOptions> options, TimeProvider time, ILogger<RetentionPurger> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromMinutes(1), time, stoppingToken);   // let startup settle first
        using var timer = new PeriodicTimer(TimeSpan.FromHours(24), time);
        do
        {
            try
            {
                var deleted = await PurgeAsync(stoppingToken);
                if (deleted > 0) LogPurged(deleted, options.Value.RetentionDays);
            }
            catch (Exception ex) when (ex is NpgsqlException or TimeoutException)
            {
                LogPurgeFailed(ex);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    public async Task<int> PurgeAsync(CancellationToken ct)
    {
        var cutoff = time.GetUtcNow().AddDays(-options.Value.RetentionDays);
        var total = 0;
        int batch;
        do
        {
            await using var command = db.CreateCommand(
                "DELETE FROM activity_events WHERE id IN (SELECT id FROM activity_events WHERE occurred_at < $1 LIMIT 5000)");
            command.Parameters.AddWithValue(cutoff);
            batch = await command.ExecuteNonQueryAsync(ct);
            total += batch;
        }
        while (batch > 0);

        return total;
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Retention purge deleted {Count} activity events older than {Days} days")]
    private partial void LogPurged(int count, int days);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Retention purge failed; retrying tomorrow")]
    private partial void LogPurgeFailed(Exception ex);
}

/// <summary>
/// Rebuilds D3's reading baselines from activity events (SPEC §8.2): at startup, then hourly.
/// Each run folds only minutes after each user's watermark, so restarts and overlapping runs
/// are harmless.
/// </summary>
public sealed partial class BaselineUpdater(UserBaselineStore baselines, TimeProvider time, ILogger<BaselineUpdater> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1), time);
        do
        {
            try
            {
                var updated = await baselines.UpdateAsync(time.GetUtcNow(), stoppingToken);
                if (updated > 0) LogUpdated(updated);
            }
            catch (Exception ex) when (ex is NpgsqlException or TimeoutException)
            {
                LogUpdateFailed(ex);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Updated reading baselines for {Count} users")]
    private partial void LogUpdated(int count);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Baseline update failed; retrying next hour")]
    private partial void LogUpdateFailed(Exception ex);
}
