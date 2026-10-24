using Microsoft.Extensions.Options;
using Npgsql;
using ThreatLock.Infrastructure.Response;

namespace ThreatLock.Worker.Response;

/// <summary>
/// Runs response jobs (SPEC §10.1): claim one, execute it, repeat; when there's nothing to do,
/// sleep until PostgreSQL announces a new job (LISTEN/NOTIFY) or the poll interval passes.
/// <para>
/// The NOTIFY is what keeps time-to-revoke low: without it a new job waits up to one poll
/// interval. The poll is still needed, for retries coming due and for expired leases, which
/// nobody announces.
/// </para>
/// </summary>
public sealed partial class ResponseOrchestrator(
    NpgsqlDataSource db,
    ResponseJobStore jobs,
    ResponseExecutor executor,
    IOptions<ResponseOptions> options,
    ILogger<ResponseOrchestrator> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled) return;

        NpgsqlConnection? listener = null;
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                if (await RunOneAsync(stoppingToken)) continue;   // there may be more: don't sleep

                listener ??= await TryListenAsync(stoppingToken);
                listener = await WaitAsync(listener, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Shutting down. A job we were running stays "running" until its lease expires, and
            // then another Worker (or we, after a restart) picks it up.
        }
        finally
        {
            if (listener is not null) await listener.DisposeAsync();
        }
    }

    /// <summary>Claims and runs one job. True if there was one.</summary>
    private async Task<bool> RunOneAsync(CancellationToken ct)
    {
        ClaimedJob? job;
        try
        {
            job = await jobs.ClaimAsync(ct);
        }
        catch (Exception ex) when (ex is NpgsqlException or TimeoutException)
        {
            LogClaimFailed(ex);
            return false;
        }

        if (job is null) return false;

        try
        {
            await executor.ExecuteAsync(job, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Stopping: give the job back rather than sit on it for the rest of the lease. Every
            // step is idempotent, so whoever picks it up can safely redo whatever we started.
            try
            {
                await jobs.ReleaseAsync(job, CancellationToken.None);
            }
            catch (Exception ex) when (ex is NpgsqlException or TimeoutException)
            {
                LogClaimFailed(ex);   // the lease covers this too
            }

            throw;
        }
        catch (Exception ex)
        {
            try
            {
                var status = await jobs.FailAsync(job, ex, ct);
                LogJobFailed(ex, job.Id, job.Attempts, status);
            }
            catch (Exception inner) when (inner is NpgsqlException or TimeoutException)
            {
                // Can't even record the failure. The lease runs out and the job is retried anyway.
                LogClaimFailed(inner);
            }
        }

        return true;
    }

    private async Task<NpgsqlConnection?> TryListenAsync(CancellationToken ct)
    {
        try
        {
            var connection = await db.OpenConnectionAsync(ct);
            await using var listen = new NpgsqlCommand($"LISTEN {ResponseJobStore.Channel}", connection);
            await listen.ExecuteNonQueryAsync(ct);
            return connection;
        }
        catch (NpgsqlException ex)
        {
            LogListenFailed(ex);
            return null;
        }
    }

    /// <summary>Waits for a NOTIFY or the poll interval. Returns the listener, or null if it broke.</summary>
    private async Task<NpgsqlConnection?> WaitAsync(NpgsqlConnection? listener, CancellationToken ct)
    {
        if (listener is null)
        {
            await Task.Delay(options.Value.PollInterval, ct);
            return null;
        }

        try
        {
            await listener.WaitAsync(options.Value.PollInterval, ct);
            return listener;
        }
        catch (Exception ex) when (ex is NpgsqlException or IOException)
        {
            LogListenFailed(ex);
            await listener.DisposeAsync();
            return null;
        }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Could not claim response jobs; retrying")]
    private partial void LogClaimFailed(Exception ex);

    [LoggerMessage(Level = LogLevel.Error, Message = "Response job {JobId} failed on attempt {Attempt}; now {Status}")]
    private partial void LogJobFailed(Exception ex, Guid jobId, int attempt, string status);

    [LoggerMessage(Level = LogLevel.Warning, Message = "LISTEN connection unavailable; polling only")]
    private partial void LogListenFailed(Exception ex);
}
