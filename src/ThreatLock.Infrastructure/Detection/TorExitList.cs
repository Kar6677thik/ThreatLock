using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using StackExchange.Redis;
using ThreatLock.Core.Detection;

namespace ThreatLock.Infrastructure.Detection;

/// <summary>Bound from the <c>Tor</c> configuration section (SPEC §8.2 D1).</summary>
public sealed class TorOptions
{
    public const string SectionName = "Tor";

    /// <summary>The Tor Project's published list of exit-node IPs, one per line.</summary>
    public string ListUrl { get; set; } = "https://check.torproject.org/torbulkexitlist";

    /// <summary>A local file to use instead of the URL (offline development, tests).</summary>
    public string? ListPath { get; set; }

    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromHours(1);

    public string Source => string.IsNullOrWhiteSpace(ListPath) ? ListUrl : ListPath;
}

/// <summary>Membership test against the Redis set the loader maintains: one <c>SISMEMBER</c> per event.</summary>
public sealed class RedisTorExitList(IConnectionMultiplexer redis) : ITorExitList
{
    internal const string Key = "tl:tor:exits";

    public async ValueTask<bool> IsExitAsync(IPAddress ip, CancellationToken ct)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return await redis.GetDatabase().SetContainsAsync(Key, ip.ToString());
    }
}

/// <summary>
/// Downloads the Tor exit list and installs it (SPEC §8.2 D1):
/// <list type="bullet">
/// <item>Redis gets the new set via a temporary key + <c>RENAME</c>, which is atomic, so the
/// detector never sees a half-loaded or empty list mid-refresh.</item>
/// <item>PostgreSQL keeps the latest copy, so a Worker that restarts without internet still has one.</item>
/// </list>
/// </summary>
public sealed partial class TorExitListLoader(
    IHttpClientFactory http,
    NpgsqlDataSource db,
    IConnectionMultiplexer redis,
    IOptions<TorOptions> options,
    TimeProvider time,
    ILogger<TorExitListLoader> logger)
{
    /// <summary>Fetch, parse and install. Returns the number of exits loaded.</summary>
    public async Task<int> RefreshAsync(CancellationToken ct)
    {
        var source = options.Value.Source;
        var text = string.IsNullOrWhiteSpace(options.Value.ListPath)
            ? await http.CreateClient(nameof(TorExitListLoader)).GetStringAsync(options.Value.ListUrl, ct)
            : await File.ReadAllTextAsync(options.Value.ListPath, ct);

        var ips = Parse(text);
        // A suspiciously empty download (outage page, truncated response) must not wipe a good list.
        if (ips.Count == 0) throw new InvalidDataException($"Tor exit list from {source} contained no addresses.");

        await InstallInRedisAsync(ips);
        await SaveSnapshotAsync(ips, source, ct);
        LogLoaded(ips.Count, source);
        return ips.Count;
    }

    /// <summary>Loads the last saved snapshot into Redis. Used at startup when the download fails.</summary>
    public async Task<int> RestoreSnapshotAsync(CancellationToken ct)
    {
        await using var command = db.CreateCommand("SELECT ips, fetched_at FROM tor_exit_snapshots ORDER BY fetched_at DESC LIMIT 1");
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return 0;

        var ips = reader.GetFieldValue<IPAddress[]>(0).Select(ip => ip.ToString()).ToList();
        await InstallInRedisAsync(ips);
        LogRestored(ips.Count, reader.GetFieldValue<DateTimeOffset>(1));
        return ips.Count;
    }

    /// <summary>One address per line; comments, blanks and anything unparsable are skipped.</summary>
    public static List<string> Parse(string text) =>
        [.. text.Split('\n')
            .Select(line => line.Trim())
            .Where(line => line.Length > 0 && !line.StartsWith('#'))
            .Select(line => IPAddress.TryParse(line, out var ip) ? ip.ToString() : null)
            .OfType<string>()
            .Distinct()];

    private async Task InstallInRedisAsync(IReadOnlyCollection<string> ips)
    {
        var database = redis.GetDatabase();
        RedisKey staging = $"{RedisTorExitList.Key}:loading:{Guid.NewGuid():N}";
        foreach (var chunk in ips.Chunk(1000))
        {
            await database.SetAddAsync(staging, [.. chunk.Select(ip => (RedisValue)ip)]);
        }

        await database.KeyRenameAsync(staging, RedisTorExitList.Key);
    }

    private async Task SaveSnapshotAsync(IReadOnlyCollection<string> ips, string source, CancellationToken ct)
    {
        await using var connection = await db.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);

        await using (var insert = new NpgsqlCommand("INSERT INTO tor_exit_snapshots (fetched_at, source, ips) VALUES ($1, $2, $3)", connection, transaction))
        {
            insert.Parameters.AddWithValue(time.GetUtcNow());
            insert.Parameters.AddWithValue(source.Length > 500 ? source[..500] : source);
            insert.Parameters.AddWithValue(ips.Select(IPAddress.Parse).ToArray());
            await insert.ExecuteNonQueryAsync(ct);
        }

        // Keep only the newest snapshot; history isn't useful and each one is ~20 KB.
        await using (var prune = new NpgsqlCommand(
            "DELETE FROM tor_exit_snapshots WHERE id NOT IN (SELECT id FROM tor_exit_snapshots ORDER BY fetched_at DESC LIMIT 1)",
            connection, transaction))
        {
            await prune.ExecuteNonQueryAsync(ct);
        }

        await transaction.CommitAsync(ct);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Loaded {Count} Tor exit addresses from {Source}")]
    private partial void LogLoaded(int count, string source);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Restored {Count} Tor exit addresses from the snapshot taken at {FetchedAt}")]
    private partial void LogRestored(int count, DateTimeOffset fetchedAt);
}
