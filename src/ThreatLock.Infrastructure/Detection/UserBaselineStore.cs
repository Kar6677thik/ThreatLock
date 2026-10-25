using System.Collections.Concurrent;
using Npgsql;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Events;

namespace ThreatLock.Infrastructure.Detection;

/// <summary>
/// D3's per-user reading baselines in <c>user_baselines</c> (SPEC §8.2): read on the Worker's hot
/// path (cached for a minute; they only change hourly), and rebuilt hourly from activity events.
/// </summary>
public sealed class UserBaselineStore(NpgsqlDataSource db, TimeProvider time) : IUserBaselines
{
    /// <summary>How far back a user's first baseline looks.</summary>
    public static readonly TimeSpan Bootstrap = TimeSpan.FromDays(7);

    private static readonly TimeSpan CacheFor = TimeSpan.FromMinutes(1);
    private readonly ConcurrentDictionary<Guid, (UserBaseline? Baseline, DateTimeOffset Expires)> cache = new();

    public async ValueTask<UserBaseline?> GetAsync(Guid userId, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        if (cache.TryGetValue(userId, out var hit) && hit.Expires > now) return hit.Baseline;

        await using var command = db.CreateCommand("SELECT reads_per_min_mean, reads_per_min_std, active_minutes FROM user_baselines WHERE user_id = $1");
        command.Parameters.AddWithValue(userId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var baseline = await reader.ReadAsync(ct) ? new UserBaseline(reader.GetDouble(0), reader.GetDouble(1), reader.GetInt64(2)) : null;
        cache[userId] = (baseline, now + CacheFor);
        return baseline;
    }

    /// <summary>
    /// Folds every *complete* minute up to <paramref name="through"/> into each user's baseline,
    /// starting after that user's watermark (<c>computed_through</c>), so running twice changes
    /// nothing. One transaction under an advisory lock: two Workers can't both fold the same
    /// minutes. Minutes above the user's current threshold are capped first (<see cref="Ewma.Update"/>),
    /// so a scraping burst doesn't become "normal". Uses the default D3 settings for the cap.
    /// </summary>
    /// <returns>How many users' baselines changed.</returns>
    public async Task<int> UpdateAsync(DateTimeOffset through, CancellationToken ct)
    {
        through = new DateTimeOffset(through.UtcTicks - through.UtcTicks % TimeSpan.TicksPerMinute, TimeSpan.Zero);
        await using var connection = await db.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using (var serialise = new NpgsqlCommand("SELECT pg_advisory_xact_lock(hashtextextended('user_baselines', 0))", connection, transaction))
        {
            await serialise.ExecuteNonQueryAsync(ct);
        }

        var perUser = new Dictionary<Guid, List<long>>();
        var existing = new Dictionary<Guid, UserBaseline>();
        await using (var minutes = new NpgsqlCommand(
            $"""
            SELECT e.user_id, date_trunc('minute', e.occurred_at) AS minute, count(*) AS reads,
                   b.reads_per_min_mean, b.reads_per_min_std, b.active_minutes
            FROM activity_events e
            LEFT JOIN user_baselines b ON b.user_id = e.user_id
            WHERE e.type IN ('{EventTypes.NoteRead}', '{EventTypes.NoteListed}') AND e.user_id IS NOT NULL
              AND e.occurred_at >= COALESCE(b.computed_through, $1) AND e.occurred_at < $2
            GROUP BY e.user_id, minute, b.reads_per_min_mean, b.reads_per_min_std, b.active_minutes
            ORDER BY e.user_id, minute
            """, connection, transaction))
        {
            minutes.Parameters.AddWithValue(through - Bootstrap);
            minutes.Parameters.AddWithValue(through);
            await using var reader = await minutes.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var user = reader.GetGuid(0);
                if (!perUser.TryGetValue(user, out var counts)) perUser[user] = counts = [];
                counts.Add(reader.GetInt64(2));
                if (!reader.IsDBNull(3)) existing[user] = new UserBaseline(reader.GetDouble(3), reader.GetDouble(4), reader.GetInt64(5));
            }
        }

        foreach (var (user, counts) in perUser)
        {
            var baseline = existing.GetValueOrDefault(user);
            foreach (var reads in counts)
            {
                baseline = Ewma.Update(baseline, reads, cap: ScrapingSettings.Default.ThresholdFor(baseline));
            }

            await using var upsert = new NpgsqlCommand(
                """
                INSERT INTO user_baselines (user_id, reads_per_min_mean, reads_per_min_std, active_minutes, computed_through, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (user_id) DO UPDATE SET reads_per_min_mean = $2, reads_per_min_std = $3, active_minutes = $4,
                                                    computed_through = $5, updated_at = $6
                """, connection, transaction);
            upsert.Parameters.AddWithValue(user);
            upsert.Parameters.AddWithValue(baseline!.MeanPerMinute);
            upsert.Parameters.AddWithValue(baseline.StdPerMinute);
            upsert.Parameters.AddWithValue(baseline.ActiveMinutes);
            upsert.Parameters.AddWithValue(through);
            upsert.Parameters.AddWithValue(time.GetUtcNow());
            await upsert.ExecuteNonQueryAsync(ct);
            cache.TryRemove(user, out _);
        }

        await transaction.CommitAsync(ct);
        return perUser.Count;
    }
}
