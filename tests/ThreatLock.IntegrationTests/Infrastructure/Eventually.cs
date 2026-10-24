using Npgsql;
using StackExchange.Redis;

namespace ThreatLock.IntegrationTests.Infrastructure;

/// <summary>
/// Waits for something asynchronous (the Worker) to happen. Polls a condition instead of
/// sleeping a fixed time: fast when things are fast, and it fails with a clear timeout.
/// </summary>
public static class Eventually
{
    public static async Task<T> GetAsync<T>(Func<Task<T?>> probe, TimeSpan? timeout = null, string? what = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(15));
        while (true)
        {
            var value = await probe();
            if (value is not null && !(value is System.Collections.ICollection { Count: 0 })) return value;
            if (DateTime.UtcNow > deadline) throw new TimeoutException($"Timed out waiting for {what ?? "condition"}.");
            await Task.Delay(100, TestContext.Current.CancellationToken);
        }
    }

    public static async Task TrueAsync(Func<Task<bool>> probe, TimeSpan? timeout = null, string? what = null) =>
        await GetAsync<object>(async () => await probe() ? true : null, timeout, what);
}

/// <summary>Direct access to the test databases, for assertions the API doesn't expose.</summary>
public static class Stores
{
    public static NpgsqlDataSource Db(this ContainersFixture c) => NpgsqlDataSource.Create(c.Postgres.GetConnectionString());

    public static async Task<IDatabase> RedisAsync(this ContainersFixture c) =>
        (await ConnectionMultiplexer.ConnectAsync(c.Redis.GetConnectionString())).GetDatabase();

    public static async Task<T?> ScalarAsync<T>(this ContainersFixture c, string sql, params object[] args)
    {
        await using var db = c.Db();
        await using var command = db.CreateCommand(sql);
        foreach (var arg in args) command.Parameters.AddWithValue(arg);
        var result = await command.ExecuteScalarAsync(TestContext.Current.CancellationToken);
        return result is null or DBNull ? default : (T)result;
    }
}
