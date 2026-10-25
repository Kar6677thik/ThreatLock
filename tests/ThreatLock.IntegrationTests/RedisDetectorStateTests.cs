using StackExchange.Redis;
using ThreatLock.Infrastructure.Detection;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

/// <summary>The Redis detector state against real Redis: the sliding window and set-once values D3–D5 rely on.</summary>
public class RedisDetectorStateTests(ContainersFixture containers)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly DateTimeOffset T0 = new(2026, 10, 24, 9, 0, 0, TimeSpan.Zero);

    private async Task<RedisDetectorState> StateAsync() =>
        new(await ConnectionMultiplexer.ConnectAsync(containers.Redis.GetConnectionString()));

    [Fact]
    public async Task The_window_slides_with_event_time_and_counts_each_member_once()
    {
        var state = await StateAsync();
        var key = $"test:{Guid.NewGuid():N}";
        var window = TimeSpan.FromMinutes(1);

        Assert.Equal(1, await state.CountInWindowAsync(key, "a", T0, window, Ct));
        Assert.Equal(2, await state.CountInWindowAsync(key, "b", T0.AddSeconds(30), window, Ct));
        Assert.Equal(2, await state.CountInWindowAsync(key, "b", T0.AddSeconds(30), window, Ct));   // redelivered: still 2
        // A minute and a second after "a": "a" has left the window, "b" and "c" are in it.
        Assert.Equal(2, await state.CountInWindowAsync(key, "c", T0.AddSeconds(61), window, Ct));
    }

    [Fact]
    public async Task Values_can_be_set_once_and_expire()
    {
        var state = await StateAsync();
        var key = $"test:{Guid.NewGuid():N}";

        Assert.True(await state.SetValueAsync(key, "first", TimeSpan.FromSeconds(1), onlyIfAbsent: true, Ct));
        Assert.False(await state.SetValueAsync(key, "second", TimeSpan.FromSeconds(1), onlyIfAbsent: true, Ct));
        Assert.Equal("first", await state.GetValueAsync(key, Ct));

        await Eventually.TrueAsync(async () => await state.GetValueAsync(key, Ct) is null, TimeSpan.FromSeconds(5), "expiry");
    }
}
