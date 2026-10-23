using ThreatLock.Core.Sessions;

namespace ThreatLock.Core.Tests.Sessions;

public class SessionRulesTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 23, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Tick = TimeSpan.FromTicks(1);

    [Fact]
    public void Active_until_the_first_deadline_and_not_a_tick_longer()
    {
        var idle = Now.AddHours(1);
        var absolute = Now.AddDays(1);

        Assert.True(SessionRules.IsActive(null, idle, absolute, idle - Tick));
        Assert.False(SessionRules.IsActive(null, idle, absolute, idle));
    }

    [Fact]
    public void Absolute_deadline_wins_even_if_idle_deadline_is_later()
    {
        Assert.False(SessionRules.IsActive(null, Now.AddHours(5), Now.AddHours(1), Now.AddHours(2)));
    }

    [Fact]
    public void Revoked_sessions_are_never_active()
    {
        Assert.False(SessionRules.IsActive(Now.AddMinutes(-1), Now.AddHours(1), Now.AddDays(1), Now));
    }

    [Fact]
    public void Sliding_never_passes_the_absolute_deadline()
    {
        var absolute = Now.AddHours(3);

        Assert.Equal(Now.AddHours(2), SessionRules.SlideIdle(Now, TimeSpan.FromHours(2), absolute));
        Assert.Equal(absolute, SessionRules.SlideIdle(Now, TimeSpan.FromHours(12), absolute));
    }

    [Theory]
    [InlineData(null, RefreshDecision.Rotate)]
    [InlineData(0, RefreshDecision.Conflict)]       // same instant: concurrent tabs
    [InlineData(5, RefreshDecision.Conflict)]       // still inside the 5 s grace
    [InlineData(6, RefreshDecision.ReuseDetected)]  // outside: two parties hold the token
    [InlineData(3600, RefreshDecision.ReuseDetected)]
    public void Refresh_decision_depends_on_how_long_ago_the_token_was_used(int? secondsAgo, RefreshDecision expected)
    {
        DateTimeOffset? usedAt = secondsAgo is null ? null : Now.AddSeconds(-secondsAgo.Value);

        Assert.Equal(expected, SessionRules.DecideRefresh(usedAt, Now, TimeSpan.FromSeconds(5)));
    }
}
