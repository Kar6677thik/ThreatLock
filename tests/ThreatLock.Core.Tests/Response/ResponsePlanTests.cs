using ThreatLock.Core.Detection;
using ThreatLock.Core.Policy;
using ThreatLock.Core.Response;

namespace ThreatLock.Core.Tests.Response;

public class ResponsePlanTests
{
    private static readonly SecurityPolicy Policy = SecurityPolicy.Default;

    [Theory]
    [InlineData(DecisionOutcome.Suppressed)]
    [InlineData(DecisionOutcome.Observed)]
    public void Suppressed_and_observed_anomalies_need_no_job(DecisionOutcome outcome) =>
        Assert.Null(ResponsePlanner.Plan(new Decision(outcome, "x"), Severity.Critical, Policy));

    [Fact]
    public void Notified_only_notifies_the_policys_roles()
    {
        var plan = ResponsePlanner.Plan(new Decision(DecisionOutcome.Notified, "x"), Severity.Critical, Policy);

        Assert.Equal(JobActions.Notify, plan!.Action);
        Assert.Equal(Policy.NotifyRoles, plan.NotifyRoles);
    }

    [Theory]
    [InlineData(Severity.High, JobActions.RevokeSessions)]
    [InlineData(Severity.Critical, JobActions.RevokeAndLock)]   // default lockOnSeverity
    public void Responded_revokes_and_escalates_to_lock_at_the_policys_severity(Severity severity, string expected) =>
        Assert.Equal(expected, ResponsePlanner.Plan(new Decision(DecisionOutcome.Responded, "x"), severity, Policy)!.Action);

    [Fact]
    public void An_org_can_choose_to_always_lock()
    {
        var policy = Policy with { Response = new ResponsePolicy(ResponseActions.RevokeAndLock) };

        Assert.Equal(JobActions.RevokeAndLock, ResponsePlanner.Plan(new Decision(DecisionOutcome.Responded, "x"), Severity.Low, policy)!.Action);
    }

    [Theory]
    [InlineData(1, 2)]
    [InlineData(2, 4)]
    [InlineData(4, 16)]
    [InlineData(6, 60)]    // 64 s, capped
    [InlineData(20, 60)]
    public void Backoff_doubles_up_to_a_minute(int attempts, double seconds) =>
        Assert.Equal(TimeSpan.FromSeconds(seconds), ResponseBackoff.Delay(attempts, jitter: 0));

    [Fact]
    public void Jitter_adds_at_most_twenty_percent()
    {
        Assert.Equal(TimeSpan.FromSeconds(2.2), ResponseBackoff.Delay(1, jitter: 0.5));
        Assert.True(ResponseBackoff.Delay(6, jitter: 1) < TimeSpan.FromSeconds(72));
    }

    [Theory]
    [InlineData(4, false)]
    [InlineData(5, true)]
    public void The_fifth_attempt_is_the_last(int attempts, bool exhausted) =>
        Assert.Equal(exhausted, ResponseBackoff.IsExhausted(attempts));
}
