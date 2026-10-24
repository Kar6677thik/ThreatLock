using ThreatLock.Core.Detection;
using ThreatLock.Core.Policy;

namespace ThreatLock.Core.Response;

/// <summary>What a response job does (SPEC §10.3). Stored in <c>response_jobs.action</c>.</summary>
public static class JobActions
{
    /// <summary>Only tell the admins (decision <c>notified</c>).</summary>
    public const string Notify = "notify";

    /// <summary>Sign the user out everywhere, then tell the admins.</summary>
    public const string RevokeSessions = ResponseActions.RevokeSessions;

    /// <summary>Sign out everywhere and refuse logins until an admin unlocks.</summary>
    public const string RevokeAndLock = ResponseActions.RevokeAndLock;

    public static bool Revokes(string action) => action is RevokeSessions or RevokeAndLock;
}

/// <summary>Where a job is in its lifecycle (SPEC §10.1).</summary>
public static class JobStatuses
{
    public const string Pending = "pending";
    public const string Running = "running";
    public const string Succeeded = "succeeded";
    public const string Dead = "dead";

    public static IReadOnlyList<string> All { get; } = [Pending, Running, Succeeded, Dead];
}

/// <summary>
/// The response to carry out for one anomaly, fixed when the anomaly is created. Retries replay
/// this plan; they don't re-read a policy that may have changed since.
/// </summary>
public sealed record ResponsePlan(string Action, IReadOnlyList<string> NotifyRoles);

public static class ResponsePlanner
{
    /// <summary>
    /// <c>responded</c> → revoke (escalated to revoke-and-lock if the policy says so, or if the
    /// severity reaches <see cref="ResponsePolicy.LockOnSeverity"/>); <c>notified</c> → notify only;
    /// anything else → nothing to do, so no job.
    /// </summary>
    public static ResponsePlan? Plan(Decision decision, Severity severity, SecurityPolicy policy) => decision.Outcome switch
    {
        DecisionOutcome.Responded => new(
            policy.Response.Action == ResponseActions.RevokeAndLock || severity >= policy.Response.LockOnSeverity
                ? JobActions.RevokeAndLock
                : JobActions.RevokeSessions,
            policy.NotifyRoles),
        DecisionOutcome.Notified => new(JobActions.Notify, policy.NotifyRoles),
        _ => null,
    };
}

/// <summary>Retry timing for failed jobs (SPEC §10.1).</summary>
public static class ResponseBackoff
{
    public const int MaxAttempts = 5;
    public static readonly TimeSpan Cap = TimeSpan.FromSeconds(60);

    /// <summary>
    /// <c>min(2^attempts s, 60 s)</c> plus up to 20 % jitter. The jitter spreads out retries so a
    /// burst of jobs that failed together (say, Redis blipped) doesn't retry in lockstep.
    /// </summary>
    /// <param name="attempts">Attempts made so far, including the one that just failed (≥ 1).</param>
    /// <param name="jitter">A number in [0, 1); pass <c>Random.Shared.NextDouble()</c>.</param>
    public static TimeSpan Delay(int attempts, double jitter)
    {
        var seconds = Math.Min(Math.Pow(2, Math.Max(attempts, 0)), Cap.TotalSeconds);
        return TimeSpan.FromSeconds(seconds * (1 + 0.2 * Math.Clamp(jitter, 0, 0.999_999)));
    }

    /// <summary>After this attempt, does the job get another try or is it dead?</summary>
    public static bool IsExhausted(int attempts) => attempts >= MaxAttempts;
}
