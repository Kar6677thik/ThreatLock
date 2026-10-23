namespace ThreatLock.Core.Sessions;

/// <summary>Why a session stopped being usable. Stored in <c>sessions.revoked_reason</c>.</summary>
public static class RevocationReasons
{
    public const string UserLogout = "user_logout";
    public const string UserRevoked = "user_revoked";          // "sign out that device" from My sessions
    public const string AdminManual = "admin_manual";
    public const string RefreshTokenReused = "refresh_token_reused";
}

/// <summary>Lifetime settings for one session (SPEC §6.3).</summary>
public sealed record SessionLifetime(TimeSpan Idle, TimeSpan Absolute)
{
    public static SessionLifetime Default { get; } = new(TimeSpan.FromHours(12), TimeSpan.FromDays(7));
}

/// <summary>
/// Pure rules about session state. No database, no clock: callers pass "now", which makes every
/// edge case (one tick before expiry, one tick after) trivial to unit-test.
/// </summary>
public static class SessionRules
{
    /// <summary>
    /// A session is usable only if nobody revoked it and neither deadline has passed. The idle
    /// deadline moves forward on each refresh; the absolute one never moves, so even a constantly
    /// used session must log in again eventually.
    /// </summary>
    public static bool IsActive(DateTimeOffset? revokedAt, DateTimeOffset idleExpiresAt, DateTimeOffset absoluteExpiresAt, DateTimeOffset now) =>
        revokedAt is null && now < idleExpiresAt && now < absoluteExpiresAt;

    /// <summary>New idle deadline after activity: now + idle, but never past the absolute deadline.</summary>
    public static DateTimeOffset SlideIdle(DateTimeOffset now, TimeSpan idle, DateTimeOffset absoluteExpiresAt) =>
        now + idle < absoluteExpiresAt ? now + idle : absoluteExpiresAt;

    /// <summary>
    /// What to do with a presented refresh token, given when (if ever) it was already used
    /// (SPEC §6.4).
    /// </summary>
    public static RefreshDecision DecideRefresh(DateTimeOffset? usedAt, DateTimeOffset now, TimeSpan reuseGrace)
    {
        if (usedAt is null) return RefreshDecision.Rotate;

        // Two tabs (or two requests from one tab) can refresh with the same cookie a few
        // milliseconds apart. That's a race, not a theft: refuse the late one without punishing
        // the user. An attacker replaying inside this window gains nothing; they get no token.
        return now - usedAt.Value <= reuseGrace ? RefreshDecision.Conflict : RefreshDecision.ReuseDetected;
    }
}

public enum RefreshDecision
{
    /// <summary>First use: issue a new refresh token and access token.</summary>
    Rotate,

    /// <summary>Used moments ago by someone else: answer 409 so the client retries with the newer cookie.</summary>
    Conflict,

    /// <summary>Used long ago: two parties hold the same token. Revoke the whole session.</summary>
    ReuseDetected,
}
