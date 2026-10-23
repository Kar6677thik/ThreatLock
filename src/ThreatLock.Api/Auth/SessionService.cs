using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ThreatLock.Core.Sessions;
using ThreatLock.Infrastructure.Persistence;
using ThreatLock.Infrastructure.Sessions;

namespace ThreatLock.Api.Auth;

/// <summary>A new or rotated session: what the client gets back.</summary>
public sealed record SessionTokens(IssuedToken Access, string RefreshToken, DateTimeOffset RefreshExpiresAt, AppUser User, IReadOnlyList<string> Roles);

public enum RefreshStatus { Rotated, Invalid, Conflict, ReuseDetected }

public sealed record RefreshResult(RefreshStatus Status, SessionTokens? Tokens = null);

/// <summary>Starts sessions at login and rotates refresh tokens (SPEC §6.2, §6.4).</summary>
public sealed class SessionService(
    ThreatLockDbContext db,
    UserManager<AppUser> users,
    TokenService tokens,
    SessionStore store,
    IOptions<AuthOptions> options,
    TimeProvider time)
{
    private AuthOptions Auth => options.Value;

    public async Task<SessionTokens> StartAsync(AppUser user, IReadOnlyList<string> roles, ClientInfo client, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var session = new Session
        {
            UserId = user.Id,
            OrgId = user.OrgId,
            CreatedAt = now,
            CreatedIp = client.Ip,
            CreatedDeviceId = client.DeviceId,
            CreatedUserAgent = client.UserAgent,
            LastSeenAt = now,
            AbsoluteExpiresAt = now + Auth.SessionAbsoluteTimeout,
        };
        session.IdleExpiresAt = SessionRules.SlideIdle(now, Auth.SessionIdleTimeout, session.AbsoluteExpiresAt);

        var (plain, row) = NewRefreshToken(session.Id, now);
        db.Sessions.Add(session);
        db.RefreshTokens.Add(row);
        await db.SaveChangesAsync(ct);

        return new SessionTokens(tokens.Issue(user, roles, session.Id), plain, session.IdleExpiresAt, user, roles);
    }

    public async Task<RefreshResult> RefreshAsync(string presented, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var hash = Hash(presented);
        var token = await db.RefreshTokens.SingleOrDefaultAsync(t => t.TokenHash == hash, ct);
        if (token is null) return new(RefreshStatus.Invalid);

        var session = await db.Sessions.SingleAsync(s => s.Id == token.SessionId, ct);
        if (!SessionRules.IsActive(session.RevokedAt, session.IdleExpiresAt, session.AbsoluteExpiresAt, now))
        {
            return new(RefreshStatus.Invalid);
        }

        // Claim the token atomically: "set used_at if it's still null". If two requests race,
        // PostgreSQL lets exactly one UPDATE match; the loser sees 0 rows and re-reads used_at.
        var claimed = token.UsedAt is null && await db.RefreshTokens
            .Where(t => t.Id == token.Id && t.UsedAt == null)
            .ExecuteUpdateAsync(set => set.SetProperty(t => t.UsedAt, now), ct) == 1;

        if (!claimed)
        {
            var usedAt = await db.RefreshTokens.Where(t => t.Id == token.Id).Select(t => t.UsedAt).SingleAsync(ct);
            var decision = SessionRules.DecideRefresh(usedAt, now, Auth.RefreshReuseGrace);
            if (decision == RefreshDecision.ReuseDetected)
            {
                // Two parties hold this session's refresh token. We can't tell which one is the
                // thief, so the session dies for both (SPEC §6.4). M4 turns this into an event
                // for detector D5.
                await store.RevokeAsync(session.Id, RevocationReasons.RefreshTokenReused, ct);
                return new(RefreshStatus.ReuseDetected);
            }

            return new(RefreshStatus.Conflict);
        }

        var user = await users.FindByIdAsync(session.UserId.ToString());
        if (user is null) return new(RefreshStatus.Invalid);

        var (plain, next) = NewRefreshToken(session.Id, now);
        db.RefreshTokens.Add(next);
        token.ReplacedById = next.Id;
        session.IdleExpiresAt = SessionRules.SlideIdle(now, Auth.SessionIdleTimeout, session.AbsoluteExpiresAt);
        session.LastSeenAt = now;
        // used_at was set by the atomic UPDATE above. EF only writes properties changed in
        // memory, so this save touches replaced_by_id and the session, not used_at.
        await db.SaveChangesAsync(ct);

        // Roles are re-read on every refresh, so a role change reaches the user within one access
        // token lifetime (5 minutes) instead of at the next login.
        var roles = (await users.GetRolesAsync(user)).ToArray();
        return new(RefreshStatus.Rotated, new SessionTokens(tokens.Issue(user, roles, session.Id), plain, session.IdleExpiresAt, user, roles));
    }

    /// <summary>32 random bytes from the OS CSPRNG; only the SHA-256 hash is stored.</summary>
    private static (string Plain, RefreshToken Row) NewRefreshToken(Guid sessionId, DateTimeOffset now)
    {
        var plain = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        return (plain, new RefreshToken { SessionId = sessionId, TokenHash = Hash(plain), CreatedAt = now });
    }

    // A fast hash is fine here (unlike passwords): the token has 256 bits of randomness, so
    // there's nothing to brute-force.
    private static byte[] Hash(string token) => SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token));
}
