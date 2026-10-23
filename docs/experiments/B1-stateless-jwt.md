# B1. Stateless JWT keeps working after revocation

- Status: **complete** (break in M2, prove in M3)
- Date run: 2026-10-23
- Git commits: break on `feat/m2-identity-notes` (M2); prove, and break re-run via `Auth:Mode=StatelessJwt`, on `feat/m3-real-sessions` (M3)
- Environment: local
- Machine: Intel Core Ultra 5 225H (14 cores), 14.9 GiB RAM, Windows 11 Pro 10.0.26100, .NET SDK 10.0.401, PostgreSQL 17.11 and Redis 8.10.2 in Docker Desktop

## Hypothesis

With stateless JWTs, the API validates a token using only its signature and claims; nothing it checks changes when a user logs out or an admin revokes their sessions. So a copied token should keep working until its `exp`, plus the validator's clock-skew allowance (30 s), whatever the server-side "revocation" does.

## Setup

- `Auth:AccessTokenMinutes` = 60 (M2 default) for run 1, and 2 for run 2 so the whole window can be watched.
- The script registers a fresh org, creates a victim, signs the victim in, copies the token (the "attacker"), signs the victim out, has the owner call `POST /api/admin/users/{id}/revoke-sessions`, then uses the copied token on `GET /api/notes/export`.
- Run 2 polls once per second until the API rejects the token.

## Commands

    docker compose -f deploy/compose/docker-compose.yml up -d --wait

    # Run 1: 60-minute tokens
    dotnet run --project src/ThreatLock.Api
    scripts/experiments/b1-stateless-jwt.sh

    # Run 2: 2-minute tokens, watch until rejected
    Auth__AccessTokenMinutes=2 dotnet run --project src/ThreatLock.Api
    POLL=1 POLL_INTERVAL=1 scripts/experiments/b1-stateless-jwt.sh

## Results: break

Run 1 (60-minute tokens):

    [12:37:27] Victim signed in. Token expires at 2026-10-23T13:37:27.4758094+00:00.
    [12:37:28] Attacker copied the token. /api/notes/export -> 200
    [12:37:28] Victim signed out.
    [12:37:28] Admin revoked the victim's sessions.
    [12:37:28] Attacker after revocation: /api/notes/export -> 200
    [12:37:28] Token still valid for about 3599s (+ up to 30s clock-skew allowance).

Run 2 (2-minute tokens, polled every 1 s):

    [12:37:39] Victim signed in. Token expires at 2026-10-23T12:39:38.7375935+00:00.
    [12:37:39] Attacker after revocation: /api/notes/export -> 200
    [12:37:39] Token still valid for about 119s (+ up to 30s clock-skew allowance).
    [12:40:09] Rejected. Continued access after revocation: 149.5s

| Metric | 60-min tokens | 2-min tokens |
| --- | --- | --- |
| Stolen token accepted after logout + admin revoke | yes | yes |
| Time left on token at revocation | 3,599 s | 119 s |
| Measured continued access after revocation | not waited (predicted ≈ 3,629 s) | **149.5 s** |

## Conclusion

The window is exactly *remaining lifetime + clock skew*: 119 s + 30 s ≈ 149.5 s. Nothing the server does shortens it, because the server consults nothing that revocation changes. With the M2 default of 60 minutes, a token stolen just after login gives an attacker about an hour, and logging out or clicking "revoke" doesn't help.

Two details worth remembering:

- **Clock skew counts.** The 30 s allowance (5 minutes by default in ASP.NET Core) is pure extra attacker time with stateless tokens.
- **Roles behave the same way.** A user promoted or demoted keeps their old roles until their token expires (see the `UserAdminTests` role-change test). Anything frozen into a token is stale until `exp`.

## Results: prove (M3)

M3 adds a server-side session per login, a `sid` claim in every access token, and a session check on every request (SPEC §6.5). The same script, with the step order unchanged, against both modes of the M3 build:

    # Default mode (SessionChecked), 5-minute tokens
    dotnet run --project src/ThreatLock.Api
    scripts/experiments/b1-stateless-jwt.sh

    [13:26:12] Victim signed in. Token expires at 2026-10-23T13:31:12.2797511+00:00.
    [13:26:12] Attacker copied the token. /api/notes/export -> 200
    [13:26:13] Victim signed out.
    [13:26:13] Attacker after logout:          /api/notes/export -> 401 in 0.014427s
    [13:26:13] Admin revoked the victim's sessions.
    [13:26:13] Attacker after admin revoke:    /api/notes/export -> 401
    [13:26:13] PROTECTED: rejected on the first request after revocation, although the token itself had 298s left.

    # Break mode kept as a switch in the M3 build
    Auth__Mode=StatelessJwt Auth__AccessTokenMinutes=60 dotnet run --project src/ThreatLock.Api
    scripts/experiments/b1-stateless-jwt.sh

    [13:26:27] Victim signed out.
    [13:26:27] Attacker after logout:          /api/notes/export -> 200 in 0.011695s
    [13:26:27] Admin revoked the victim's sessions.
    [13:26:27] Attacker after admin revoke:    /api/notes/export -> 200
    [13:26:27] VULNERABLE: the token is accepted for about 3598s more (+ up to 30s clock skew).

| Metric | Break (StatelessJwt, 60 min) | Prove (SessionChecked) |
| --- | --- | --- |
| Stolen token accepted after victim logout | yes | **no** (`401`) |
| Stolen token accepted after admin revoke | yes | **no** (`401`) |
| Continued access after revocation | ≈ remaining lifetime + 30 s (measured 149.5 s with 2-min tokens; ≈ 3,630 s with 60-min) | **0 requests**: the first request after revocation is rejected, 14 ms round trip |
| What the token's own expiry means | the only limit | defence in depth only (5 min) |

The same behaviour is pinned by automated tests (`BreakB1StatelessJwtTests`: break and prove, each for logout and admin revoke), and by a mutation check: disabling the session check makes 11 integration tests fail.

### What the fix costs

The session check is one Redis `GET` per request. Measured with `scripts/experiments/session-check-latency.py`: 2,000 sequential `GET /api/me` on one keep-alive connection, after 200 warm-up requests, same machine as above.

| Mode | p50 | p95 | p99 |
| --- | --- | --- | --- |
| StatelessJwt (no check) | 3.24 ms | 5.41 ms | 14.77 ms |
| SessionChecked, served from Redis | 3.89 ms | 6.18 ms | 10.24 ms |
| SessionChecked, Redis stopped → PostgreSQL fallback | 5.09 ms | 8.30 ms | 16.12 ms |

So instant revocation costs about **0.6 ms per request at p50** with Redis, and about 1.9 ms while Redis is down. The table uses the second of two runs per mode. The first SessionChecked run came straight after an API restart and measured p50 6.18 ms: 200 warm-up requests weren't enough to finish JIT warm-up, so that run measured a cold process, not the check. p99 values are noisy at this sample size.

## Threats to validity

- Local machine, single process, no network latency; neither the break nor the fix depends on timing, so this doesn't change the conclusion.
- The poll interval (1 s) bounds the measurement precision of the 2-minute break run to about ±1 s.
- Latency numbers are from a Windows laptop with Docker Desktop (a VM between the API and the databases). They will differ on the home server; the *difference* between modes is the useful number, and M10 re-measures there.
- `GET /api/me` itself does three database reads, so the relative overhead of the check would look larger on a cheaper endpoint.
