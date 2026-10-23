# B1. Stateless JWT keeps working after revocation

- Status: **break run** (M2). The prove run is added in M3.
- Date run: 2026-10-23
- Git commit (break): M2 branch `feat/m2-identity-notes`
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

## Prove (M3, to be added)

Expected: with server-side sessions checked on every request, the same script shows `401` on the first request after revocation, so continued access is roughly one request round-trip instead of minutes.

## Threats to validity

- Local machine, single process, no network latency; the break doesn't depend on timing, so this doesn't change the conclusion.
- The poll interval (1 s) bounds the measurement precision of run 2 to about ±1 s.
