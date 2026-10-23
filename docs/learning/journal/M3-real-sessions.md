# M3. Real sessions

- Dates: 2026-10-23 →
- PR(s): M3 PR
- Spec sections: §6 identity, sessions and revocation (all of it), §13 API, §14 UI (My sessions), §15 B1 prove, §16.3 overhead
- Concepts: [1.2 sessions vs tokens](../concepts.md#12-sessions-vs-tokens-fg-82-83), [1.4 stateless revocation](../concepts.md#14-why-stateless-jwt-revocation-is-hard-break-b1), [1.5 refresh rotation](../concepts.md#15-refresh-tokens-rotation-and-reuse-detection-fg-814), [1.6 cookies](../concepts.md#16-cookies-httponly-secure-samesite-csrf-fg-258), [1.11 fail closed](../concepts.md#111-fail-closed-vs-fail-open-fg-17-253), [2.7 atomic compare-and-set](../concepts.md#27-atomic-compare-and-set-in-sql-fg-11)

## Goal

Make revocation real. A logout or admin revoke must stop a copied token on its very next request, the browser must stay signed in across reloads without keeping a long-lived token where JavaScript can read it, and a stolen refresh cookie must be detectable. Done when the B1 script that "won" in M2 gets `401`, the cost of the fix is measured, and the naive mode is still available behind a switch.

## What I did, in order

1. **Wrote the rules as pure functions first** (`SessionRules` in Core): is a session active, how the idle deadline slides without passing the absolute one, and what to do with a presented refresh token (rotate / conflict / reuse). *Why first:* every edge case (one tick before expiry, 5 s vs 6 s after first use) is a one-line unit test when the clock is a parameter.
2. **Added `sessions` and `refresh_tokens`** (migration `AddSessionsAndRefreshTokens`). `inet` for IPs; a *partial index* on `user_id WHERE revoked_at IS NULL`, so "all live sessions of this user" stays fast as revoked rows pile up; refresh tokens stored only as SHA-256 hashes.
3. **Built `SessionStore` in Infrastructure** (shared with the Worker for M6): `IsActiveAsync` (Redis `a`/`r` cache → PostgreSQL), `RevokeAsync` / `RevokeAllForUserAsync` (PostgreSQL first, then write `r` to Redis), `TouchAsync` (last-seen, throttled to once a minute with a Redis `SET NX`). Hand-written SQL via Npgsql: three small statements are clearer than EF here, and `UPDATE ... RETURNING` gives back exactly what was revoked.
4. **Hooked the check into JWT bearer authentication** (`SessionValidation`): after the signature, issuer, audience and expiry pass, `OnTokenValidated` checks the `sid`. A dead session gets `401` with `error_description="session_revoked"`; an unreachable store gets `503` (fail closed, but "try again", not "you're signed out").
5. **Tokens now carry `sid` and live 5 minutes**; `Auth:Mode=StatelessJwt` keeps the M2 behaviour for B1.
6. **Login/register start a session** and set the refresh cookie (`HttpOnly; Secure; SameSite=Strict; Path=/api/auth`). **`/api/auth/refresh`** rotates it with an atomic claim, re-reads roles, slides the idle deadline, and handles the two-tab race with a 5-second grace window (`409`). Reuse after the window revokes the whole session. **Logout** revokes the session. **My sessions** lists and revokes your own sessions; **admin revoke** is now real and idempotent; admins can list a user's sessions.
7. **Client IP from trusted proxies only** (ADR-0007, moved here from M2): forwarded headers are honoured only from configured proxies/networks, ASP.NET Core's default trust of loopback is removed, and `ForwardLimit = 1` so a client can't prepend a fake address. Device id (`X-Device-Id`, strict format) and user agent are recorded with the session.
8. **Tests**: 9 new unit tests and 25 new integration tests (cookie attributes, rotation, race, reuse, CSRF header, role pickup, logout, My sessions, cross-user revoke attempt, admin revoke idempotency, idle expiry with a fake clock, Redis down, both stores down, client IP trust, device-id validation). The four tests that pinned M2's behaviour were updated, and B1 now has a break test *and* a prove test.
9. **Mutation check**: switched the session check off → 11 integration tests failed. Restored.
10. **SPA**: a device id in localStorage, sent on every request; silent session restore on page load; refresh-once-on-401 with a single shared in-flight refresh; a 409 retry; a "You were signed out" message; a My sessions tab.
11. **Checked it in a real browser** (in-app preview): registered, reloaded → still signed in via the HttpOnly cookie (which `document.cookie` cannot see); signed out → refresh returns `401`.
12. **Ran B1 again** in both modes and **measured the cost** of the check (see Numbers).

## Decisions

| Decision | Alternative | Why |
| --- | --- | --- |
| Check `sid` in `JwtBearerEvents.OnTokenValidated` | Separate middleware after authentication | Runs exactly when a token has been validated, and a failure becomes a normal authentication failure (401 + `WWW-Authenticate`), so `[Authorize]`/fallback policies just work. |
| Redis cache stores `a`/`r` with TTLs; revocation *writes* `r` | Delete the key on revoke | A delete leaves a window where a concurrent check re-caches a stale "active" from a read that started before the revoke. Writing `r` closes it. |
| Unknown session id → inactive | Throw / 500 | A forged or old token with a made-up `sid` is simply not signed in. |
| Both stores down → `503`, not `401` | `401` | `401` makes the SPA throw the user out over *our* outage. `503` says "retry later" and still lets nothing through. |
| Atomic claim (`UPDATE ... WHERE used_at IS NULL`) for refresh | Load entity, check, save | Two concurrent refreshes would both pass a check-then-save. The test fires 5 at once: exactly one `200`. |
| 5 s grace → `409`, no revocation | Treat every reuse as theft | Two tabs (or React StrictMode's double effects in development) refresh at the same moment. Punishing that signs real users out. An attacker inside the window gets nothing. |
| Re-read roles on every refresh | Freeze roles until next login | Role changes (especially removals) now apply within 5 minutes. |
| `Auth:Mode` switch kept in the product | Delete the naive path | B1 must stay reproducible, and the switch makes the before/after comparison one environment variable. Default is the safe mode. |
| Sessions created in both modes | Skip sessions in StatelessJwt | One code path. In StatelessJwt they exist but nothing checks them, which is exactly the vulnerability. |
| Trust no proxies by default (cleared loopback) | Keep ASP.NET's default loopback trust | In Kubernetes the proxy is never loopback, and on a dev box loopback trust lets any local process claim any IP. The config list is the whole truth. |
| Test client uses `https://localhost` | Turn `Secure` off in tests | Tests exercise the real cookie attributes; TestServer doesn't care about the scheme. |
| Hand-written SQL in `SessionStore` | EF Core | Three tiny hot-path statements; `RETURNING` makes revocation results exact; the Worker can share it without a DbContext. |
| Didn't add `user_devices` yet | Add the table now | Nothing reads it until detectors D4/D5 (M8). The session row already records the device. |

## Commands I ran

    dotnet ef migrations add AddSessionsAndRefreshTokens --project src/ThreatLock.Infrastructure \
        --startup-project src/ThreatLock.Infrastructure --output-dir Persistence/Migrations
    dotnet ef migrations script InitialIdentityOrgsNotes -o /tmp/m3.sql   # just this migration's SQL

    dotnet test                                   # 93 passed (23 unit + 70 integration)
    # mutation: return early in SessionValidation.OnTokenValidated → 11 failures → restore

    cd web && npm run lint && npm test && npm run build    # 11 tests

    dotnet run --project src/ThreatLock.Api
    scripts/experiments/b1-stateless-jwt.sh                               # prove
    Auth__Mode=StatelessJwt Auth__AccessTokenMinutes=60 dotnet run --project src/ThreatLock.Api
    scripts/experiments/b1-stateless-jwt.sh                               # break, same build

    python scripts/experiments/session-check-latency.py <label>           # x2 per mode
    docker compose -f deploy/compose/docker-compose.yml stop redis        # fallback run

## What broke / surprised me

- **Exactly four existing tests failed** after switching to sessions, all of them tests that pinned M2's behaviour (60-minute tokens, forged tokens without `sid`, the B1 "still works" assertions). Everything else passed unchanged, a good sign the change was contained.
- **Configuration read in `Program.cs` is invisible to test overrides.** The forwarded-headers setup first read `Network:*` while the app was being built; `WebApplicationFactory` applies its settings later. Moving the read into an options `Configure<IConfiguration>` callback fixed it (the same lesson as M1's connection strings).
- **ASP.NET Core trusts loopback proxies by default.** Easy to miss, and wrong for us. Cleared explicitly.
- **The B1 script's own wording became misleading** in the prove run ("token still valid for 298 s" next to a 401). Fixed the script to say VULNERABLE / PROTECTED.
- **The first latency run after a restart was ~2× slower** than the second. 200 warm-up requests didn't cover JIT warm-up. Reported both runs instead of quietly picking one.
- **`curl` won't send a `Secure` cookie over plain http**, but browsers will on `localhost`. Documented how to refresh from curl by sending the cookie header manually.

## Numbers

| Metric | Value | Conditions |
| --- | --- | --- |
| Tests | 93 .NET (23 unit + 70 integration), 11 frontend | All green |
| B1 break (StatelessJwt, M3 build): stolen token after logout + admin revoke | `200`, ≈ 3,598 s of validity left | Local |
| **B1 prove (SessionChecked): stolen token after logout** | **`401` on the first request (14 ms round trip)** | Token itself still had 298 s left |
| Session check cost, p50 / p95 | +0.65 ms / +0.77 ms vs no check (3.89 vs 3.24 ms; 6.18 vs 5.41 ms) | Redis hit, 2,000 `GET /api/me`, warm |
| Session check with Redis down (PostgreSQL fallback), p50 / p95 | 5.09 ms / 8.30 ms | Same |
| Mutation check | 11 integration tests fail without the session check | |

Full numbers and the raw runs: [B1 report](../../experiments/B1-stateless-jwt.md).

## What I'd explain in an interview

I fixed the stateless-JWT revocation problem by tying every access token to a server-side session and checking that session on each request through a Redis cache that falls back to PostgreSQL and fails closed with a 503 if both are down. Revocation writes a "revoked" marker instead of deleting the cache entry, which closes a stale-read race. Refresh tokens are rotated with an atomic compare-and-set in SQL, and reuse after a 5-second grace window kills the session, which turns a stolen refresh cookie into a detectable event without punishing two browser tabs refreshing at once. The same attack script that kept access for an hour in the naive mode is now rejected on its first request, for about 0.6 ms of extra latency per request.

## Open threads

- Emit `token_refreshed` and `refresh_token_reused` as activity events (M4); D5 consumes reuse (M8).
- Audit entries for logout and revocations (M7).
- `user_devices` table for "first time we've seen this device" (M8).
- Security lock (`revoke_and_lock`) refusing login with `403` (M6).
- Re-measure session-check cost on the home server (M10).
