# 0002. Short-lived JWT plus server-side session check, rotating refresh cookie

- Status: Accepted
- Date: 2026-10-22
- Milestone: M3 (the B1 break is in M2)

## Context

The whole point of ThreatLock is that revocation works *now*. A stateless JWT is valid until it expires: the server has nothing to consult, so "revoking" it means nothing until `exp`. A server-side session can be revoked instantly but traditionally costs a database read per request. The browser also needs to stay signed in for hours without keeping a long-lived bearer credential where JavaScript can read it.

## Decision

1. Login creates a **server-side session row** (`sid`). This row is the unit of revocation.
2. The browser gets a **5-minute access JWT** carrying `sid`, kept in memory only.
3. The API **checks `sid` on every request** through a Redis cache (`a` = active, `r` = revoked), falling back to PostgreSQL, and fails closed if both are down.
4. A **refresh token** (random, stored hashed) lives in an `HttpOnly; Secure; SameSite=Strict; Path=/api/auth` cookie. It is **rotated on every use**, and **reuse of an old one revokes the session** and raises a hijack signal.
5. A config flag `Auth:Mode=StatelessJwt` (60-minute tokens, no session check) exists only to reproduce Break B1.

## Alternatives considered

- **Pure stateless JWT:** cannot revoke. This is the failure we are demonstrating.
- **JWT deny-list of `jti`s:** works, but you must list *every* outstanding token of a user. Revoking a session id covers all of them with one key.
- **Per-user `sessions_valid_after` timestamp:** simple (reject tokens whose `iat` is older), but coarse: it kills every session and can't express "kill only this one". We may still add it as a belt-and-braces check.
- **Classic cookie session only (no JWT):** simplest and perfectly revocable, but cookie-authenticated APIs need CSRF protection on every endpoint, and we would lose the JWT lesson the brief asks for.
- **Opaque tokens validated against the DB:** effectively what we do; the JWT just lets us read user, org and roles without a lookup.

## Consequences

- Every request costs one Redis `GET` (sub-millisecond on the same host). We measure it (`tl_session_check_seconds`).
- Redis staleness is bounded: revocation *writes* a revoked marker, so only a failed Redis write after a successful PostgreSQL commit can leave a stale active entry, for at most its 60 s TTL.
- The SPA needs a refresh-on-401 wrapper, and the access token disappears on page reload (the refresh cookie gets a new one). That's expected.
