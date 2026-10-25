# B2. Replayed stolen session from another country

- Date run: 2026-10-25
- Git commit (break): M8 branch with D5 and D2 switched off by policy             Git commit (prove): M8 branch, default policy
- Environment: local
- Machine: Intel Core Ultra 5 225H (14 logical cores), 15 GB RAM, Windows 11, .NET SDK 10.0.401, PostgreSQL 17.11 and Redis 8.10.2 in Docker Compose; DB-IP Lite City GeoIP

## Hypothesis

A session token copied off a victim's machine (malware, a shared computer, a leaked HAR file) works for whoever holds it. The server-side session check (M3) only helps once *someone* revokes the session. Before M8, nothing would.

D5 should notice that the session's **fingerprint** changed: a different device id and a different browser family than the session started with. D2 should notice the jump from India to the UK. Under the default policy D5 responds, so the stolen token should stop working within about a second.

## Setup

- **Break:** a fresh org whose policy switches `session_hijack` and `impossible_travel` off. That is the pre-M8 situation for this attack (D2 only notified anyway). Using the same build for both runs means the only difference is the detectors.
- **Prove:** a fresh org with the default policy: D5 `respond`, D2 `notify`.
- **10 trials per mode**, each with a new victim:
  1. The victim signs in from India (`49.207.48.1`, simulated via the keyed header, ADR-0007) with device `victim-device-…` and Chrome on Windows, then lists their notes.
  2. The thief replays the same access token from the UK (`81.2.69.142`) with device `thief-device-…` and Firefox on Linux, polling `GET /api/notes` every 50 ms until it gets a 401 or 15 s pass.
- **Time to revoke** = the thief's first request → the first 401 the thief sees, measured by the client (SPEC §16.2).

## Commands

    docker compose -f deploy/compose/docker-compose.yml up -d
    dotnet run --project src/ThreatLock.Api        # and, in another terminal:
    dotnet run --project src/ThreatLock.Worker
    scripts/experiments/b2-cookie-replay.sh        # TRIALS=10, MAX_SECONDS=15; ~3 minutes

## Results: break

    break trial 1: thief served 45 requests; still working after 15 s
    ...
    break trial 10: thief served 44 requests; still working after 15 s
    break: no trial was revoked within 15 s

| Metric | Value |
| --- | --- |
| Trials where the thief lost access within 15 s | **0 / 10** |
| Requests served to the thief per trial | 43–45 (all of them) |
| Anomalies raised | none |

## Results: prove

    prove trial 1: thief served 2 requests; revoked after 869 ms
    prove trial 2: thief served 1 requests; revoked after 481 ms
    ...
    prove: n=10 p50=506 ms p95=869 ms max=869 ms mean=546 ms

| Metric | Value |
| --- | --- |
| Trials where the thief lost access | **10 / 10** |
| Time to revoke p50 / p95 / max | **506 ms / 869 ms / 869 ms** |
| Requests served to the thief | 1 in 9 trials, 2 in 1 |
| Anomalies per victim | D5 `session_hijack` *responded* (evidence: `Chrome/Windows` → `Firefox/Linux`, `victim-device-…` → `thief-device-…`); D2 `impossible_travel` *notified* |

## Evidence

The admin UI's anomaly page for "Victim 10": *Session hijack (D5), high, responded (mode_respond), judged by policy v0*. The timeline reads *revoke_sessions: succeeded after 1 attempt(s) · 1 session(s) revoked · Admins notified*. Next to it in the list is the D2 *notified* anomaly for the same victim.

## Conclusion

Without D5, a replayed token kept working for as long as we watched, and nothing anywhere noticed. With D5, the first request from the other machine was enough: the session was revoked in about half a second. The one request the thief did get served is the price of detecting asynchronously (ADR-0004). D2 adds a notification on top, so admins see "this person was suddenly in the UK" next to "and their session moved machines".

## Threats to validity

- **Coarse timing.** On Windows each poll costs ~330 ms (curl plus a Python call for the timestamp), so the 50 ms sleep isn't what limits the loop. The real time to revoke is somewhat shorter than reported. M9 measures it properly with an in-process client.
- **An attacker who copies more defeats D5's fingerprint signal.** A thief who also copies the device id and the exact user agent changes nothing D5 looks at. The refresh-token side (signal (a): reuse is Critical) still catches them as soon as both parties refresh, and D2 still notifies on the geography.
- Simulated IPs through the keyed header; single machine; 10 trials.
