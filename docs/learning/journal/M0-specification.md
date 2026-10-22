# M0. Specification

- Dates: 2026-10-22 →
- PR(s): spec PR
- Spec sections: all
- Concepts: all (skim once)

## Goal

Turn a half-page project brief into a specification precise enough that every later milestone is "implement §X" rather than "figure out what §X should be". Done when the open questions are either answered or have a default that doesn't block M1.

## What I did, in order

1. **Read the brief and the Field Guide sections it cites** (8, 18, 19, 24, 25). *Why first:* the brief is short and leaves a lot unsaid. The Field Guide lists the patterns we're expected to exercise.
2. **Read Slack's write-up of AER.** *Why:* the three-part shape (detection engine, decision framework, response orchestrator) becomes our component boundaries, and the specific details (idempotent async job, audit entry naming the anomaly, no duplicate notices for multi-role admins) become requirements.
3. **Checked the home server before designing deployment.** Found it runs k3s (not Docker) for other projects, with an existing "GitHub Actions → Tailscale → SSH → restricted root helper" pattern. *Why now:* the deployment target shapes packaging decisions (images, migrations as Jobs, resource limits), and it's cheaper to know at spec time.
4. **Made three owner decisions:** C#/.NET 10, React + Vite SPA, tailnet-only exposure.
5. **Listed every ambiguity** in the brief and resolved each (spec §22).
6. **Wrote one ADR per decision that would be expensive to reverse** (docs/adr).
7. **Defined measurements before building anything** (spec §16): what a false positive is, and where time-to-revoke starts and stops. *Why:* if you define the metric after seeing the numbers, you'll unconsciously define it to look good.

## Decisions

| Decision | Alternative | Why | Record |
| --- | --- | --- | --- |
| .NET 10 + Identity | Python + FastAPI | Identity gives battle-tested login, lockout and hashing; same stack as the guide and the existing server app | [ADR-0001](../../adr/0001-stack-dotnet-react-postgres-redis.md) |
| React + Vite SPA | Razor Pages | Keeps bearer tokens visible so the revocation lesson shows in the browser | ADR-0001 |
| Session row + 5-min JWT + rotating refresh cookie | Stateless JWT | Revocation must be immediate | [ADR-0002](../../adr/0002-short-lived-jwt-plus-server-side-session-check.md) |
| Redis Streams for events, Postgres table for jobs | One queue for both | Different reliability needs; and both are worth learning | [ADR-0003](../../adr/0003-event-transport-redis-streams-and-postgres-jobs.md) |
| Async detect-then-respond | Inline blocking | Matches AER; keeps the request path fast and independent | [ADR-0004](../../adr/0004-asynchronous-detect-then-respond.md) |
| Per-org hash chain | Permissions only | Detects edits even by a DB superuser | [ADR-0005](../../adr/0005-audit-log-per-org-sha256-hash-chain.md) |
| Replay harness + live harness | One harness | Realistic scenarios need days of event time; latency needs real hops | [ADR-0006](../../adr/0006-evaluation-replay-harness-and-live-harness.md) |
| Keyed simulation header for client IP | Real proxies abroad | Reproducible geography from one home network | [ADR-0007](../../adr/0007-client-ip-resolution-and-simulation-header.md) |
| k3s via GitHub Actions + Tailscale, tailnet only | Self-hosted runner / public tunnel | Least privilege, no public exposure, reuses a known-good pattern | [ADR-0008](../../adr/0008-deployment-k3s-github-actions-tailscale.md) |
| DB-IP Lite GeoIP | MaxMind (needs account) | No account or licence key needed in CI | [ADR-0009](../../adr/0009-geoip-source-dbip-lite.md) |
| Added detector D5 (hijack signals) | Only the four listed | Break B2 (cookie replay) can't be caught reliably by the other four | Spec §8.2 |
| Added `revoke_and_lock` action | Revoke only | Revoking sessions doesn't stop someone who has the password | Spec §10.3 |

## Commands I ran

    # Inspect the repo and local toolchain
    git status
    dotnet --list-sdks
    docker --version

    # Read-only look at the home server over Tailscale
    # (OS, CPU, memory, disk, k3s version, what's listening, existing deploy pattern)

## What surprised me

- **The server has no Docker.** Compose is local-only; the server needs Kubernetes manifests. Good thing to find out at spec time, not at M10.
- **The brief's Break steps need things the Build step doesn't list.** "Replay a copied cookie from a different IP" needs (a) a way to fake IPs and (b) a detector that notices. Hence ADR-0007 and D5.
- **"Safe to run twice" is subtle.** The obvious "revoke all sessions for user" step is *not* safe to retry: if the real user logged back in between attempts, the retry would kick them out again. The fix is the `cutoff` timestamp (spec §10.2).
- **Revoking sessions doesn't evict an attacker who knows the password.** They log in again and we loop. Hence the lock option.

## What I'd explain in an interview

Stolen sessions are dangerous for as long as they stay valid, so the design target was the time from a malicious request to that session being rejected. I split the system like Slack's AER into detection, a per-tenant decision step and an async responder. I made revocation instant by checking a server-side session id on every request through a Redis cache, while keeping 5-minute tokens as defence in depth. Every step of the response is idempotent, so crashes and retries can't double-revoke or double-notify, and the audit trail is a per-tenant hash chain, so tampering is detectable.

## Open threads

- Q1–Q5 in spec §23, each with a default.
- Verify the server's k3s storage class and free memory in M10.
