# Architecture decision records

An ADR captures **one** significant decision: the situation, what we chose, what we rejected, and what it costs us. They are short on purpose. Field Guide section 33 (teamwork and architecture governance) is why they exist: six months from now, "why on earth is it like this?" should take one minute to answer.

## Rules

- One file per decision, numbered, never renumbered.
- Status is `Proposed`, `Accepted`, `Superseded by ADR-NNNN` or `Deprecated`.
- Don't edit an accepted ADR's decision. Write a new ADR that supersedes it, so the history of thinking stays visible.
- Write it when the decision is made, not after the code ships.

## Index

| # | Decision | Status |
| --- | --- | --- |
| [0001](0001-stack-dotnet-react-postgres-redis.md) | Stack: .NET 10, React + Vite, PostgreSQL, Redis | Accepted |
| [0002](0002-short-lived-jwt-plus-server-side-session-check.md) | Short-lived JWT plus server-side session check, rotating refresh cookie | Accepted |
| [0003](0003-event-transport-redis-streams-and-postgres-jobs.md) | Redis Streams for activity events, PostgreSQL table for response jobs | Accepted |
| [0004](0004-asynchronous-detect-then-respond.md) | Asynchronous detect-then-respond, no inline blocking | Accepted |
| [0005](0005-audit-log-per-org-sha256-hash-chain.md) | Audit log as a per-org SHA-256 hash chain in PostgreSQL | Accepted |
| [0006](0006-evaluation-replay-harness-and-live-harness.md) | Two evaluation harnesses: offline replay and live HTTP | Accepted |
| [0007](0007-client-ip-resolution-and-simulation-header.md) | Client IP from trusted proxies only, plus a keyed simulation header | Accepted |
| [0008](0008-deployment-k3s-github-actions-tailscale.md) | Deploy to home-server k3s via GitHub Actions over Tailscale, tailnet only | Accepted |
| [0009](0009-geoip-source-dbip-lite.md) | GeoIP from DB-IP Lite City (CC BY 4.0) | Accepted |

## Template

```markdown
# NNNN. Title

- Status: Proposed
- Date: YYYY-MM-DD
- Milestone: Mx

## Context
What forces are at play? What problem needs a decision?

## Decision
What we will do, in one or two sentences, then details.

## Alternatives considered
- Option: why not.

## Consequences
Good, bad, and what we must now remember.
```
