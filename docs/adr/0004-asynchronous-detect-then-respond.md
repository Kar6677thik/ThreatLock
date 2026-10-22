# 0004. Asynchronous detect-then-respond, no inline blocking

- Status: Accepted
- Date: 2026-10-22
- Milestone: M4–M6

## Context

We could run detectors inside the request (block the Tor request before it returns data) or after it (let it through, then revoke). Slack's AER responds asynchronously.

## Decision

Detection, decision and response run in the Worker, after the request has been served. The metric we optimise is **time to revoke**. The only inline security action is refresh-token reuse, which is certain, cheap and local to the refresh endpoint.

## Alternatives considered

- **Inline detection on every request:** adds latency to every request; an outage in GeoIP lookups or Redis detector state would break the product; and several detectors (baselines, sequences like "new device then export") need history that isn't ready at request time.
- **Hybrid (inline Tor block at login, async for the rest):** reasonable and a possible stretch goal. Left out so there is one clear pipeline to learn.

## Consequences

- An attacker always gets *some* data before revocation. The size of that window is the headline number, and the report must state it honestly.
- The API stays simple and fast; detectors can evolve without touching request paths.
