# 0006. Two evaluation harnesses: offline replay and live HTTP

- Status: Accepted
- Date: 2026-10-22
- Milestone: M9

## Context

We must report the false-positive rate on a labelled dataset and the p95 time to revoke. Realistic benign scenarios span hours or days (a flight, two weeks of baseline). Time to revoke must include real network hops, queues and databases.

## Decision

- **Replay harness:** the Simulator generates labelled scenarios (seeded, reproducible) and feeds events straight into the Core detectors and policy evaluator with an in-memory state store. Detectors use event timestamps, never wall-clock time, so a two-week scenario replays in milliseconds. Used for FP rate, recall and precision.
- **Live harness:** the Simulator runs attacks over HTTP against a running stack (local or home server) and measures client-observed time to revoke. Used for latency only.

## Alternatives considered

- **Everything over HTTP with a fake-clock header:** pollutes the production code path with time travel and makes latency numbers meaningless.
- **Everything offline:** no honest latency number.

## Consequences

- Detectors must be written against an `IDetectorState` abstraction and event time from day one.
- A bug that exists only in the Redis-backed state store would not show up in replay; integration tests cover that store separately.
