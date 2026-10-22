# 0003. Redis Streams for activity events, PostgreSQL table for response jobs

- Status: Accepted
- Date: 2026-10-22
- Milestone: M4 (events), M6 (jobs)

## Context

Two very different flows move work from the API to the Worker:

- **Activity events:** every authenticated request produces one. High volume, cheap to lose one occasionally, must not slow requests down.
- **Response jobs:** a handful per day. Losing one means a compromised session stays alive. Must be created atomically with the anomaly and decision that justify it.

## Decision

- **Events:** the API inserts each event into `activity_events` and then `XADD`s it to the Redis stream `tl:events`. The Worker reads with a consumer group (`XREADGROUP`), acknowledges after processing (`XACK`), reclaims stuck messages (`XAUTOCLAIM`), and moves poison messages to `tl:events:dead` after 5 deliveries. A sweeper republishes rows whose `published_at` is still null. Delivery is at-least-once; consumers are idempotent on event id.
- **Jobs:** `response_jobs` is a PostgreSQL table. Rows are inserted in the same transaction as the anomaly. Workers claim them with `FOR UPDATE SKIP LOCKED` and a lease (`locked_until`), and `LISTEN/NOTIFY` wakes them immediately.

## Alternatives considered

- **PostgreSQL for both:** one fewer moving part, and a fine production choice at this scale. Rejected for learning value: the guide maps this project to Field Guide section 18 (Messaging), and Redis Streams teach consumer groups, acks, pending lists and redelivery directly.
- **Redis for both:** a response job could be lost between "anomaly committed" and "job enqueued" (the dual-write problem), and Redis persistence is weaker than PostgreSQL's.
- **Redpanda/Kafka:** the right tool at company scale, heavy for a shared 8 GB home server. Project 3 is where a log-based broker earns its place.
- **In-process channel inside the API:** events vanish on restart, and the API and Worker could not scale or fail independently.

## Consequences

- Two queue technologies to understand, which is the point.
- The event table doubles as an outbox, so a Redis outage delays detection but does not lose events.
- The time-to-revoke budget includes one Redis hop and one PostgreSQL notify; both are measured.
