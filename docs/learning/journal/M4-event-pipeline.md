# M4. Event pipeline and the first two detectors

- Dates: 2026-10-24 →
- PR(s): M4 PR
- Spec sections: §6.7 simulation, §7 activity events and transport, §8 detection engine (D1, D2, §8.3 dedupe), §13 anomalies API
- ADRs: [0003](../../adr/0003-event-transport-redis-streams-and-postgres-jobs.md), [0006](../../adr/0006-evaluation-replay-harness-and-live-harness.md), [0007](../../adr/0007-client-ip-resolution-and-simulation-header.md), [0009](../../adr/0009-geoip-source-dbip-lite.md)
- Concepts: [2.1 events vs audit](../concepts.md#21-activity-events-vs-audit-logs-fg-2518), [2.2 at-least-once](../concepts.md#22-at-least-once-delivery-and-idempotency-fg-18), [2.3 outbox](../concepts.md#23-transactional-outbox-and-the-dual-write-problem-fg-18), [2.4 Redis Streams](../concepts.md#24-redis-streams-and-consumer-groups), [3.3 haversine](../concepts.md#33-haversine-and-impossible-travel), [3.5 Tor](../concepts.md#35-tor-exit-nodes), [6.5 testing async](../concepts.md#65-testing-asynchronous-systems-fg-23)

## Goal

Detection exists. Every meaningful request becomes an activity event, the event reaches the Worker reliably (at-least-once, through a Redis stream backed by a PostgreSQL outbox), and two detectors turn suspicious events into de-duplicated anomalies: **D1** Tor exit nodes and **D2** impossible travel. Done when that works end to end with real processes and real data, and every failure mode in the pipeline (lost publish, duplicate delivery, crashed consumer, poison message, no internet for the Tor list) has a test.

Decisions and automatic responses are M5 and M6. M4 only *finds* things.

## What I did, in order

1. **Downloaded the real data first.** DB-IP Lite City (60 MB gzipped, 122 MB unpacked, git-ignored) via `scripts/download-geoip.sh`, and checked the Tor bulk exit list (1,217 addresses). *Why first:* the detectors are only as real as their inputs.
2. **Core, pure:** `ActivityEvent` + event types; `GeoInfo` and haversine distance; the detector contract (`IDetector`, `DetectionSignal`, `IDetectorState`, `ITorExitList`) with in-memory fakes; `TorExitDetector` (D1) and `ImpossibleTravelDetector` (D2). Every detector decision depends on the *event's* timestamp, never the clock, so "London 11 hours later" is one line in a test (ADR-0006).
3. **21 unit tests** for geo maths (known city distances, the antimeridian) and both detectors: plausible flights, short hops, accuracy radii, same-instant events, out-of-order redeliveries, failed logins not counting as being somewhere, dedupe keys.
4. **Schema** (`AddActivityEventsAndAnomalies`): `activity_events` (also the outbox: `published_at` null until on the stream, with a partial index of only the unpublished rows), `anomalies` (`UNIQUE (org_id, dedupe_key)`, `event_ids uuid[]`), `tor_exit_snapshots`.
5. **Infrastructure:** `EventPublisher` (insert → `XADD` → mark published; never throws into the request), the sweeper query, `MmdbGeoIpLookup` (memory-mapped, private/CGNAT ranges excluded), `RedisDetectorState`, `RedisTorExitList` + `TorExitListLoader` (atomic `RENAME` swap, PostgreSQL snapshot), `AnomalyStore` (one-statement upsert).
6. **Worker:** `EventConsumer` (pending-first restart, ack after processing, reclaim, dead-letter), `EventSweeper` (the outbox relay), `TorListRefresher` (hourly, snapshot fallback), `RetentionPurger` (30-day purge in batches), `EventProcessor` (runs detectors, upserts anomalies), all wired in a `WorkerApp` builder the tests reuse.
7. **API:** keyed **simulation** middleware (ADR-0007), an arrival-time stamp on every request, `ActivityRecorder` (adds IP, geo, device, UA, request id, simulated flag), events from every auth and notes endpoint, and read-only `GET /api/admin/anomalies[/{id}]`.
8. **Smoke-tested against real data** (`scripts/experiments/m4-detection-smoke.sh`): simulated India → UK → a live Tor exit. Found a serialisation crash (see "What broke"), fixed it, and got D1 and D2 firing on real DB-IP geography.
9. **Integration tests (19 new):** the shared fixture now runs the **real Worker** next to the API, with a fake GeoIP lookup (documentation-range IPs pinned to cities) and a fixture Tor list. Covers event contents, every recorded type, simulation with/without key and disabled, recording failures not failing requests, D1 and D2 end to end, the absence of a false positive (Bangalore → Chennai), tenant isolation and roles on anomalies, the sweeper, duplicate delivery, crash recovery, poison messages, the Tor snapshot, list parsing and retention.
10. **Ran the suite three times** (no flakes) and **mutation-checked** reclaim (2 tests fail without it) and the dedupe guard (1 fails).

## Decisions

| Decision | Alternative | Why |
| --- | --- | --- |
| The event table *is* the outbox; the API publishes inline and a sweeper catches misses | A separate outbox table and relay only | One write, no second table; the fast path keeps detection latency low, the sweeper keeps correctness. |
| Recording an event never fails the request | Fail the request if telemetry fails | Security telemetry must not become an availability risk (SPEC §7.2). Failures are logged loudly instead. |
| Geo looked up in the **API** at capture time and stored on the event | Look up in the Worker | The event then records where the IP was *at that time* (GeoIP data changes monthly), and the Worker needs no 120 MB database. |
| Consumer **polls** every 100 ms instead of `XREADGROUP BLOCK` | Blocking read | StackExchange.Redis multiplexes one connection and doesn't support blocking commands. 100 ms is the price; it's inside the latency budget and measured in M9. |
| Failed messages are just not acknowledged; reclaim retries them | Separate retry queue | One path for "consumer crashed" and "processing failed". Delivery counts come free from `XPENDING`. |
| Copy to the dead-letter stream, *then* ack | Ack, then copy | A crash in between leaves a duplicate dead letter, never a lost message. |
| Group created at position `0` | `$` (only new messages) | Events written before the Worker's first start are still processed. Duplicates are harmless; gaps aren't. |
| Anomaly upsert in one SQL statement (`ON CONFLICT ... DO UPDATE ... RETURNING (xmax = 0)`) | Select, then insert or update | No read-then-write race, and `xmax = 0` tells us whether the row was created. |
| Unknown-email failed logins are **not** events | Record with `user_id = null` (original spec) | Events are per tenant and an unknown email has no tenant. Spec updated. |
| `[JsonIgnore]` on computed properties of `ActivityEvent` | Leave them | They aren't data; and serialising `IPAddress` crashes (see below). |
| Fake GeoIP and a fixture Tor list in integration tests | Real DB-IP file and live list in CI | Deterministic, offline, and the real files are verified by the smoke script instead. |
| Read-only anomalies API now, UI in M5 | Wait for M5 | Lets the pipeline be inspected and tested end to end today. |
| Admin anomalies API not tenant-filtered by EF query filter, but by explicit `org_id` predicate | Add a global filter on anomalies | The Worker writes anomalies for many orgs without a tenant context; an explicit predicate in the (few) API queries is clearer. |

## Commands I ran

    scripts/download-geoip.sh
    curl -s https://check.torproject.org/torbulkexitlist | wc -l      # 1217

    dotnet add src/ThreatLock.Infrastructure package MaxMind.Db
    dotnet ef migrations add AddActivityEventsAndAnomalies --project src/ThreatLock.Infrastructure \
        --startup-project src/ThreatLock.Infrastructure --output-dir Persistence/Migrations
    dotnet ef migrations script AddSessionsAndRefreshTokens -o /tmp/m4.sql     # review the SQL

    dotnet run --project src/ThreatLock.Api
    dotnet run --project src/ThreatLock.Worker
    scripts/experiments/m4-detection-smoke.sh
    docker compose -f deploy/compose/docker-compose.yml exec redis redis-cli XINFO GROUPS tl:events

    dotnet test        # 133 passed (44 unit + 89 integration), three runs
    # mutations: return early in EventConsumer.ReclaimAsync → 2 fail; "WHEN false" in the dedupe CASE → 1 fails

## What broke / surprised me

- **EF merged two indexes into one.** Two `HasIndex` calls on the same column (one partial, one plain) silently became one. Named indexes fix it, and then the snake_case convention *renamed* them (`..._occurred_at1`) until I added `HasDatabaseName`. Lesson: always read the migration SQL.
- **`System.Text.Json` serialised a computed property and crashed.** `ActivityEvent.IpAddress` is a convenience getter returning an `IPAddress`; serialising it reads `ScopeId`, which throws for IPv4. Every request with an IP returned 500. Only running the real app with a real IP found it, since unit tests never serialised an event. Fixed with `[JsonIgnore]`.
- **DB-IP Lite has no accuracy radius.** The code had a fallback for this; the smoke test proved it's always used (8,033 km raw → 7,933 km after subtracting 2 × 50).
- **`head -1` broke a script under `set -o pipefail`.** `head` exits after one line, `curl` gets a broken pipe (exit 23), and pipefail reports failure. `sed -n 1p` reads the whole stream.
- **The Tor exit in the smoke test produced a second impossible-travel anomaly** (London → Stockholm in seconds), correctly marked `high` because the destination is a Tor exit. Two detectors corroborating each other is exactly what M5's decision step will use.
- **A Worker `Program` class clashed with the API's** in the test project. The Worker's `Program` stays internal.
- **CI caught a race in a test, three green local runs didn't.** The sweeper test first asserted "nothing is published yet", but the shared Worker sweeps every 200 ms and on GitHub's faster runner it won (expected 0, got 2). The *precondition* was the bug, not the product. Now the test proves the point directly: the API under test can't reach Redis, so if its event id appears on the stream, the sweeper put it there. Lesson: in tests of asynchronous systems, assert outcomes, never "it hasn't happened yet".
- **Proving a negative needs a marker.** The first draft of the "Chennai isn't impossible travel" test used a Tor login as its "processing finished" marker, which would itself have been impossible travel from Chennai. The marker now comes from a different user (concepts.md §6.5).

## Numbers

| Metric | Value | Conditions |
| --- | --- | --- |
| Tests | 133 .NET (44 unit + 89 integration), 11 frontend | Three consecutive green runs |
| Tor exit list | 1,217 addresses | 2026-10-24 |
| GeoIP database | 122 MB, DB-IP Lite City 2026-10 | No accuracy radius → 50 km assumed |
| Smoke test detections | D2 Bengaluru → London 7,933 km in 0 s; D1 Tor exit (SE), 2 events in one anomaly; D2 London → Tor exit 1,330 km (high) | Local, real data, simulated IPs |
| Consumer group after smoke test | `pending 0`, `lag 0` | Every event read and acknowledged |
| Mutation checks | reclaim off → 2 tests fail; dedupe guard off → 1 test fails | |

Time from request to anomaly is measured properly in M9 (§16.2); in the smoke test the anomalies were present by the first poll.

## What I'd explain in an interview

Every request writes an activity event to PostgreSQL and appends it to a Redis stream; the table doubles as an outbox, so if Redis is down a sweeper publishes the backlog later and nothing is lost. The Worker reads the stream through a consumer group and acknowledges only after processing, so delivery is at-least-once; a crashed consumer's messages are reclaimed, and a message that keeps failing is copied to a dead-letter stream before it's acknowledged. Detectors are pure functions of the event and a small state store, so they're unit-tested with synthetic timestamps, and anomalies are de-duplicated by a unique key in a single upsert, which makes duplicate deliveries harmless. I tested it end to end with the real API and Worker, and against real Tor and GeoIP data, which caught a serialisation crash no unit test would have.

## Open threads

- Decision step and per-org policy: modes, exclusions, trusted networks (M5).
- Automatic response (M6) and audit entries (M7).
- D3–D5 (M8). D5 will consume `refresh_token_reused`, already recorded.
- Metrics: dead letters, stream lag, detection latency (M9).
- `GeoIp:DefaultAccuracyKm` is a guess; revisit with evaluation data (M9).
