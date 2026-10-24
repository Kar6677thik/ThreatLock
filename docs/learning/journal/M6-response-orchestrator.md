# M6. Response orchestrator

- Dates: 2026-10-24 → 2026-10-24
- PR(s): M6 PR
- Spec sections: §5.2 life of a stolen session, §10 response orchestrator (all), §12 `response_jobs` and `notifications`, §13 inbox, jobs and unlock endpoints, §14 Notifications and Jobs screens, §15 Break B4
- Concepts: [2.5 SKIP LOCKED and leases](../concepts.md#25-postgresql-as-a-job-queue-for-update-skip-locked-and-leases), [2.6 backoff and jitter](../concepts.md#26-retries-exponential-backoff-and-jitter-fg-17), [2.8 effect markers](../concepts.md#28-effect-markers-making-a-multi-step-job-idempotent-fg-18), [2.9 LISTEN/NOTIFY and graceful shutdown](../concepts.md#29-listennotify-polling-and-graceful-shutdown), [4.3 notification grouping](../concepts.md#43-notification-deduplication-and-grouping), [5.2 advisory locks](../concepts.md#52-advisory-locks)
- Experiment: [B4 report](../../experiments/B4-idempotent-responder.md)

## Goal

M5 *decided*; M6 *acts*. A `responded` anomaly gets its user's sessions revoked (and, if the policy says so, the account locked); `responded` and `notified` anomalies reach each admin's inbox **once**, even when the Worker crashes mid-job and the job runs again. Done when the whole loop works through the real API and Worker, every step is proven safe to rerun after a crash at any point, and Break B4 shows the difference in numbers.

## What I did, in order

1. **Core: the response plan and backoff** (`ResponsePlanner`, `ResponseBackoff`, `JobActions`, `JobStatuses`). `responded` becomes `revoke_sessions`, or `revoke_and_lock` if the policy says so or the severity reaches `lockOnSeverity`. `notified` becomes `notify`. Anything else gets no job. Backoff is `min(2^attempts, 60) s` plus up to 20 % jitter; 5 attempts, then dead. 14 unit tests. *Why first:* pure rules, so the rest is plumbing around tested logic.
2. **Migration `AddResponseJobsAndNotifications`:** `response_jobs` (`UNIQUE (anomaly_id)`), `notifications`, the user lock columns, `sessions.revoked_by_anomaly_id`, `anomalies.responded_at`.
3. **The job is created in the anomaly's transaction.** `AnomalyStore.UpsertAsync` now opens a transaction: insert or update the anomaly; if it's new and the plan isn't null, insert the job and `pg_notify`; commit. Either both exist or neither does.
4. **The queue** (`ResponseJobStore`): claim with `FOR UPDATE SKIP LOCKED` and a 60 s lease (also reclaiming expired leases), complete, and fail with backoff or dead. Time comes from `TimeProvider`, not SQL `now()`, so tests can move past leases.
5. **The Worker loop** (`ResponseOrchestrator`): claim, run, repeat; when idle, wait on `LISTEN response_jobs` or the 250 ms poll.
6. **The deliberately naive executor**, committed and **tagged `break/b4-naive-responder`**: it revokes, writes Redis from what the UPDATE returned, inserts one notification per *role* membership, then finishes. Nothing is guarded.
7. **The test harness**: a fresh database per test, cloned in milliseconds from a migrated template (`CREATE DATABASE ... TEMPLATE`), so the shared Worker can't claim the jobs. A fake clock, and a fault injector that "kills the Worker" after a chosen step. Queue tests: one job per anomaly, six concurrent claimers never share a job, lease reclaim, backoff to dead.
8. **Break B4:** 100 jobs, each crashed once (cycling through three crash points), then reclaimed after the lease. Result: **532 deliveries instead of 300, and 34 revoked sessions still cached "active"**.
9. **Prove B4, the idempotent executor.** Revoke + lock commit with a `revoked_at` marker on the job, notify commits with `notified_at`, and both markers are read `FOR UPDATE`. Redis is re-marked every run from `revoked_by_anomaly_id`. Recipients are `SELECT DISTINCT`. Repeats are grouped per (recipient, subject user) for an hour under an advisory lock, and `UNIQUE (anomaly_id, recipient_user_id)` is the backstop. The migration `MakeResponseStepsIdempotent` backfills and de-duplicates rows left by the naive version before adding the unique index. Same 100 crashes: **300 / 300, 0 duplicates, 0 stale**.
10. **Crash-after-each-step tests** (SPEC §17): a theory over "no crash" and each crash point, checking the whole end state. Also tested: two Workers running one job at once, grouping and its one-hour end, the cutoff sparing a fresh session, and "a retry after unlock doesn't lock again".
11. **API:**
    - Login answers `403 account_locked` for a locked account, but only after a correct password. Refresh refuses locked users.
    - `POST /api/admin/users/{id}/unlock`.
    - The own-inbox endpoints, with read and read-all.
    - Response jobs list and retry, dead jobs only.
    - The anomaly detail gains its response timeline.
12. **Graceful release:** a Worker stopping mid-job hands the job back, without counting the attempt (see "surprised me").
13. **UI:**
    - An unread badge, polled every 30 s.
    - A Notifications inbox, with grouped repeats shown as ×N.
    - A Jobs screen with Retry.
    - Lock status and Unlock on Users.
    - The response timeline on the anomaly page.
    - Sign-in explains a lock.

    7 new frontend tests.
14. **Mutation checks:** 4 of 4 caught (below).
15. **Browser check** against the real API, Worker and SPA (below).

## Decisions

| Decision | Alternative | Why |
| --- | --- | --- |
| Jobs in a PostgreSQL table, created in the anomaly's transaction | Put jobs on the Redis stream; create the job after the anomaly commits | Must never be lost and must commit with the anomaly (ADR-0003). A separate write after commit is the dual-write problem again. |
| `notified` decisions get a job too (action `notify`) | Insert notifications inline in the event processor | Same durability, retries and idempotency as responses, and one code path for "tell the admins". |
| Plan (action + notify roles) frozen on the job | Re-read the policy on each attempt | A retry must do what was decided, not what a later policy edit would decide. |
| Step markers committed with each step's effect | Rely only on each statement being naturally idempotent | Grouping (`count + 1`) and locking aren't naturally idempotent; a marker in the same transaction makes *any* step effect-once. |
| Redis re-marked from `revoked_by_anomaly_id` every run | Re-mark only what this run revoked | That list is empty on a retry, so the cache stayed stale: one of B4's two findings. |
| Unique `(anomaly_id, recipient_user_id)` kept as a backstop | Markers alone | Defence in depth: a future bug in the marker logic still can't open two entries for one anomaly. |
| Group by `created_at` + 1 h, unread only | Sliding window on `updated_at` | A sliding window could hold one entry open forever during a long attack; fixed windows give at most one new entry per hour per subject, and reading an entry closes it. |
| `revoke_and_lock` ignores the cutoff | Same cutoff as `revoke_sessions` | Once the account is closed, a session opened after the detection is as likely to be the attacker's. The marker stops a retry killing sessions after an unlock. |
| Lock checked after the password, `403` with a code | Check first; or answer `401` like a wrong password | Checking first tells anyone "this account exists and is locked". A plain 401 leaves the real user retrying a correct password. |
| Shutdown hands the job back, attempt not counted | Let the lease expire | Every deploy would delay in-flight responses by up to 60 s, and burn attempts. A crash still relies on the lease. |
| Test DB per test via template clone | Pause the shared Worker; filter jobs by test | Cloning takes milliseconds and gives total isolation; the alternatives couple tests to Worker internals. |
| Fault injection through an interface (`IResponseFaultInjector`) | Kill a real process at random | Deterministic: each crash point is hit exactly, every run. A process kill lands *within* a step, which reduces to "the step didn't happen" because each step is one transaction. |
| Audit step (step 4) deferred | Build a minimal audit table now | It's M7's whole subject (hash chain, permissions); the slot and idempotency key are reserved in SPEC §10.2. |
| In-app notifications only (Q1) | A webhook now | A webhook can't share the inbox's transaction, so it can only be at-least-once. Stays a stretch goal. |

## Commands I ran

    dotnet ef migrations add AddResponseJobsAndNotifications --project src/ThreatLock.Infrastructure \
        --startup-project src/ThreatLock.Infrastructure --output-dir Persistence/Migrations
    git tag break/b4-naive-responder                     # on the naive commit
    dotnet ef migrations add MakeResponseStepsIdempotent ...   # then hand-added the backfill/dedupe SQL
    dotnet test                                          # 210 passed (82 unit + 128 integration)
    scripts/experiments/b4-responder-crashes.sh          # Break at the tag vs Prove at HEAD, ~40 s

    # mutations (each reverted with git checkout):
    #   ignore the notified_at marker            → 2 tests fail
    #   SELECT DISTINCT → SELECT                  → 1 fails
    #   cutoff = now for every action             → 4 fail
    #   re-mark Redis only on the first attempt   → 2 fail

    cd web && npm run lint && npm test && npm run build  # 24 tests
    dotnet run --project src/ThreatLock.Api ; dotnet run --project src/ThreatLock.Worker ; cd web && npx vite
    # setup by curl: org with revoke_and_lock, Ben signs in at the office, then via a real Tor exit

## What broke / surprised me

- **The Break found a second bug I wasn't looking for.** B4 was about duplicate notifications. But a crash right after the PostgreSQL revoke meant the retry revoked nothing, so it wrote nothing to Redis. A session cached as "active" kept working for up to 60 s, quietly undoing M3's instant revocation in a third of the crashes. The fix is a general rule: derive repeated work from durable state, not from what this run happened to see.
- **Role overlap alone caused 100 of the 232 duplicates.** No crash needed: one notification per role membership means four for three people. "Per person, not per role" is a Slack lesson for a reason.
- **An older test started failing for the right reason.** "Anomalies are visible only to admins" asserted a Tor-detected member gets `403` on the admin API. From M6 that member's session is revoked, so `401`. The test now uses a bystander. The same thing happened again in the inbox test.
- **A response took over 15 s in one test.** Other tests start and stop their own Workers, and those ran response jobs too. A Worker stopped mid-job left its job "running" until the 60 s lease expired. Two fixes: only the shared test Worker runs responses (`Responses:Enabled`), and, in production code, a stopping Worker hands its job back. A rolling deploy would have hit exactly the same delay.
- **Npgsql positional parameters (`$1`) don't allow two statements in one command.** `INSERT ...; SELECT pg_notify(...)` had to become two commands in the same transaction.
- **`ExecuteScalar` returns `timestamptz` as a UTC `DateTime`, not a `DateTimeOffset`.** The test helpers convert it.
- **The policy cache showed up in the browser check.** The org switched to `revoke_and_lock` (v1), then Ben's Tor login a second later was judged by **v0**, so he was revoked but not locked. The owner's registration event had loaded v0 into the Worker's 10 s cache moments earlier. That's documented behaviour, and the anomaly honestly recorded "policy v0"; the setup now waits 11 s. It went into the troubleshooting table.
- **Concurrent clones of one template database can fail** ("source database is being accessed by other users"), so the fixture clones one at a time. Each clone takes milliseconds.

## Numbers

| Metric | Value | Conditions |
| --- | --- | --- |
| B4 break: deliveries / expected | **532 / 300** (232 duplicates) | 100 jobs, 1 crash each, 3 recipients (one with 2 roles) |
| B4 break: revoked sessions still cached "active" | **34** | the 34 crashes right after the revoke |
| B4 prove: deliveries / expected | **300 / 300**, 0 duplicates, 0 stale | same run at the M6 commit; 6 inbox rows thanks to grouping |
| Tor login → user locked out (login gets 403) | **679 ms** | local dev stack, measured by a curl loop polling every 100 ms, so the true time is slightly less; includes event capture, detection, decision, job claim via NOTIFY and revocation |
| Mutation checks | 4 of 4 caught | |
| Tests | 210 .NET (82 unit + 128 integration), 24 frontend | all green |

A proper p95 time-to-revoke is M9's evaluation; the 679 ms is one observation.

## Browser check

Against the real API, Worker and SPA (Vite):

1. Setup by curl: org with `response.action = revoke_and_lock`. Ben signs in at the office, then through a real Tor exit. A curl loop sees his next login get `403` after 679 ms.
2. In the browser, Ben's sign-in shows *"Your account was locked after suspicious activity. Ask an administrator to unlock it."*
3. The owner signs in. The nav shows **Notifications 1**. The inbox has "Tor exit node: Ben", with no IP in the title.
4. The anomaly page shows *responded (mode_respond), judged by policy v1*, and the timeline *revoke_and_lock: succeeded after 1 attempt(s) · 2 session(s) revoked and account locked · Admins notified · Finished*.
5. Users shows Ben as **Locked (tor)**. After Unlock he's **Active**, with the message *"Unlocked Ben. They can sign in again."* His next login gets `200`.
6. Jobs: *No jobs here. Responses are running normally.* Marking the notification read clears the badge.

## What I'd explain in an interview

Detection and decision happen on the event stream, but the response runs from a PostgreSQL job table. The job is created in the same transaction as the anomaly, so a "responded" anomaly can never exist without someone acting on it. Workers claim jobs with `FOR UPDATE SKIP LOCKED` and a lease, and LISTEN/NOTIFY starts them within milliseconds. Jobs run at least once, so every step must be safe to repeat. I proved that by breaking it first: a naive responder, crashed 100 times, delivered 532 notifications instead of 300, and quietly left a third of the revoked sessions usable for up to a minute. Committing an effect marker in the same transaction as each step, deriving retries from durable state, and notifying distinct people made the same 100 crashes produce exactly 300 deliveries and no stale sessions.

## Open threads

- Audit entry for each response, and for unlocks and policy edits (M7, step 4 of §10.2).
- D3–D5 feed the same orchestrator (M8).
- p95 time to revoke and the response metrics `tl_response_job_*` (M9).
- Webhook notifications, at-least-once with receiver-side dedupe (stretch, Q1).
- The jobs and inbox screens poll; server push isn't needed at this scale.
