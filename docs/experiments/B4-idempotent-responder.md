# B4. Duplicate notifications from a non-idempotent responder

- Date run: 2026-10-24
- Git commit (break): tag `break/b4-naive-responder` (`d3af5ae`)            Git commit (prove): `d78ff5d` (M6 branch)
- Environment: local
- Machine: Intel Core Ultra 5 225H (14 logical cores), 15 GB RAM, Windows 11, .NET SDK 10.0.401, PostgreSQL 17.11 and Redis 8.10.2 in Docker (Testcontainers)

## Hypothesis

A response job runs again whenever its Worker dies before marking it done: that's what at-least-once execution means. If the steps aren't safe to repeat, every retry repeats their side effects. We expect:

1. **Duplicate notifications** for crashes that happen after notifying.
2. **One notification per role, not per person**, even without any crash: the naive responder loops over roles, so someone who is both `admin` and `security_admin` gets two.
3. **A subtler bug:** a crash between the PostgreSQL revoke and the Redis write. The retry finds nothing left to revoke, so it also writes nothing to Redis. A session whose status was cached as "active" keeps passing the session check until that cache entry expires, up to 60 s. That's exactly the window M3 worked to close.

Idempotent steps should give exactly one delivery per (anomaly, person) and no stale cache, whatever the crash point.

## Setup

- One org with four users: an owner, a plain admin, someone who is both admin and security admin, and the victim. The default policy notifies `owner`, `admin` and `security_admin`, so **3 people** should hear about each anomaly.
- **100 anomalies** about the victim, each with its own live session cached as "active" in Redis, and a `responded` decision, so each gets a revoke job.
- Each job **crashes once**, cycling through the three crash points: after revoking, after writing Redis, after notifying. The crash is a thrown exception from the test's fault injector, and nothing records it, as if the process had been killed. A fake clock then moves past the 60 s lease, the job is claimed again, and it runs to completion.
- Both runs use the same test harness (`ResponseHarness`, `BreakB4ResponderCrashTests.RunAsync`) against a fresh database cloned from the migrated template.

## Commands

    scripts/experiments/b4-responder-crashes.sh

The script checks out the tag into a temporary git worktree, runs `Break_the_naive_responder_duplicates_notifications_after_a_crash` there, then runs `Prove_idempotent_steps_deliver_each_anomaly_once_per_person_despite_crashes` at the current commit, and prints what each test reported. It takes about 40 s.

## Results: break

    naive: Outcome { Anomalies = 100, Notifications = 532, Expected = 300, Duplicates = 232, StaleCache = 34 }

| Metric | Value |
| --- | --- |
| Notifications delivered | **532** (expected 300) |
| Duplicates | **232** |
| Revoked sessions still cached "active" | **34** of 100 |

The numbers decompose exactly:

- Every run sends 4 notifications (owner 1 + admin role 2 + security_admin role 1): 100 × 4 = 400. That's **100 duplicates from role overlap alone**, with no crash involved.
- 33 jobs crashed after notifying and notified again on retry: 33 × 4 = **132 more**.
- 34 jobs crashed right after the PostgreSQL revoke: **34 stale cache entries**, one per crash.

## Results: prove

    idempotent: Outcome { Anomalies = 100, Deliveries = 300, Rows = 6, Expected = 300, Duplicates = 0, StaleCache = 0 }

| Metric | Value |
| --- | --- |
| Deliveries (`SUM(count)`) | **300** (expected 300) |
| Duplicates | **0** |
| Revoked sessions still cached "active" | **0** |
| Inbox rows | 6: 3 people × 2 hour-long groups (the fake clock advances 61 s per job, so 100 jobs span ~100 minutes) |

## What fixed it

| Bug | Fix |
| --- | --- |
| Retry notifies again | Notifying commits a `notified_at` marker on the job **in the same transaction**; a retry sees the marker and skips the step. `UNIQUE (anomaly_id, recipient_user_id)` is the backstop. |
| One notification per role | Recipients are `SELECT DISTINCT` users across the notify roles. |
| Stale "active" in Redis | Redis is re-marked on every run from `sessions.revoked_by_anomaly_id`, i.e. *everything this anomaly revoked*, not what this run's UPDATE happened to return. Writing "r" twice is harmless. |
| Two Workers on one job (lease expired mid-run) | Marker checks read the job row `FOR UPDATE`, so the second Worker waits, then sees the marker. Tested separately. |

## Evidence

- Mutation checks on the prove version: ignoring the `notified_at` marker, dropping `DISTINCT`, and re-marking Redis only on the first attempt each make tests fail (journal M6).
- The "crash after any step" theory test (`ResponseIdempotencyTests`) checks the full end state after a crash at each point: sessions, Redis, notifications, job status, `responded_at`.

## Conclusion

At-least-once execution is only safe with idempotent steps. The naive responder over-delivered by 77 % (532 vs 300). It also did something worse and quieter: in a third of the crashes it left revoked sessions usable for up to 60 s, undoing M3's "revocation is immediate". With effect markers committed atomically with each effect, distinct recipients, and a re-mark derived from durable state, the same 100 crashes produced exactly the expected deliveries and no stale cache.

## Threats to validity

- Crashes are simulated with an exception at three chosen points, not by killing a process at random instructions. A real kill can land *inside* a step; each step is one transaction (or an idempotent Redis write), so that case reduces to "the step didn't happen", which these runs cover.
- One Worker at a time, apart from the separate two-Worker test.
- In-app notifications only. An external channel (webhook, email) can't be made exactly-once this way: the receiver would have to deduplicate (SPEC §10.4 stretch).
- The audit step (M7) isn't included yet.
