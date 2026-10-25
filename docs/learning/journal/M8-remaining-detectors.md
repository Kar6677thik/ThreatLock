# M8. Remaining detectors

- Dates: 2026-10-24 → 2026-10-25
- PR(s): M8 PR
- Spec sections: §8.2 D3, D4, D5 (as-built rows added), §6.8 devices, §9.1 policy example, §9.3 defaults, §10.3 last-owner guard, §12 `user_devices` and `user_baselines`, §15 Breaks B2 and B3
- Concepts: [3.1 rules vs baselines](../concepts.md#31-rules-vs-baselines), [3.2 EWMA](../concepts.md#32-mean-standard-deviation-z-score-ewma), [3.4 false positives](../concepts.md#34-false-positives-false-negatives-precision-and-recall), [3.6 sliding windows](../concepts.md#36-sliding-windows-on-event-time), [3.7 session fingerprints](../concepts.md#37-session-fingerprints)
- Experiments: [B2 report](../../experiments/B2-cookie-replay.md), [B3 report](../../experiments/B3-vpn-false-positive.md)

## Goal

The three detectors that complete the set:

- **D3 scraping:** reading far faster than this user normally does.
- **D4 new device + export:** a never-seen device grabbing everything soon after its first login.
- **D5 session hijack:** refresh-token reuse, or a session suddenly used from another machine.

Each one plugs into the existing pipeline: decision, response, audit. Done when each is proven through the real API and Worker, Break B2 shows a replayed token being revoked, and Break B3 shows the VPN false positive and its fix in numbers.

## What I did, in order

1. **Core contract additions:**
   - `IDetectorState` gains a sliding window counted on event time (`CountInWindowAsync`, idempotent per member) and set-once expiring values.
   - `IUserBaselines` provides baselines, with in-memory fakes for both.
   - `DetectorIds.All` gains the three new ids, with display names.
2. **D3 `ScrapingDetector`:** reads per user per minute against `max(floor, μ + k·σ)`; cold start uses the floor until 30 active minutes. **`Ewma.Update`** is pure and caps outliers.
3. **D4 `NewDeviceExportDetector`:** a mark set on a login with `newDevice: true`, then an export or more than 50 distinct notes read within 30 minutes of it.
4. **D5 `SessionHijackDetector`:** (a) refresh reuse is Critical; (b) a fingerprint change (device id + `UserAgentFamily`) is High. UA families are tested on real Chrome, Edge, Firefox, Safari, iOS, Android and curl strings.
5. **Policy:** defaults for all three (respond; D3 at medium, D4 and D5 at high) and validator ranges for their thresholds. **24 unit tests** for D3–D5, EWMA and UA families.
6. **Infrastructure:**
   - Redis implementations: a sorted set under `MULTI` for the window, `SET NX EX` for values.
   - Migration `AddUserDevicesAndBaselines`.
   - `UserBaselineStore`: a cached read path, plus an hourly fold of complete minutes behind a watermark under an advisory lock.
   - Anomalies keep at most **100 event ids**: a scraper at 300 reads a minute would otherwise grow one row without bound.
7. **API: devices at login.** One upsert statement returns "inserted" and "the user had other devices", and the login event carries `newDevice`. A user's first device is never "new".
8. **Worker:** registers D3–D5 and a `BaselineUpdater`, and passes baselines into the detection context.
9. **Found while running the old tests (see below): the responder could lock an org's only owner.** It now never locks the last unlocked owner. Their sessions are still revoked, and the audit entry records `lockSkipped: "last_owner"` with the lock state read back from the database.
10. **Integration tests** (9 end to end and 2 Redis):
    - D3 cold-start scraping revoked, and an ongoing scrape capped at 100 event ids.
    - The baseline learnt from 30 seeded minutes (mean 10, σ 0), with a rerun changing nothing.
    - D4 fires on a second device's export, and not on a first device's.
    - D5 fingerprint change revoked; refresh reuse is Critical and locked; the last owner is not locked.
    - Policy tuning of the new detectors, and validation.
    - The Redis window slides and counts each member once; set-once values expire.
11. **UI:** the policy screen lists D3–D5 with their thresholds.
12. **Mutation checks:** 6 of 6 caught (the sixth only after adding a real-Redis test, below).
13. **Break/Prove B3** as a replay: 500 VPN users and 100 attacks, under four policies.
14. **Break/Prove B2** on the real stack: 10 trials each with D5 off and with the default policy.
15. **Browser check** of the hijack anomaly and the policy screen.

## Decisions

| Decision | Alternative | Why |
| --- | --- | --- |
| Windows counted on event time in a Redis sorted set keyed by event id | `INCR` per minute bucket; server clock | Event time makes replay identical to live traffic (ADR-0006). Members make a redelivered event count once; buckets would double-count it. |
| D3 signals on every event above the threshold, capped at 100 event ids | Signal only on the crossing event | Signalling only at the crossing loses the detection if that one event's processing crashed and was redelivered after more reads. The cap keeps rows bounded. |
| Baseline learning caps minutes above the current threshold | Learn every minute as is | Otherwise one scraping burst (which D3 just flagged) would raise the baseline for every future burst. Slow "training" stays a documented weakness. |
| Baseline fold behind a per-user watermark, under an advisory lock | Recompute from scratch each hour | Idempotent and cheap. Two Workers can't fold the same minutes twice. |
| "New device" decided by the API at login and sent in the event | The detector keeps its own "seen devices" set | PostgreSQL is the source of truth and survives a Redis flush. One upsert statement decides it without races. |
| A user's first device is never "new" | Every first-seen device is new | Otherwise every new account's first export would be a High anomaly, and D4 would just be onboarding noise. An attacker on a stolen account is, by definition, *another* device. |
| Fingerprint = device id + UA family (browser/OS) | Full UA string; IP | Full strings change on every browser update; IPs change on every phone. Families change when the machine changes. |
| Refresh reuse stays Critical and so locks under the default policy | Lower it to High | Two parties holding one refresh token is the strongest theft signal there is. The cost is one admin unlock. |
| **Never lock the last unlocked owner** | Allow it | Only owners and security admins can unlock. Locking the last owner would lock the org out of its own controls, a self-inflicted denial of service. Sessions still die. |
| B3 as a replay in Core tests | Through the live stack | The scenario needs hours of event time per user. Replay is exactly what ADR-0006 is for, and it's deterministic (seed 42). |
| B2 with detectors switched off by policy as the Break | A git tag of pre-M8 code | The same build for both runs isolates the variable. Pre-M8 had no D5, which is what "off" reproduces. |

## Commands I ran

    dotnet ef migrations add AddUserDevicesAndBaselines --project src/ThreatLock.Infrastructure \
        --startup-project src/ThreatLock.Infrastructure --output-dir Persistence/Migrations
    dotnet test                                          # 275 passed (122 unit + 153 integration)

    # mutations, run against committed code (see "What broke"):
    #   a user's first device counts as new            → 1 integration test fails
    #   fingerprint uses the full user agent           → 2 unit tests fail
    #   EWMA without the outlier cap                   → 1 unit test fails
    #   no last-owner guard                            → 1 integration test fails
    #   no 100-event-id cap                            → 1 integration test fails
    #   Redis window never trimmed                     → 0 at first; 1 after adding RedisDetectorStateTests

    B3_REPORT=... dotnet test --project tests/ThreatLock.Core.Tests -- --filter-class "*BreakB3VpnReplayTests"
    scripts/experiments/b2-cookie-replay.sh              # ~3 min; API + Worker running
    cd web && npm run lint && npm test && npm run build  # 27 tests

## What broke / surprised me

- **The new detectors found a design hole in M6.** An old test (refresh reuse, then an admin action) started failing. Reuse is now D5's Critical signal, the default policy locks at critical, and the user who reused their token was the org's **only owner**. Their sessions died mid-test, and in real life nobody could have unlocked them. Hence the last-owner guard: a real fix found by an unrelated test failing for the right reason.
- **I destroyed my own uncommitted work with a mutation run.** The mutation loop restored each file with `git checkout -- file`. That's fine for committed code, but the M8 changes weren't committed yet, so three files were reset to main: `SessionService.cs` (device tracking), `ResponseExecutor.cs` (the last-owner guard) and `AnomalyStore.cs` (the event-id cap). Worse, the two new files were untracked, so `git checkout` couldn't restore them and they **kept** their mutations: the full-UA fingerprint in D5, and no outlier cap in EWMA. The edit scripts were still on disk, so everything was re-applied and checked line by line against the diff, then the suite run (271 green) and committed *before* rerunning the mutations. Those numbers are the ones above. Rule from now on: **commit before mutating; mutate only what git can restore; check `git diff --quiet` after each mutation.**
- **An in-memory fake can hide a bug in the real thing.** Removing the trim from the *Redis* window survived every test, because the unit tests use the (correct) in-memory state. A small test against real Redis now catches it.
- **Docker Desktop had stopped overnight.** All integration tests failed in the fixture with `DockerUnavailableException`; starting Docker fixed it. The troubleshooting table already says so, and it was still worth a minute of confusion.
- **My own test was wrong, not the detector.** The first D4 bulk-read test produced only 40 distinct notes, under the 50 threshold. Counting by hand found it.

## Numbers

| Metric | Value | Conditions |
| --- | --- | --- |
| B2 break: thief still working after 15 s | **10 / 10** trials, ~44 requests each | D5 and D2 off by policy |
| B2 prove: time to revoke p50 / p95 / max | **506 / 869 / 869 ms** | default policy, 10 trials, ~300 ms client poll resolution |
| B2 prove: requests served to the thief | 1 (9 trials), 2 (1 trial) | |
| B3 break: VPN users signed out | **499 / 500 (99.8 %)** | replay, D2 respond, no trusted networks |
| B3 prove: false positives / recall | **0 % / 100 %** | VPN CIDRs trusted |
| B3 default without the fix: notified FPs | 99.8 % | D2 notify, no trusted networks |
| Mutation checks | 6 of 6 caught | after adding the Redis test |
| Tests | 275 .NET (122 unit + 153 integration), 27 frontend | all green |

## Browser check

As the B2 prove org's owner:

- **Anomalies:** each victim has *Session hijack (D5), high, responded* and *Impossible travel (D2), medium, notified*.
- **Hijack detail:** *responded (mode_respond), judged by policy v0*.
  - Timeline: *revoke_sessions: succeeded after 1 attempt(s) · 1 session(s) revoked · Admins notified*.
  - Evidence: `Chrome/Windows` → `Firefox/Linux`, `victim-device-…` → `thief-device-…`.
- **Policy:** the screen shows the new threshold fields (reads/min floor, window after first login, distinct notes).

## What I'd explain in an interview

The last three detectors cover three ways of abusing a session:

- **Taking too much:** D3 compares reads per minute with a per-user EWMA baseline, capping outliers so a burst can't become normal.
- **Taking everything from somewhere new:** D4 is an export soon after a login from a device that's new for the user. The API decides "new" from PostgreSQL at login, not the detector.
- **Using someone else's session:** D5 is refresh-token reuse, or a session whose device id and browser family suddenly change.

All counting is on event time, so the replay harness produces exactly what live traffic would. A replayed stolen token was revoked in about half a second. On the false-positive side, a replay of 500 VPN users showed that letting impossible travel *respond* would sign out 99.8 % of them, and that trusting the VPN's egress ranges brings that to zero without missing a single outside attack. Building these also exposed that a Critical response could lock an org's only owner, so the responder now never locks the last owner.

## Open threads

- The labelled dataset with all scenarios, FP rate and recall for every detector, and p95 time to revoke measured in-process (M9). B2 and B3 re-run there.
- `tl_*` metrics for detectors and responses (M9).
- Per-org thresholds for the baseline cap (it uses default D3 settings today).
- D4 relies on client-chosen device ids; a server-issued device cookie would be stronger (stretch).
