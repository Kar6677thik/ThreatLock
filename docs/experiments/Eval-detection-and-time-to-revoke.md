# Evaluation: false positives, recall and time to revoke

- Date run: 2026-10-25
- Git commit: M9 branch (`feat/m9-simulator-evaluation`); the replay "v1" run was before the D3 cold-start change, "v2" after (commit "Revisit D3's cold start…")
- Environment: local. The replay is offline (ADR-0006). The live harness ran against the local stack: the API and Worker built in Release with Development settings, PostgreSQL 17.11 and Redis 8.10.2 in Docker Compose, and the Worker warm (already running, live Tor list loaded).
- Machine: Intel Core Ultra 5 225H (14 logical cores), 15 GB RAM, Windows 11, .NET SDK 10.0.401
- The home-server re-run is part of M10.

This is the evaluation SPEC §16 asks for: how often ThreatLock is wrong (false positives on a labelled dataset), how often it misses (recall), and how fast the loop closes (time to revoke).

## Part 1. False positives and recall (replay harness)

### Setup

The Simulator generates **1,000 benign and 200 malicious scenario instances** with seed 42: 2,908,713 events with timestamps spanning about two weeks. It replays them through the real Core detectors (D1–D5) and policy evaluator.

- **State:** in-memory detector state, fresh for each instance.
- **Baselines:** D3's baseline is folded every event-time hour, exactly as the Worker's `UserBaselineStore` does it.
- **Decisions:** each anomaly is decided once, when its dedupe key is first seen.
- **Speed:** the whole replay takes about 15 s.

The evaluated org uses the default policy plus its corporate VPN's egress networks in `trustedNetworks`. That's an org that has done the one piece of setup Break B3 showed matters.

| Scenario (SPEC §16.1) | Label | What it does |
| --- | --- | --- |
| office_worker | benign | Two weeks of workdays from Bengaluru, 20–60 reads a day |
| traveller | benign | A week in Bengaluru, then London 11–13 h later |
| corporate_vpn | benign | VPN exit flips between Bengaluru and Frankfurt every few minutes |
| mobile_user | benign | New carrier IP every few minutes, around south India |
| power_user | benign | A daily 30–45 minute burst at ~50 reads/min (normal, σ 8, clipped to 30–70) |
| new_laptop | benign | A week on one laptop, then normal use on a new one |
| new_laptop_export | benign | The same, exporting 5 min after the first login: **an expected false positive** |
| tor_login | malicious | A login through a Tor exit |
| stolen_session_replay | malicious | The victim's token used minutes later from London, New York or São Paulo, on another machine |
| scraper | malicious | 250–350 reads/min for three minutes |
| new_device_export | malicious | A login on a never-seen device, an export 2 min later |
| refresh_token_reuse | malicious | The same refresh token used by two parties |

**Definitions** (SPEC §16.1, unit = one scenario instance):

- **False-positive rate:** benign instances with any anomaly decided `responded`, ÷ benign instances.
- **Notified false positives:** reported separately.
- **Recall:** malicious instances where an *expected* detector reached `notified` or `responded`, ÷ malicious instances.
- **Precision:** responded instances that were malicious, ÷ all responded instances.

### Commands

    dotnet run --project src/ThreatLock.Simulator -c Release -- replay --seed 42 --out artifacts/replay.json
    dotnet run --project src/ThreatLock.Simulator -c Release -- dataset --out artifacts/dataset.jsonl   # the dataset itself, if wanted

### Results: v1, the first run

| Metric | Value |
| --- | --- |
| False-positive rate | **28.2 %** |
| Recall / recall (responded) | 100 % / 100 % |
| Precision | 41.5 % |
| False positives by detector | scraping 140, new_device_export 142 |

**140 of 143 power users were signed out by D3.** On day one there is no trusted baseline (fewer than 30 active minutes), so the 60-reads-a-minute floor applies, and a ~50±8/min burst crosses it within the first burst. Once the baseline is learnt (μ ≈ 50, σ ≈ 8, threshold ≈ max(60, 82) = 82), the same user is fine. The false positives came entirely from the cold start.

### The change (SPEC §9.3: defaults are revisited after the first evaluation)

Until a user's baseline is trusted, a D3 signal above the floor but below 3× the floor is **Low**. That's below scraping's default `minSeverity` (medium), so it's recorded as `observed` (`below_min_severity`) and nobody is signed out. A burst over 3× the floor (180/min) is still High and still responded to. Real scrapers (250–350/min) are unaffected.

The cost is that a *slow* scraper (61–180/min) on a brand-new account is only observed until a baseline exists. That's recorded in SPEC §8.2.

### Results: v2, after the change

    Seed 42: 1000 benign + 200 malicious instances, 2,908,713 events, replayed in 17.0 s

| Metric | Value |
| --- | --- |
| **False-positive rate** | **14.3 %** (143 / 1,000) |
| False-positive rate excluding the expected `new_laptop_export` | **0.1 %** (1 / 858) |
| Notified false positives | 0 % |
| **Recall** | **100 %** (200 / 200), all responded |
| Precision | 58.3 % |
| False positives by detector | new_device_export 142, scraping 1 |

| Scenario | Label | Instances | Signed out | Caught |
| --- | --- | --- | --- | --- |
| office_worker | benign | 143 | 0 | |
| traveller | benign | 143 | 0 | |
| corporate_vpn | benign | 143 | 0 | |
| mobile_user | benign | 143 | 0 | |
| power_user | benign | 143 | **1** (scraping) | |
| new_laptop | benign | 143 | 0 | |
| new_laptop_export | benign | 142 | **142** (new_device_export) | |
| tor_login | malicious | 40 | 40 (tor) | 40 |
| stolen_session_replay | malicious | 40 | 40 (session_hijack) | 40 |
| scraper | malicious | 40 | 40 (scraping) | 40 |
| new_device_export | malicious | 40 | 40 (new_device_export) | 40 |
| refresh_token_reuse | malicious | 40 | 40 (session_hijack) | 40 |

### Reading these numbers honestly

- **The headline 14.3 % is mostly the dataset's composition.** One benign scenario in seven is "a new laptop that exports five minutes after its first login". D4 can't tell that from an attacker, by design: it's the same behaviour. In a real org that event is far rarer than one in seven, so the real-world rate depends on how often people migrate. This is the base-rate point from concepts.md §3.4. The per-scenario table is the useful view.
- **D4's precision on this dataset is 22 %** (40 true vs 142 false). An org that migrates often can set D4 to `notify`. ThreatLock's default stays `respond`, because "new device, take everything, fast" is the account-takeover pattern D4 exists for.
- **The one remaining power-user false positive** is a burst above the warm baseline's μ + 4σ: a genuine statistical tail.
- **100 % recall on a synthetic dataset is not 100 % in the wild.** Each malicious scenario is the attack its detector was built for. What it does prove is that nothing in the pipeline (dedupe, decision order, policy defaults, trusted networks) loses those detections. A CI test replays a smaller version of this dataset on every build to keep it that way.

## Part 2. Time to revoke (live harness)

### Setup

The Simulator registers an org, then runs **200 attacks of each kind, one after another, each against a fresh user**:

- **tor (D1):** the user's password is used from a real Tor exit (from the live list). t0 is the moment the login is sent.
- **hijack (D5):** the victim signs in from India and uses the app; the thief replays the token from the UK, with another device id and browser. t0 is the moment the thief's first request is sent.

From t0, the stolen token polls `GET /api/me` every 50 ms; **t1 is the first `401`**. That's the headline number, as seen by the attacker (SPEC §16.2). The server-side stages come from each anomaly's detail in the admin API (detected, sessions revoked), on the same machine and clock.

### Commands

    docker compose -f deploy/compose/docker-compose.yml up -d
    dotnet run --project src/ThreatLock.Api -c Release --launch-profile http
    dotnet run --project src/ThreatLock.Worker -c Release
    dotnet run --project src/ThreatLock.Simulator -c Release -- live --base-url http://127.0.0.1:5080 \
        --sim-key dev-only-simulator-key-change-me --kind tor --attacks 200 --out artifacts/live-tor.json
    # and the same with --kind hijack

### Results

**D1, Tor login:** 200 / 200 revoked, 46 s total.

| Measured from t0 | p50 | p95 | p99 | max | mean |
| --- | --- | --- | --- | --- | --- |
| Anomaly detected (server) | 118 ms | 154 ms | 173 ms | 185 ms | 118 ms |
| Sessions revoked (server) | 126 ms | 162 ms | 188 ms | 206 ms | 126 ms |
| **Client sees `401`** | **176 ms** | **199 ms** | **202 ms** | **255 ms** | 162 ms |

**D5, replayed token:** 200 / 200 revoked, 48 s total.

| Measured from t0 | p50 | p95 | p99 | max | mean |
| --- | --- | --- | --- | --- | --- |
| Anomaly detected (server) | 76 ms | 113 ms | 120 ms | 124 ms | 76 ms |
| Sessions revoked (server) | 86 ms | 122 ms | 133 ms | 139 ms | 85 ms |
| **Client sees `401`** | **132 ms** | **142 ms** | **193 ms** | **202 ms** | 120 ms |

**Requests the attacker got served before the `401`:**

- **Tor:** 1–2 polls (mean 1.6).
- **Hijack:** 2–4, counting the thief's first request (mean 2.8).

**The Worker's own metrics** (`/metrics` on port 9464) after both runs:

- `tl_anomalies_total`: tor/responded 200, session_hijack/responded 200, impossible_travel/notified 200 (the UK hop).
- `tl_response_job_attempts_total{outcome="succeeded"} 600`; `tl_stream_lag 0`.
- `tl_time_to_revoke_seconds`, from the anomaly's first event to revocation: mean 141 ms (tor) and 98 ms (hijack).

### Where the time goes

- **Event → detected is most of it** (~75–120 ms). The Worker *polls* the Redis stream every 100 ms, because StackExchange.Redis can't issue a blocking `XREADGROUP` on its shared connection (M4). That poll interval is the single biggest term. Tor login is slower than hijack because the login itself (password hashing, session creation) sits between t0 and the event.
- **Detected → revoked is ~8–10 ms:** the job is created in the anomaly's transaction and LISTEN/NOTIFY wakes the orchestrator at once (M6).
- **Revoked → client sees 401 is ~50 ms:** the client's own poll interval, plus the Redis `r` marker being read on the next request.
- **Earlier numbers were the measuring tool, not ThreatLock.** B2's bash script reported p50 506 ms for the same hijack attack. Its ~330 ms per-poll overhead (curl plus Python on Windows) dominated, and the in-process client removes it.

## Conclusion

On a labelled dataset of 1,200 instances, ThreatLock caught every attack and signed out no benign user except:

- the deliberately included legitimate-migration export, which D4 cannot and should not distinguish;
- one power user in the statistical tail.

The first evaluation run found a real design problem (cold-start scraping false positives on 98 % of power users), and a one-line severity rule fixed it without losing recall. That's the reason to measure before declaring victory.

A stolen session is revoked, as seen by the attacker, in **p95 199 ms (Tor) and 142 ms (replayed token)**. The attacker typically gets one or two responses.

## Threats to validity

- **Synthetic dataset.** Scenario parameters are chosen by us, and the attacks are the textbook cases each detector targets. Recall on novel attacks is unknown. Benign behaviour is simpler than real life (no shared computers, no browser extensions changing user agents).
- **Composition drives the headline FP rate**, so read the per-scenario table.
- **The live harness ran on one machine** (client, API, Worker and databases all local) with a warm Worker. Network hops on the home server (M10) will add latency; re-running there is part of M10.
- **Sequential attacks.** Under load (many simultaneous anomalies) queueing would add time. Throughput wasn't measured here.
- **Timing granularity.** 50 ms polling bounds the client-observed resolution, so t1 is accurate to within one poll.
