# M9. Simulator and evaluation

- Dates: 2026-10-25 → 2026-10-25
- PR(s): M9 PR
- Spec sections: §16 evaluation (all), §17 testing (CI replay, Playwright), §18 metrics, §9.3 defaults revisited, §11.4 independent verify
- ADR: [0006 replay harness and live harness](../../adr/0006-evaluation-replay-harness-and-live-harness.md)
- Concepts: [6.1 percentiles](../concepts.md#61-percentiles-p50-p95-p99-fg-24), [6.6 evaluating a detector](../concepts.md#66-evaluating-a-detector-datasets-labels-and-base-rates), [3.4 base rates](../concepts.md#34-false-positives-false-negatives-precision-and-recall)
- Report: [Evaluation: false positives, recall and time to revoke](../../experiments/Eval-detection-and-time-to-revoke.md)

## Goal

Turn "it works" into numbers:

- a false-positive rate and recall on a labelled dataset;
- a p95 time to revoke over hundreds of real attacks;
- metrics the system reports about itself;
- a browser test of the whole loop.

Done when the evaluation report exists, its numbers are reproducible from a seed or a command, and CI guards them.

## What I did, in order

1. **Fixed a performance trap first:** the in-memory detector state never trimmed its windows. That was fine for unit tests, but quadratic for a replay of millions of events. It now trims like Redis does.
2. **Dataset generator** (`Simulator/Evaluation/Dataset.cs`): the twelve scenario kinds of SPEC §16.1, seven benign and five malicious.
   - Everything comes from one seeded `Random`: ids, times, addresses (from the RFC 2544 benchmarking range) and a Box–Muller normal for power users' read rates.
   - Scenarios are streamed one at a time: the full set is 2.9 million events.
   - The generator plays the API's part: session ids, and `newDevice` with the same "new for a user who has others" rule as `SessionService`.
3. **Replay harness** (`Replay.cs`): each scenario runs through the five real detectors and the policy evaluator, with fresh in-memory state.
   - Anomalies are decided once, at their first dedupe key.
   - `BaselineLearner` folds D3 baselines every event-time hour, exactly like `UserBaselineStore`: complete minutes only, capped.
   - The report gives the FP rate, notified FPs, recall (expected detector, notified or responded), precision, and a per-kind table.
4. **CLI** (`Program.cs`): `dataset`, `replay`, `live`, `audit-verify`.
5. **The first replay (v1): 28.2 % FP.** 140 of 143 power users were signed out by D3's cold-start floor. That's the §9.3 "revisit after the first evaluation" moment, below.
6. **The change:** cold-start D3 bursts above the floor but under 3× it are Low, so observed under the default policy. **v2: 14.3 % FP**, of which 142 of 143 are the expected migration export (0.1 % without it), with recall still 100 %. Committed separately with both numbers in the message.
7. **`ThreatLock.Simulator.Tests`:** a small replay on every build checks that every attack kind is caught, benign kinds stay quiet, the same seed gives the same numbers, and B3's trusted-network guard still works. Also tests percentiles and option parsing.
8. **Live harness** (`LiveHarness.cs`): sequential attacks, one fresh user each. It polls `GET /api/me` every 50 ms, uses nearest-rank percentiles, and reads the server stages from the anomaly detail.
9. **Independent audit verifier** (`AuditVerifier.cs`): downloads the chain and recomputes it with the client's own `AuditChain`. This needed the API to **expose `idempotencyKey`**, which is hashed, so it had to be visible for anyone else to verify.
10. **Metrics:**
    - `ThreatLockMetrics` on `System.Diagnostics.Metrics`, wired into the event publisher, session check, processor, consumer (dead letters, stream lag), orchestrator (attempts and duration) and executor (server-side time to revoke).
    - OpenTelemetry Prometheus exporters: `/metrics` on the API, a listener on 9464 in the Worker.
    - An integration test checks the series exist and that no user id or email appears.
11. **Live runs:** 200 Tor and 200 hijack attacks on the local stack.
12. **Playwright smoke test and a CI `e2e` job:**
    - The test: sign up in a real browser, sign the same account in from a Tor exit out of band, and see "You were signed out".
    - The job: service containers, the API and Worker with a one-line Tor list, Vite, then Playwright.
13. **Docs:** the evaluation report, spec as-built notes, concepts 6.1 and 6.6, the development guide and the README.

## Decisions

| Decision | Alternative | Why |
| --- | --- | --- |
| Generate the dataset from a seed, stream it | A committed dataset file | 2.9 M events is ~1 GB of JSONL. A seed is exact and tiny. `dataset --out` writes the file when someone wants to inspect it. |
| Replay folds baselines hourly in event time | Give power users a pre-trained baseline | Pre-training would hide exactly the cold-start problem the first run found. |
| Fix the cold start with severity (Low while cold, unless 3× the floor) | Raise the floor; notify-only D3 | Raising the floor blinds D3 for everyone. Notify-only gives up responding to real scrapers. Severity keeps both: real scrapers (250–350/min) are High. |
| Report the expected FP inside the headline, and the rate without it | Leave the migration scenario out | SPEC §16.1 lists it as an honest FP. Hiding it would flatter the numbers; showing both explains them. |
| D4 stays `respond` despite 22 % precision on the dataset | Default it to `notify` | That precision comes from the dataset's mix (1 in 7 benign users migrating). Account takeover's "new device, take everything" is what D4 exists for. Orgs can choose `notify`. |
| Live attacks sequential, a fresh user each | Concurrent | Measures the loop's latency, not queueing. Throughput is a separate, later number. |
| Nearest-rank percentiles | Interpolated | Simple, always an actual measurement, and the definition is in concepts §6.1. |
| Expose `idempotencyKey` in the audit API | Leave it hidden | It's part of the hash: without it nobody but the server can verify. It holds ids only, no secrets. |
| OpenTelemetry with the beta Prometheus exporters | prometheus-net; OTLP to a collector | SPEC §18 says OpenTelemetry. The Prometheus exporters have only ever shipped as betas, so they're pinned exactly. A collector is overkill for one server. |
| Instruments in Infrastructure on plain `System.Diagnostics.Metrics` | Reference OpenTelemetry everywhere | Only the hosts know about exporters, so Infrastructure stays dependency-free and tests can construct things without metrics. |
| Playwright test against a running stack | Spin up the stack from the test | Same command locally and in CI, and the CI job shows exactly what's needed to run the system. |

## Commands I ran

    dotnet run --project src/ThreatLock.Simulator -c Release -- replay --seed 42 --out artifacts/replay-v1.json   # 28.2 % FP
    # change D3 cold-start severity
    dotnet run --project src/ThreatLock.Simulator -c Release -- replay --seed 42 --out artifacts/replay-v2.json   # 14.3 % FP
    dotnet test                                  # 284 passed (122 core + 8 simulator + 154 integration)
    # mutation (after committing): drop the cold-start downgrade → 1 simulator + 1 core test fail
    dotnet run --project src/ThreatLock.Simulator -c Release -- live ... --kind tor --attacks 200
    dotnet run --project src/ThreatLock.Simulator -c Release -- live ... --kind hijack --attacks 200
    dotnet run --project src/ThreatLock.Simulator -c Release -- audit-verify ...   # intact org; and the B5-tampered org: seq 3
    curl http://localhost:9464/metrics
    cd web && npm install -D @playwright/test && npx playwright install chromium && npm run e2e

## What broke / surprised me

- **The first evaluation found what months of unit tests wouldn't have.** Every D3 test passed, and 98 % of power users were still being signed out on day one. Unit tests check that the code does what I meant. The evaluation checks whether what I meant was right.
- **The measuring tool was slower than the system.** B2 (M8) reported p50 506 ms. The in-process harness measured the same attack at 132 ms. The bash loop spent ~330 ms per poll starting curl and Python. Always ask what the instrument contributes.
- **The audit API hid a field the hash depends on.** Writing an independent verifier showed that `idempotency_key` is hashed but wasn't returned, so only the server could verify its own log. That defeats the point of an *independent* check.
- **I almost pinned an action to a SHA I'd made up.** I typed the `upload-artifact` commit SHA from memory, then checked it with `gh api`: it was wrong. Every action is downloaded at job start, even conditional steps, so it would have broken the e2e job. The real v7.0.2 SHA is pinned now.
- **OpenTelemetry API drift:** the HttpListener exporter's options are `Host` and `Port`, not `UriPrefixes`. I checked the installed package's XML docs rather than guessing again.
- **A metrics test assumed the cache.** The first session check for a new session is a Redis miss, so its label is `source="postgres"`. The test now accepts either. Getting the regex into a C# raw string literal took two attempts (a pattern ending in `"` collides with `"""`).
- **Vitest would have run Playwright's file.** Its default `include` matches `*.spec.ts`. The include is now `src/**`.

## Numbers

| Metric | Value | Conditions |
| --- | --- | --- |
| Replay throughput | 2.9 M events in ~15 s | 1,200 instances, seed 42, Release |
| FP rate v1 → v2 | **28.2 % → 14.3 %** | v2: 142 of 143 FPs are the expected migration export; 0.1 % without it |
| Recall | **100 %** (200/200), all responded | both runs |
| Precision v1 → v2 | 41.5 % → 58.3 % | |
| Time to revoke, D1, client-observed | **p50 176 / p95 199 / p99 202 / max 255 ms** | 200 attacks, local, warm Worker |
| Time to revoke, D5, client-observed | **p50 132 / p95 142 / p99 193 / max 202 ms** | 200 attacks |
| Detection stage (event → anomaly) | p50 118 ms (D1), 76 ms (D5) | dominated by the 100 ms stream poll |
| Detected → revoked | ~8–10 ms | job in the anomaly's transaction + LISTEN/NOTIFY |
| Server-side `tl_time_to_revoke_seconds` mean | 141 ms (D1), 98 ms (D5) | Worker metrics |
| Playwright smoke | 1.5 s sign-up → signed out | local |
| Tests | 284 .NET (122 + 8 + 154), 27 frontend unit, 1 e2e | all green |

## What I'd explain in an interview

I built two harnesses. A replay harness generates a seeded, labelled dataset (2.9 million events, two weeks of simulated time) and pushes it through the real detectors and policy code in 15 seconds. A live harness runs hundreds of real attacks over HTTP and measures when the attacker's stolen token stops working.

The first replay showed that a per-user baseline with a cold-start floor signed out almost every heavy reader on their first day. I fixed it with one severity rule, kept recall at 100 %, and committed both numbers. That one result is why evaluation exists.

The live harness puts the stolen-session window at a p95 under 200 ms, and its stage breakdown shows the remaining time is mostly the Redis stream poll. Metrics, an independent audit verifier and a Playwright test in CI keep it honest.

## Open threads

- Re-run the live harness on the home server (M10). Network hops will add latency.
- Throughput: events/s before consumer lag grows (SPEC §16.3). The `tl_stream_lag` gauge now makes it observable.
- Shrinking the 100 ms stream poll: a dedicated connection for a blocking `XREADGROUP` would cut most of the detection stage.
- More adversarial scenarios: slow scrapers, an attacker who copies the device id and user agent, a VPN-using insider.
