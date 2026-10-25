# B3. VPN user flagged as impossible travel

- Date run: 2026-10-25
- Git commit: M8 branch (`feat/m8-remaining-detectors`); break and prove are policies, run on the same code and dataset
- Environment: local, **replay harness** (ADR-0006): no HTTP, events go straight into the real D2 detector and policy evaluator
- Machine: Intel Core Ultra 5 225H (14 logical cores), 15 GB RAM, Windows 11, .NET SDK 10.0.401

## Hypothesis

A corporate VPN with exits in two countries makes its users look like they teleport: Bangalore at 10:02, Frankfurt at 10:09, Bangalore again at 10:20. To D2 that's ~6,800 km in minutes. If D2 were allowed to **respond**, nearly every VPN user would be signed out repeatedly: a false-positive storm.

Two fixes, which the spec asks to compare:

1. The org lists its VPN egress networks in `trustedNetworks`. A travel anomaly whose IPs are *all* trusted is suppressed (SPEC §9.2 rule 4). An attacker outside the VPN is still caught, because their IP isn't trusted.
2. D2's default mode is `notify`, not `respond`.

## Setup

The dataset is generated with a fixed seed (42), so every policy sees identical traffic:

- **500 benign VPN users**, 20 events each over a working day, 2–30 minutes apart. Before each event the VPN switches exit with probability 0.3. Exits are `198.18.10.0/24` (geolocated to Bengaluru) and `198.18.20.0/24` (Frankfurt).
- **100 attacks:** the victim is active on the Bangalore VPN exit, then 5–60 minutes later a thief uses the session from a London residential address (`203.0.113.x`, not a VPN).

Unit of measurement: a scenario instance (one user's day), as in SPEC §16.1. A benign instance counts as a **false positive** if any of its anomalies was decided `responded`. `notified` false positives are reported separately. **Recall** = attacks with at least one `notified` or `responded` D2 anomaly ÷ all attacks.

Policies:

| Name | D2 mode | `trustedNetworks` |
| --- | --- | --- |
| break | respond | none |
| prove | respond | both VPN CIDRs |
| default, unfixed | notify | none |
| shipped default | notify | both VPN CIDRs |

## Commands

    B3_REPORT=/path/to/b3.txt dotnet test --project tests/ThreatLock.Core.Tests -- --filter-class "*BreakB3VpnReplayTests"
    cat /path/to/b3.txt          # on Windows, give B3_REPORT a Windows path

## Results

    Outcome { Policy = break: D2 respond, no trusted networks, FalsePositiveRate = 0.998, NotifiedFalsePositiveRate = 0, Recall = 1, BenignResponded = 499, ... AttacksCaught = 100 }
    Outcome { Policy = default: D2 notify, no trusted networks, FalsePositiveRate = 0, NotifiedFalsePositiveRate = 0.998, Recall = 1, BenignNotified = 499, ... }
    Outcome { Policy = prove: D2 respond, VPN CIDRs trusted, FalsePositiveRate = 0, NotifiedFalsePositiveRate = 0, Recall = 1, ... AttacksCaught = 100 }
    Outcome { Policy = shipped default: D2 notify, VPN CIDRs trusted, FalsePositiveRate = 0, NotifiedFalsePositiveRate = 0, Recall = 1, ... }

| Policy | FP rate (signed out) | FP rate (notified) | Recall |
| --- | --- | --- | --- |
| break: respond, no trusted networks | **99.8 %** (499 / 500) | 0 % | 100 % |
| default, unfixed: notify, no trusted networks | 0 % | **99.8 %** | 100 % |
| prove: respond, VPN trusted | **0 %** | 0 % | **100 %** |
| shipped default: notify, VPN trusted | 0 % | 0 % | 100 % |

The single benign user who escaped in the break run happened never to switch exits that day.

## Conclusion

- **D2 responding on raw GeoIP is unusable for a VPN-heavy org:** 499 of 500 employees signed out on an ordinary day.
- **`notify` alone only moves the cost:** nobody is signed out, but admins get one alert per employee per day, which is alert fatigue and the way real alerts get ignored.
- **Trusting the VPN's egress networks fixes both without losing anything:** 0 % false positives, and still 100 % of the attacks from outside the VPN caught. "*All* IPs trusted", not "*any*" (the M5 decision), is what keeps the attacks: the thief's London IP isn't trusted, so the anomaly isn't suppressed.
- Keeping D2 at `notify` by default stays right. The org has to tell ThreatLock about its VPN, and until it does, a wrong `respond` costs far more than a wrong `notify`.

## Threats to validity

- A synthetic dataset: two exits, a fixed switching probability, an attacker who is obviously elsewhere. Real VPNs have many exits and mobile carriers geolocate badly too. M9's labelled dataset (SPEC §16.1) re-runs this alongside other scenarios.
- An attacker who is *also* on the org's VPN (an insider, or a stolen VPN credential) is suppressed by design. Trusting a network is a decision with consequences, and SPEC §9.2 records it as the reason on each suppressed anomaly.
- Replay exercises D2 and the evaluator, not the API or Worker; those are covered end to end by `DecisionEndToEndTests`.
