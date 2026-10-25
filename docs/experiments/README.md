# Experiments

Each Break/Prove experiment from [spec §15](../spec/SPEC.md#15-break-and-prove-experiments) gets one report here, named `Bn-short-name.md`. A report must be reproducible by someone who has only this repository.

| ID | Experiment | Report |
| --- | --- | --- |
| B1 | Stateless JWT keeps working after revocation | [B1-stateless-jwt.md](B1-stateless-jwt.md) (complete) |
| B2 | Replayed cookie from another country | [B2-cookie-replay.md](B2-cookie-replay.md) (complete) |
| B3 | VPN user flagged as impossible travel | [B3-vpn-false-positive.md](B3-vpn-false-positive.md) (complete) |
| B4 | Duplicate notifications from a non-idempotent responder | [B4-idempotent-responder.md](B4-idempotent-responder.md) (complete) |
| B5 | Tampered audit entry | [B5-audit-tamper.md](B5-audit-tamper.md) (complete) |
| Eval | False-positive rate, recall, p95 time to revoke | [Eval-detection-and-time-to-revoke.md](Eval-detection-and-time-to-revoke.md) (complete, local; home server in M10) |

## Template

```markdown
# Bn. Title

- Date run:
- Git commit (break):            Git commit (prove):
- Environment: local | home server
- Machine: CPU, cores, RAM, OS, .NET version, PostgreSQL and Redis versions

## Hypothesis
What we expect to see, and why.

## Setup
Config flags, seed data, dataset seed, number of runs.

## Commands
    # exact, copy-pasteable

## Results: break
| Metric | Value |

## Results: prove
| Metric | Value |

## Evidence
Screenshots, log excerpts, recording link.

## Conclusion
What the numbers show, and what they don't.

## Threats to validity
Simulated IPs, warm caches, small sample, same-host network, etc.
```
