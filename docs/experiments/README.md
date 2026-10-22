# Experiments

Each Break/Prove experiment from [spec §15](../spec/SPEC.md#15-break-and-prove-experiments) gets one report here, named `Bn-short-name.md`. A report must be reproducible by someone who has only this repository.

| ID | Experiment | Report |
| --- | --- | --- |
| B1 | Stateless JWT keeps working after revocation | *not run* |
| B2 | Replayed cookie from another country | *not run* |
| B3 | VPN user flagged as impossible travel | *not run* |
| B4 | Duplicate notifications from a non-idempotent responder | *not run* |
| B5 | Tampered audit entry | *not run* |
| Eval | False-positive rate, recall, p95 time to revoke | *not run* |

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
