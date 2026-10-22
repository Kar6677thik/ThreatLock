# Build journal

One file per milestone, written **during** the work. It's the story of the build: what was done, why, when, and what surprised you. Future you, or an interviewer asking "walk me through it", reads this rather than the git log.

| Milestone | Entry |
| --- | --- |
| M0 Specification | [M0-specification.md](M0-specification.md) |
| M1 Skeleton | *not started* |
| M2 Identity, orgs, notes | *not started* |
| M3 Real sessions | *not started* |
| M4 Event pipeline + D1, D2 | *not started* |
| M5 Decision framework + admin UI | *not started* |
| M6 Response orchestrator | *not started* |
| M7 Audit log | *not started* |
| M8 Remaining detectors | *not started* |
| M9 Simulator and evaluation | *not started* |
| M10 Deployment | *not started* |
| M11 Finish | *not started* |

## Template

Copy this into `Mx-short-name.md`.

```markdown
# Mx. Title

- Dates: YYYY-MM-DD → YYYY-MM-DD
- PR(s): #
- Spec sections: §
- Concepts: concepts.md §

## Goal
One paragraph: what this milestone delivers and how we know it's done.

## What I did, in order
1. Step: what, and *why this step now*.
2. ...

## Decisions
- Decision, the alternative, and why. Link an ADR if it was big enough to need one.

## Commands I ran
    # exact commands, so this can be reproduced

## What broke / surprised me
- Symptom → cause → fix.

## Numbers (if any)
| Metric | Value | Conditions |

## What I'd explain in an interview
Three to five sentences, in your own words.

## Open threads
- Things deferred, with the milestone they move to.
```
