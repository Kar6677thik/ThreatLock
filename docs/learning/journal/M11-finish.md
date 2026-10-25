# M11. Finish

- Dates: 2026-10-25
- PR(s): M11 PR
- Spec sections: §21 (M11: README with architecture diagram, recorded failure demo, final report, résumé line)

## Goal

Make the project understandable in two minutes by someone who will never open the code: what it does, a demo of it working, the
measured results, and how it's built. M10 (deployment) is on hold while the home server is down, so this milestone was done first. The
README says plainly that deployment is planned, not live.

## What I did, in order

1. **Recorded the failure demo** (`web/demo/record-demo.mjs`). Playwright drives the real stack:
   - It sets up two orgs through the API, with the same notes and the same user "Ben" in each. In the first, the Tor detector only observes.
   - Two attacker browsers, sending the simulator header with a live Tor exit's address, sign in as Ben at the same moment and try to read and export.
   - Two admin browsers then show the anomaly, the response timeline, the notification and the audit chain.

   The recorder screenshots both sides at each step and writes a manifest with captions and durations.
2. **Composed the GIF** (`scripts/demo/make-gif.py`, Pillow): the panels side by side under coloured titles, a caption band, and a closing
   card with the measured revocation time. 12 frames, 376 KiB. There's no ffmpeg on this machine and none is needed.
3. **Checked the frames by eye before composing.** The first take cut the anomaly detail off just above the response timeline,
   the part that matters most, so the recorder now scrolls it into view.
4. **Rewrote the README** in the shape of the earlier projects: tagline, badges, hero GIF with a comparison table, measured results
   (B1–B5 and the evaluation), a Mermaid architecture diagram, how it works, quick start, reproduction commands, deployment status, layout,
   stack and documentation index.

## Decisions

| Decision | Alternative | Why |
| --- | --- | --- |
| Demo as two policies side by side on the real stack | A narrated screen recording of one run | Side by side makes the difference the whole story: the same attacker, the same second, two outcomes. Scripted means anyone can re-record it. |
| Left side = Tor detector in **observe** mode | A separate "naive" build | Observe is exactly "ThreatLock without automatic response": it still detects and records, so the left admin view shows the anomaly nobody acted on. |
| Screenshots + Pillow → GIF | Playwright video + ffmpeg | No external tool to install. Frames are chosen moments with their own hold times, which reads better than real-time video of a 94 ms event. |
| README states deployment is planned | Leave the deploy badge and wording from the plan | It isn't deployed yet. Claims in the README should be things a reader can verify. |

## What broke / surprised me

- **Starting the API and the Worker at once with `dotnet run -c Release` broke the Worker's build.** Both compiled the shared projects in
  parallel and fought over the same output files. Starting the Worker after the API had built fixed it.
- **The revocation is too fast to see.** The demo can't show "the moment it happened", because 94 ms after sign-in the session is already
  gone. What's visible is the attacker's *next* click failing, so the caption gives the server-side number from the anomaly's timeline.

## Numbers

| Metric | Value | Conditions |
| --- | --- | --- |
| Demo: sessions revoked after the attacker's sign-in | 94 ms (another take: 250 ms) | local, live Tor exit, server timestamps |
| Demo: attacker saw "signed out" | 0.7 s after sign-in | at their first click after the notes loaded |
| GIF | 12 frames, 1328×676, 376 KiB | |

## Final report

What was built, M0–M9:

- **M0–M3:** sessions that can actually be revoked. A 5-minute JWT plus a per-request session check against Redis, falling back to PostgreSQL and failing closed. Rotating refresh tokens with reuse detection. Break B1: a revoked token went from 149.5 s of continued access to rejection on the next request, for about 0.6 ms per request.
- **M4:** an event pipeline with a transactional outbox into Redis Streams, consumer-group reclaim and dead letters, and the first two detectors.
- **M5:** per-org versioned policy, a fixed evaluation order, and optimistic concurrency.
- **M6:** a response orchestrator on a PostgreSQL job table with leases and step markers. Break B4: from 532 notifications for 300 to exactly 300, across 100 injected crashes.
- **M7:** a hash-chained audit log. Break B5: a superuser's invisible edit is named by sequence number.
- **M8:** three more detectors, and a last-owner guard found by a failing test. Breaks B2 and B3.
- **M9:** evaluation. A seeded 1,200-scenario dataset, which found and fixed a cold-start false-positive problem, ending at 100 % recall. Live time to revoke: p95 199 ms (Tor) and 142 ms (replayed token). Plus metrics, an independent audit verifier, and Playwright in CI.

What's left:

- **M10:** deployment to the home server, with the live harness re-run there.
- **Known weaknesses, documented in SPEC §8.2:** slow scrapers, an attacker who copies the device id and user agent, a VPN-using insider.
- **The detection stage is dominated by a 100 ms stream poll.** A dedicated connection for a blocking read would cut it.

## Résumé lines

- Built **ThreatLock**, an automatic account-takeover response system (.NET 10, PostgreSQL, Redis Streams, React). Five detectors and per-org policy revoke a stolen session in **p95 under 200 ms** across 400 live attacks, with **100 % recall** on a 1,200-scenario labelled dataset.
- Made the responder **crash-safe**: across 100 injected crashes, duplicate admin notifications went from 232 to **0**, using a PostgreSQL job queue (`SKIP LOCKED`, leases) and effect markers committed with each step.
- Designed a **tamper-evident audit log** (per-org SHA-256 chain, canonical serialisation, append-only trigger, anchors). It names the exact entry a database superuser edited, and verifies 1,000 entries in 23 ms.
- Used a reproducible replay harness to cut false positives from **28 % to 14 %** (0.1 % excluding the expected migration export), finding a cold-start flaw that unit tests had missed.
