# B5. Tampered audit entry

- Date run: 2026-10-24
- Git commit (break): none needed, see Setup             Git commit (prove): M7 branch (`feat/m7-audit-log`)
- Environment: local
- Machine: Intel Core Ultra 5 225H (14 logical cores), 15 GB RAM, Windows 11, .NET SDK 10.0.401, PostgreSQL 17.11 and Redis 8.10.2 in Docker Compose

## Hypothesis

An audit log is evidence only if a change to it can be noticed. Someone with superuser access to PostgreSQL can change any row, and a changed row looks like any other: same columns, plausible values. A per-org SHA-256 hash chain should let `verify` name the exact entry that was changed (`seq`), from nothing but the data itself.

We also expect two honest limits of a chain on its own (ADR-0005):

1. Deleting entries off the **end** leaves a shorter chain that is still internally valid.
2. Rewriting everything **from** the edit onwards, recomputing every hash, rebuilds a valid chain.

An **anchor**, a `(seq, hash)` saved outside the database earlier, should catch both.

## Setup

- No break tag: the "before" is simply a table without the chain. The edited row in step 4 below shows what that world looks like: nothing in the row reveals the change.
- An org with real audited history through the API: `org.created`, the owner's login, `user.created` for Ben, then **1,000** `notes.exported` entries (each export is audited). 1,003 entries in total.
- The attacker is the PostgreSQL superuser from the Compose container (`docker exec ... psql`).
- A second, fresh org for the truncation test.

## Commands

    docker compose -f deploy/compose/docker-compose.yml up -d
    dotnet run --project src/ThreatLock.Api          # in another terminal
    scripts/experiments/b5-audit-tamper.sh           # N=1000 by default; ~50 s, mostly the 1,000 exports

## Results

    == 1. An org with audited history
    verify: {"ok":true,"entries":1003,"head":"758b91f6…44bbb1",...}  (0.022782s)

    == 2. Entry 3 as it was
    3|user.created|{"email": "ben-1792850934@b5.test", "roles": ["member"]}

    == 3. A plain UPDATE, even as the superuser, hits the append-only trigger
    ERROR:  audit_log is append-only: UPDATE is not allowed

    == 4. With triggers off for the session, the edit succeeds and the row looks normal
    3|user.created|{"email": "nobody@b5.test", "roles": ["member"]}
    verify: {"ok":false,"entries":2,"head":null,"firstBrokenSeq":3,"reason":"hash_mismatch"}  (0.011474s)

    == 5. A second org: delete its newest entry, which a chain alone cannot notice
    verify, no anchor:   {"ok":true,"entries":4,...}
    verify, with anchor: {"ok":false,"entries":4,"head":null,"firstBrokenSeq":5,"reason":"anchor_mismatch"}

| Attack | Without the chain | With the chain | With chain + anchor |
| --- | --- | --- | --- |
| Plain `UPDATE`/`DELETE`/`TRUNCATE` (app, owner, even superuser) | Refused by the trigger | Refused by the trigger | Refused by the trigger |
| Superuser edits one entry with triggers off | **Undetectable**: the row looks normal | **Detected: `seq 3`, `hash_mismatch`** | Detected |
| Superuser deletes an entry in the middle | Undetectable | Detected: `seq_gap` (integration test) | Detected |
| Superuser deletes the newest entry | Undetectable | Not detected (valid shorter chain) | **Detected: `anchor_mismatch`** |
| Superuser edits an entry and recomputes every later hash | Undetectable | Not detected | Detected: `anchor_mismatch` (unit test) |

| Metric | Value |
| --- | --- |
| Verify, 1,003 entries (streamed, every hash recomputed) | **23 ms** end to end over HTTP |
| Verify that stops at seq 3 | 11 ms |

## Evidence

- The browser's Audit log screen, signed in as that org's owner, after step 4: *"Tampered. Entry 3 fails: its contents no longer match its hash: the entry was edited. The 2 entries before it check out."* Row 3 is highlighted, showing the edited `nobody@b5.test`.
- Integration tests reproduce each row of the table: `Break_B5_an_edit_by_a_superuser_is_named_by_seq`, `Deleting_an_entry_shows_as_a_gap`, `An_anchor_catches_entries_cut_off_the_end`, `The_table_refuses_updates_deletes_and_truncation_from_the_app`; unit tests cover `chain_break` and the full rewrite with an anchor.

## Conclusion

Layers stop different people:

- **The trigger** stopped everyone who didn't deliberately switch it off, including the superuser's plain `UPDATE`.
- **The chain** turned an invisible edit into a precise finding: entry 3, contents don't match. It also costs little: 1,003 entries verified in 23 ms.
- **The anchor** covered the chain's two blind spots, a truncated tail and a full rewrite. It only works if the anchor lives somewhere the attacker can't also change. Saving it is manual today; publishing heads automatically is a stretch goal.

## Threats to validity

- A superuser could also change the application code or the verify endpoint itself. The chain is evidence for someone verifying with a trusted copy of the code (the `Simulator audit verify` command, M9, gives a second, independent verifier).
- Anchors are only as safe as where they're kept.
- Single machine; verify time scales linearly with entries, measured here at ~1,000.
- Until M10 the app connects as the table owner; the trigger is what stops it today, and role grants arrive with the deployment.
