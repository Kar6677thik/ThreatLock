# 0005. Audit log as a per-org SHA-256 hash chain in PostgreSQL

- Status: Accepted
- Date: 2026-10-22
- Milestone: M7

## Context

The audit log is evidence. If an attacker (or an insider with database access) can quietly edit or delete entries, it stops being evidence. The guide asks for "a tamper-evident audit log where each entry hashes the previous one".

## Decision

- Each org has its own chain: `entry_hash = SHA-256(prev_hash || canonical(entry))`. The genesis `prev_hash` is 32 zero bytes and `seq` increases by one.
- Appends take `pg_advisory_xact_lock` on the org, read the head, and insert in one transaction; `UNIQUE (org_id, seq)` is the backstop.
- The application's DB role has only `INSERT` and `SELECT` on the table.
- `verify` walks the chain and reports the first broken `seq`.
- Optional anchoring (publishing head hashes outside the database) is a stretch goal.

## Alternatives considered

- **One global chain:** every org's writes serialise behind one lock, and verifying one tenant means reading all tenants.
- **Permissions only:** stops the app, not a superuser, and there's no way to *prove* nothing changed.
- **Digital signatures per entry (HMAC or asymmetric):** stronger against a full-chain rewrite if the key lives outside the DB, at the cost of key management. Anchoring gets most of the benefit for less.
- **External append-only store (e.g. object storage with object lock):** better in production, overkill on a single home server.

## Consequences

- Detects edits and deletions in the middle of the chain. Does **not** detect a rewrite of everything after the edit point unless anchors exist. The docs must say so.
- Canonical serialisation must never change for existing entries; if it must, add a `hash_version` column.
- Appends per org are serialised. At audit-log volumes this doesn't matter.
