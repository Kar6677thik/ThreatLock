# M7. Audit log

- Dates: 2026-10-24 → 2026-10-24
- PR(s): M7 PR
- Spec sections: §11 tamper-evident audit log (all), §12 `audit_log`, §13 audit endpoints, §14 Audit log screen, §15 Break B5, §10.2 step 4
- ADR: [0005 per-org SHA-256 hash chain](../../adr/0005-audit-log-per-org-sha256-hash-chain.md) (implementation notes added)
- Concepts: [5.1 hash chains](../concepts.md#51-hash-chains-fg-2518), [5.2 advisory locks](../concepts.md#52-advisory-locks), [5.3 canonical serialisation](../concepts.md#53-canonical-serialisation), [5.4 prevent vs detect](../concepts.md#54-prevent-vs-detect), [2.2 idempotency](../concepts.md#22-at-least-once-delivery-and-idempotency-fg-18)
- Experiment: [B5 report](../../experiments/B5-audit-tamper.md)

## Goal

Every security-relevant action becomes an entry in its org's audit log, and the log is **evidence**. The app can't change it. A database superuser can, but then `verify` names the exact entry they changed. Done when real actions build a chain that verifies, concurrent writers can't fork it, a superuser's edit is named by `seq`, and the chain's blind spots are covered by anchors and documented.

## What I did, in order

1. **Core: `AuditChain`.**
   - Canonical form: fixed field order, `name=len:value`, null as `~`, microsecond UTC timestamps, JSON with keys sorted at every level.
   - `SHA-256(prev_hash || canonical)`, with a genesis of 32 zero bytes.
   - A streaming verifier (`AuditChainVerifier`) reporting `hash_mismatch`, `chain_break`, `seq_gap` and `anchor_mismatch`.
   - 12 unit tests, including the `"ab"+"c"` ambiguity, null vs empty, key order, precision, edit, edit-and-rehash, delete, full rewrite vs anchor, and truncated tail vs anchor.

   *Why first:* this is the part that must never change once rows exist, so it gets nailed down and tested alone.
2. **Migration `AddAuditLog`:**
   - Primary key `(org_id, seq)` and a unique `idempotency_key`.
   - FK to orgs with `RESTRICT`, so deleting an org can't delete its evidence.
   - A hand-written **append-only trigger** (UPDATE, DELETE and TRUNCATE refused for every role), plus least-privilege grants for `threatlock_app` once M10 creates it.
3. **`AuditLog` appender:**
   - Takes `pg_advisory_xact_lock` on the org, checks the idempotency key under the lock, reads the head, hashes, and inserts.
   - Can join the caller's transaction or open its own.
   - Verify streams rows and stops at the first failure.
4. **The Worker audits what it does:**
   - The `notified`/`responded` decision is written in the anomaly's transaction, so anomaly, job and audit entry exist together, under the key `anomaly:{id}`.
   - Each response is audited as the new **step 4**, under `response:{anomalyId}`, with the revoked session ids and whether the account was locked. The crash-after-each-step test gained an "after audit" case and checks there is exactly one entry and a valid chain.
5. **Policy saves are audited in the same transaction** as the new version (`PolicyStore`).
6. **The API audits.** An `AuditExtensions` helper joins EF Core's current transaction when there is one.
   - **Inside the action's transaction:** sign-up (seq 1 is `org.created`), user creation, role changes, unlock.
   - **Right after the action:** logins, Identity lockouts, logouts, session revocations (own device, refresh reuse, admin), exports (count only).
7. **Endpoints:** `GET /api/admin/audit?afterSeq=&limit=` and `POST /api/admin/audit/verify` with an optional anchor. 200 either way, since a broken chain is a finding, not an error.
8. **Integration tests** (13):
   - Real history verifies.
   - Actor names, and no secrets in details.
   - 40 concurrent appends stay one chain.
   - The idempotency key writes once under 5 concurrent appends.
   - The trigger refuses UPDATE, DELETE and TRUNCATE.
   - **B5:** a superuser edit is named as seq 3.
   - A delete shows as a gap; an anchor catches a truncated tail.
   - A bad anchor gets 400.
   - Tenancy and roles; paging.
   - The Tor response is audited as a decision plus an execution, then the unlock.
   - Microsecond round-trip.
9. **UI:** an Audit log screen with paged entries and hashes, plus Verify showing *Intact* (with the head to save as an anchor) or *Tampered* (naming the entry and what it means). The broken row is highlighted. 3 frontend tests.
10. **Mutation checks:** 5 of 5 caught (below).
11. **Break/Prove B5** on the real stack with `scripts/experiments/b5-audit-tamper.sh`, plus a browser check.

## Decisions

| Decision | Alternative | Why |
| --- | --- | --- |
| A trigger blocks UPDATE/DELETE/TRUNCATE for every role | Wait for M10's role split | The app connects as the owner until then, and grants can't restrict an owner. A trigger works today, and only a superuser who deliberately disables it gets past. |
| Append inside the action's transaction where one exists | Always append afterwards | The action and its evidence commit together. Where the action is a single statement, the after-append gap is accepted and documented. |
| Decision audited in the anomaly's transaction; response audited as its own idempotent step | One entry at the end of the job | The decision exists the moment the anomaly does. The execution can be retried, so it needs an idempotency key, the pattern from M6. |
| Idempotency key checked under the advisory lock | `INSERT ... ON CONFLICT DO NOTHING` | The hash and seq are computed before inserting. A conflicting insert would already have been assigned a seq; checking first under the lock keeps the chain gap-free. |
| Only `notified`/`responded` decisions audited | Every anomaly | SPEC §11.1: audit is for actions. Suppressed and observed anomalies are in the anomalies table, and the activity events cover the rest. |
| Report `chain_break` separately from `hash_mismatch` | One "broken" reason | They mean different things: "this entry was edited" vs "the previous one was edited *and re-hashed*", which is a more deliberate attacker. |
| Anchors, manual | Automatic publishing; none | Cheap, and it closes the two blind spots a chain has. Where to keep anchors is the admin's job for now; automatic publishing is a stretch goal. |
| Verify streams and stops early | Load the chain, then check | Memory stays flat however long the chain gets; 1,003 entries took 23 ms. |
| Details: strings, ints, bools, arrays, objects only | Any JSON | `jsonb` may rewrite number formats, which would change the hash. Documented on `AuditFields`. |
| No break tag for B5 | Tag a chain-less version | The "before" is a plain table; the experiment shows the edited row looking normal, which is the whole point. |

## Commands I ran

    dotnet ef migrations add AddAuditLog --project src/ThreatLock.Infrastructure \
        --startup-project src/ThreatLock.Infrastructure --output-dir Persistence/Migrations   # + trigger SQL by hand
    dotnet test                                          # 236 passed (94 unit + 142 integration)

    # mutations (each reverted with git checkout):
    #   no advisory lock                      → 2 integration tests fail (concurrent appends, idempotency)
    #   no length prefix in canonical()        → 1 unit test fails
    #   no microsecond truncation              → 8 integration tests fail
    #   verifier skips the prev_hash check     → 1 unit test fails
    #   JSON keys not sorted                   → 1 unit + 4 integration tests fail

    cd web && npm run lint && npm test && npm run build  # 27 tests
    dotnet run --project src/ThreatLock.Api ; scripts/experiments/b5-audit-tamper.sh

## What broke / surprised me

- **Not sorting keys broke verification on untouched chains.** The mutation test made it concrete: `jsonb` stores `{"slug":…,"owner":…}` and hands it back as `{"owner":…,"slug":…}` with spaces. Without sorted canonical JSON, every chain with two-key details "failed". A verifier that cries wolf is worse than none, because people stop listening.
- **.NET ticks vs PostgreSQL microseconds.** Hashing `DateTimeOffset.UtcNow` directly would fail verify about 9 times in 10 (whenever the 100 ns digit isn't 0). That's why the clock is truncated *before* hashing, and a test uses a fake clock with sub-microsecond ticks to prove it.
- **The trigger stops the superuser too, until they turn it off.** A plain `UPDATE` as `postgres` failed with "audit_log is append-only". It took `SET session_replication_role = replica`, a deliberate act, to get past. Exactly the "prevent the many, detect the few" layering.
- **Npgsql again:** `SET ...; UPDATE ... $1` in one command is refused ("cannot insert multiple commands into a prepared statement"). The superuser helper runs the `SET` as its own command on the same connection.
- **The `é` in a test turned into a literal character.** The expected canonical JSON must contain the six characters `é`, because System.Text.Json escapes non-ASCII by default. The file ended up with the literal `é`; fixed and verified with `cat -A`.

## Numbers

| Metric | Value | Conditions |
| --- | --- | --- |
| Superuser edit of entry 3 | Named: `seq 3`, `hash_mismatch` | B5, triggers disabled for the session |
| Newest entry deleted | Chain alone: `ok`; with anchor: `anchor_mismatch` | B5 second org |
| Verify, 1,003 entries | 23 ms | over HTTP, local, every hash recomputed |
| Concurrent appends | 40 at once → seq 1–42 contiguous, chain valid | integration test |
| Mutation checks | 5 of 5 caught | |
| Tests | 236 .NET (94 unit + 142 integration), 27 frontend | all green |

## Browser check

As the B5 org's owner after the tampering, on the Audit log screen:

- 100 entries, starting with seq 1 `org.created` and seq 2 `auth.login_succeeded` (`{"ip":"127.0.0.1"}`).
- Each entry shows its hash prefix, and there's a Load more button.
- **Verify chain** gives *"Tampered. Entry 3 fails: its contents no longer match its hash: the entry was edited. The 2 entries before it check out."*
- Row 3, showing the edited `nobody@b5.test`, is highlighted.

## What I'd explain in an interview

Every security action goes into a per-org audit log where each entry's SHA-256 covers the previous entry's hash and a length-prefixed canonical form of itself, with JSON keys sorted and timestamps at the database's precision, so the verifier reproduces the exact bytes. Appends take an advisory lock per org so concurrent writers can't fork the chain, and retried work uses idempotency keys. A trigger stops the app, and even a superuser's plain UPDATE. If a superuser disables triggers and edits a row, the row looks completely normal, but verify names the exact sequence number. A chain alone can't see a truncated tail or a full rewrite, so verify also accepts an anchor: a head hash saved somewhere the attacker can't reach.

## Open threads

- Database role split: `threatlock_app` with `SELECT, INSERT` only on `audit_log`, a migrator role for DDL (M10).
- `Simulator audit verify`, an independent verifier (M9).
- Automatic anchor publishing (stretch).
- Audit entries for D3–D5 decisions come for free via the same path (M8).
