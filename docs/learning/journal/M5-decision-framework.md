# M5. Decision framework and admin UI

- Dates: 2026-10-24 →
- PR(s): M5 PR
- Spec sections: §9 decision framework (all), §13 policy and anomaly endpoints, §14 UI (anomalies, policy, users)
- Concepts: [4.1 policy as data](../concepts.md#41-policy-as-data-fg-812), [4.4 optimistic concurrency](../concepts.md#44-optimistic-concurrency-and-lost-updates-fg-11), [3.4 false positives](../concepts.md#34-false-positives-false-negatives-precision-and-recall)

## Goal

Every anomaly gets a **decision** made by its org's own policy: suppressed, observed, notified or responded, with exactly one reason and the policy version that made it. Admins can see anomalies and edit the policy in the browser. Done when each rule of the evaluation order is proven end to end through the real Worker, and a policy edit in the UI visibly changes the next decision.

M5 *decides*; M6 *acts* on "notified" and "responded".

## What I did, in order

1. **Policy model in Core** (`SecurityPolicy`, `DetectorPolicy`, `ResponsePolicy`) with the spec's defaults: Tor *respond*, impossible travel *notify*, notify owners, admins and security admins.
2. **`PolicyEvaluator`**: the six rules of SPEC §9.2 in order, first match wins: detector off → excluded user → excluded role → every IP trusted → below minimum severity → mode. 15 unit tests (24 new in Core with the validator), including "earlier rules beat later ones".
3. **`PolicyValidator`**: rejects bad CIDRs, catch-all `/0` networks, unknown roles, detectors and thresholds, out-of-range thresholds, an empty notify list, unknown actions. *Why:* a typo in a security policy fails silently (an invalid CIDR matches nothing), so it must fail loudly at save time.
4. **Signals carry their IPs** (`DetectionSignal.Ips`) so the trusted-network rule can check *every* address involved; detectors receive the org policy so **thresholds are per org**.
5. **`org_policies` table** (migration `AddOrgPolicies`), versioned, never updated in place. **`PolicyStore`**: current version (0 = defaults), a short Worker cache, and a save that only succeeds from the expected version.
6. **Decision written with the anomaly.** The Worker reads the (cached) policy, skips detectors that are off, looks up the user's roles only when a detector fires, decides, and the same `INSERT ... ON CONFLICT` that creates the anomaly stores the decision and policy version. A duplicate signal never re-judges.
7. **API:** `GET/PUT /api/admin/policy` (security admins and owners), version history and any past version; anomalies filterable by decision and showing the policy version; enums as strings, integers rejected.
8. **Integration tests (18 new):** versions and history, the lost-update case, five concurrent saves (exactly one wins), validation, integer enums, access and tenancy, and every decision rule end to end through the real Worker (default respond/notify, observe with version number, excluded user, excluded role, trusted VPN pair, detector off produces *no* anomaly, per-org distance threshold, decision filter).
9. **Mutation checks:** skipping "off" detectors and the "*every* IP trusted" rule each caught.
10. **Admin UI** with React Router: Anomalies (filters in the URL), anomaly detail (evidence rendered as text), Policy (form, save with expected version, conflict and validation messages, history), Users (add, sign out everywhere). Nav shows only what your roles allow. DB-IP attribution in the footer (ADR-0009). 7 new frontend tests.
11. **Checked it in a real browser** against the real API and Worker: a member's Tor login → *responded* (v0); the owner switches Tor to *observe* in the Policy screen → v1; the member's next Tor login → *observed (mode_observe), policy v1*.

## Decisions

| Decision | Alternative | Why |
| --- | --- | --- |
| Policy is versioned rows, never updated in place | One mutable row | Every anomaly can point at the exact rules that judged it; history comes free. |
| Optimistic concurrency (`expectedVersion` → `409`) | Last write wins; pessimistic lock | Forms stay open for minutes; locks would block others, and last-write-wins silently loses a colleague's change. |
| Version check inside the `INSERT ... WHERE`, PK as backstop | Read, compare, then insert | Read-compare-insert races; the test fires five saves at once and exactly one wins. |
| Decision stored in the same statement that creates the anomaly | Separate update afterwards | No window where an anomaly exists without a decision; M6 will add the response job to the same unit of work. |
| An anomaly is judged once, at creation | Re-judge on every new event | Decisions must be stable and explainable; a policy edit applies to *new* anomalies. |
| "Off" means the detector doesn't run | Run it and suppress | Saves work and state; the evaluator still has a defensive `detector_off` rule. |
| Trusted network = *every* IP in the evidence trusted | *Any* IP trusted | VPN → unknown country is still suspicious; only "both ends are ours" is safe to ignore. |
| A bare IP in trusted networks means `/32` (`/128`) | Require CIDR syntax | Admins often know just one egress IP. Validator and evaluator share one parser. |
| `0.0.0.0/0` is rejected | Allow it | It would quietly switch off every detector; there's an explicit "off" mode for that. |
| Worker caches policy 10 s (0 in tests) | Read per event; cache forever | Per-event reads are wasteful; long caches make edits confusing. The anomaly records the version actually used. |
| Enums as snake_case strings, integers refused | Default numeric enums | `"mode": "respond"` is readable in stored JSON and API calls; `"mode": 3` silently changes meaning if the enum is reordered. |
| Detector keys are detector ids (`impossible_travel`), thresholds nested | Spec's earlier camelCase keys with flat numbers | One name for a detector everywhere (anomalies, events, policy); thresholds validated per detector. Spec updated. |
| Users screen built now | Leave for later | The API existed and the policy screen needs the user list for exclusions anyway. |
| React Router (declarative) | Hand-rolled tabs | Deep links (`/admin/anomalies/<id>`) and filters in the URL are worth it now. |

## Commands I ran

    dotnet ef migrations add AddOrgPolicies --project src/ThreatLock.Infrastructure \
        --startup-project src/ThreatLock.Infrastructure --output-dir Persistence/Migrations
    dotnet test                                    # 175 passed (68 unit + 107 integration)
    # mutations: remove the "Mode == Off → continue" line → 1 fails; All → Any in the trusted rule → 1 fails

    cd web && npm install react-router && npm run lint && npm test && npm run build    # 18 tests

    dotnet run --project src/ThreatLock.Api ; dotnet run --project src/ThreatLock.Worker ; cd web && npx vite
    # browser: register, member logs in via a Tor IP, /admin/anomalies, /admin/policy → observe → save

## What broke / surprised me

- **A bare IP isn't valid CIDR.** `IPNetwork.TryParse("203.0.113.7")` fails; the validator test caught it. Treating it as a single host is friendlier, and both the validator and the evaluator now use one parser, so they can't disagree.
- **Two different ways to break a test with duplicate text.** "Tor exit node (D1)" and "responded" appear both in the filter dropdowns and in the table. Queries by role (`cell`) instead of by text fixed both, and are the better habit anyway.
- **The linter can't see through an async helper.** Calling a `useCallback` that awaits and then sets state from an effect looks like a synchronous setState to `react(set-state-in-effect)`. Splitting "fetch (pure)" from "apply (sets state)" fixed it and reads better.
- **A browser has one cookie jar per site.** Setting up the browser check, a second user's login replaced the owner's refresh cookie, so a reload would have restored the *wrong* session. That's correct browser behaviour (it's why two people can't share a browser profile); the check now signs the owner in last.
- **Setting a `<select>` from outside React needs the native setter.** React tracks input values itself; assigning `.value` and firing `change` isn't enough unless the value goes through `HTMLSelectElement.prototype`'s setter.

## Numbers

| Metric | Value | Conditions |
| --- | --- | --- |
| Tests | 175 .NET (68 unit + 107 integration), 18 frontend | All green |
| Concurrent policy saves from the same version | 5 sent, exactly 1 accepted, 4 × `409` | Integration test |
| Policy edit → applied to next anomaly | within `Policy:CacheSeconds` (10 s dev, 0 in tests) | Browser check: v0 *responded* → v1 *observed* |
| Mutation checks | 2 of 2 caught | |

## What I'd explain in an interview

Detection and decision are separate: detectors say "this looks wrong", and each org's policy says what that means for them, through six rules evaluated in a fixed order so every decision has exactly one reason. The policy is versioned data, saved with optimistic concurrency so two admins can't silently overwrite each other, and every anomaly records the version that judged it, so "why was this person signed out?" always has an exact answer. The decision is written in the same statement that creates the anomaly, so there's never an undecided anomaly and a redelivered event never re-judges one. Suppressed anomalies are kept on purpose: "what did we ignore?" is how you tune false positives.

## Open threads

- Act on decisions: response jobs, revocation, notifications, lock (M6).
- Audit entries for policy changes (M7).
- D3–D5 get policy entries and thresholds (M8).
- Default modes revisited with evaluation data (M9).
- The anomaly detail could show a timeline of its events; deferred until the response timeline exists (M6).
