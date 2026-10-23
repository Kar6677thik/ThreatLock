# M2. Identity, orgs, notes (naive auth)

- Dates: 2026-10-23 →
- PR(s): M2 PR
- Spec sections: §4 tenancy and roles, §6.2–6.3 login and tokens, §12 data model, §13 API, §15 Break B1
- Concepts: [1.1–1.4](../concepts.md#part-1-identity-and-sessions), [1.7 tenant isolation](../concepts.md#17-tenant-isolation-fg-813-2537), [1.8 passwords and lockout](../concepts.md#18-password-storage-and-lockout-fg-25), [1.9 user enumeration](../concepts.md#19-user-enumeration), [1.10 object-level authorization](../concepts.md#110-object-level-authorization-and-mass-assignment-fg-2510-2511), [6.4 DI lifetimes](../concepts.md#64-dependency-injection-lifetimes-and-captive-dependencies)

## Goal

A working multi-tenant notes app with real logins, built the **naive** way on purpose: 60-minute stateless JWTs and nothing on the server to revoke. Done when orgs, users, roles and notes work end to end (API + SPA), tenant isolation is proven by tests, and Break B1 is reproduced with a script and recorded numbers.

Why build it wrong first? Because "stateless tokens can't be revoked" is a sentence you nod at; watching a "revoked" token download someone's notes is something you remember. M3 fixes it, and the before/after numbers become the B1 report.

## What I did, in order

1. **Added EF Core + Identity to Infrastructure** (Npgsql provider, snake_case naming convention, `dotnet-ef` as a pinned local tool). *Why Identity's EF stores and not Identity's full sign-in stack:* we issue our own tokens, so `AddIdentityCore` (users, roles, hashing, lockout) is all we need, and the Worker stays free of ASP.NET.
2. **Modelled the data**: `Org`, `AppUser` (+ `OrgId`, `DisplayName`), `AppRole`, `Note`, all with UUIDv7 ids. Roles are seeded by the migration with fixed ids. Entities live in Infrastructure because Identity's base classes may not leak into Core (the M1 architecture test would fail).
3. **Tenant isolation in one place**: an EF Core *global query filter* on `Note` compares `OrgId` with the current tenant from an `ITenantContext`. With no tenant the filter matches nothing, so it fails *closed*.
4. **Generated the first migration and read the SQL** before trusting it. Found two problems (see "What broke"): Identity's hard-coded `AspNetUsers` names, and no unique index on email.
5. **Auth in the API**: `TokenService` signs HS256 JWTs (`sub`, `org`, `roles`, `email`, `name`, `jti`, 60-minute `exp`); JWT bearer validation pins issuer, audience, algorithm and lifetime with a 30-second clock skew; `MapInboundClaims = false` keeps claim names short; a *fallback policy* makes every endpoint require authentication unless it opts out.
6. **Endpoints**: register-org (org + owner in one transaction), login (lockout, identical answers for unknown/wrong/locked, dummy-hash timing equaliser), logout (a no-op on the server, honestly documented), `me`; notes CRUD + export; admin users list/create/set-roles/revoke-sessions with privilege-escalation guards.
7. **Validation** with .NET 10's built-in minimal-API validation (`AddValidation()` + data annotations on request records): 400 with field errors before the endpoint runs.
8. **Smoke-tested against Compose with curl**, which surfaced the captive-dependency startup failure.
9. **Integration tests (39 new, 45 total)**: one migrated database for the whole run, isolation by giving every test its own randomly named org. Covers registration, conflicts, validation, login, lockout, six kinds of forged/invalid tokens, notes sharing rules, export, tenant isolation, mass assignment, roles, and the B1 behaviour.
10. **Mutation-checked the isolation tests**: removed the query filter, and 5 tests failed (3 isolation + 2 notes). Restored.
11. **SPA**: API client with problem-details errors, auth context holding the token in memory, login/register page, notes page (list, edit, share, delete, export download). 6 new Vitest tests.
12. **Ran Break B1** with a script against the real API, then again with 2-minute tokens to measure the whole window (see [the report](../../experiments/B1-stateless-jwt.md)).

## Decisions

| Decision | Alternative | Why |
| --- | --- | --- |
| `AddIdentityCore` + our own JWTs | Full Identity with cookie sign-in, or Identity's bearer-token endpoints | We need control over token contents and, in M3, over session ids. Identity's built-in bearer tokens are opaque and not designed for this revocation story. |
| Explicit lockout calls (`IsLockedOutAsync`, `AccessFailedAsync`, `ResetAccessFailedCountAsync`) | `SignInManager.CheckPasswordSignInAsync` | Same behaviour, but every step is visible in our code, and no cookie-auth plumbing is pulled in. |
| Same 401 + dummy hash for unknown / wrong / locked | Distinct messages ("no such user", "locked") | Prevents user enumeration by message *and* by timing. Cost: a locked-out user isn't told why. |
| EF Core global query filter for tenancy | Remember `.Where(n => n.OrgId == ...)` in every query | One place, applied to every query including future ones; tests prove it matters. The `users` table is *not* filtered (login must find a user before knowing their org), so admin queries filter explicitly. |
| 404 for notes you can't read, 403 for shared notes you can't edit | Always 403 | 404 hides existence; 403 is fine when the caller can already see the note. |
| Unique index on `normalized_email` + catch unique violations → 409 | Trust Identity's `RequireUniqueEmail` | Application checks race; only the database can guarantee uniqueness. |
| snake_case tables, Identity tables renamed (`users`, `user_roles`...) | Identity defaults (`"AspNetUsers"`) | Matches the spec and PostgreSQL convention; future hand-written SQL needs no quoted identifiers. |
| One shared test database, unique org per test | Fresh database per test, or Respawn cleanup | Tenant data is naturally partitioned, so random orgs isolate tests for free and the suite stays fast (~15 s). Tests that need a broken app make their own factory. |
| `Database:MigrateOnStartup` for dev; fixture migrates once in tests | Always migrate on startup | Parallel test factories racing to migrate one database is asking for trouble; deployments will migrate as a separate privileged step (M10). |
| Password policy: length ≥ 12, no composition rules | Identity defaults (digit, upper, symbol, 6+) | NIST SP 800-63B; "Password1!" satisfies composition rules and is terrible. |
| No router in the SPA yet | React Router now | Two screens. Routing arrives with the admin screens in M5. |
| Client IP resolution moved to M3 | Do it in M2 as ADR-0007 said | Nothing records an IP until sessions exist in M3. ADR milestone metadata updated. |
| Added `POST /api/admin/users` to the spec | | The spec had no way to add a second user to an org, which tenant/role tests and demos need. |

## Commands I ran

    dotnet new tool-manifest && dotnet tool install dotnet-ef
    dotnet ef migrations add InitialIdentityOrgsNotes --project src/ThreatLock.Infrastructure \
        --startup-project src/ThreatLock.Infrastructure --output-dir Persistence/Migrations
    dotnet ef migrations script --project src/ThreatLock.Infrastructure --startup-project src/ThreatLock.Infrastructure -o /tmp/m.sql
    dotnet ef migrations remove --force      # after fixing the model, regenerate

    dotnet test                               # 59 passed
    # mutation check: comment out note.HasQueryFilter(...) → 5 failures → restore

    cd web && npm run lint && npm test && npm run build

    dotnet run --project src/ThreatLock.Api
    scripts/experiments/b1-stateless-jwt.sh
    Auth__AccessTokenMinutes=2 dotnet run --project src/ThreatLock.Api
    POLL=1 POLL_INTERVAL=1 scripts/experiments/b1-stateless-jwt.sh

## What broke / surprised me

- **Generated migrations failed the build.** Analyzers (warnings as errors) judged EF's generated code. Fix: mark `**/Migrations/*.cs` as `generated_code = true` in `.editorconfig` instead of weakening rules globally.
- **Identity ignores the naming convention.** It sets explicit table names (`"AspNetUsers"`) and index names, which win over conventions. Renamed the tables explicitly.
- **Email wasn't unique in the database.** Identity's default index on `NormalizedEmail` is not unique; uniqueness was only checked in code. Two simultaneous sign-ups could both pass. Added a unique index and turned the violation into a 409.
- **The API refused to start: captive dependency.** My singleton `DummyPasswordHash` asked for Identity's *scoped* `IPasswordHasher`. Development enables DI scope validation, which caught it at startup. (In Production, without validation, it would have silently kept one per-request instance forever.)
- **A unit test caught an off-by-one in `Slug.From`.** Appending `-x` after reaching 49 characters produced 51. Cut to length, *then* trim the trailing hyphen.
- **Claims are frozen into tokens.** After an owner promoted a user to admin, the user's existing token still said `member`; the new role applied only after the next login. Same root cause as B1: the token is a snapshot of the past. A test now documents it.
- **`python3` on Windows is a Store stub.** The experiment script detects a working interpreter.

## Numbers

| Metric | Value | Conditions |
| --- | --- | --- |
| Tests | 59 .NET (14 unit + 45 integration), 9 frontend | All green |
| Full .NET test run | ~15 s | Containers already pulled |
| B1: stolen token accepted after logout + admin revoke | yes (`200` on `/api/notes/export`) | 60-minute tokens, local |
| B1: remaining validity at revocation | 3,599 s | 60-minute tokens |
| B1: measured continued access after revocation | **149.5 s** = 119 s remaining + 30 s clock skew ([report](../../experiments/B1-stateless-jwt.md)) | 2-minute tokens, polled every 1 s |

## What I'd explain in an interview

I first built authentication the way many tutorials do, with long-lived stateless JWTs, to demonstrate why it's dangerous: after the user logged out *and* an admin revoked their sessions, a copied token still downloaded all their notes until it expired. Along the way I put tenant isolation in a single EF Core query filter and proved it matters by deleting it and watching five tests fail. I closed user enumeration both by message and by timing, and pushed uniqueness guarantees into the database because application-level checks race.

## Open threads

- Real revocation: sessions, short tokens, refresh rotation (M3, B1 prove).
- Client IP resolution with trusted proxies (M3).
- Security headers (CSP etc.) once the API serves the SPA (M10).
- Generating the SPA's TypeScript types from OpenAPI (later; hand-written for now).
- Lockout as a DoS lever: per-IP rate limiting is a stretch goal.
