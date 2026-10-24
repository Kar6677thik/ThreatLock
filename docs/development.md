# Local development

How to build, run and test ThreatLock on your own machine.

## Prerequisites

| Tool | Version | Why |
| --- | --- | --- |
| .NET SDK | 10.0.4xx (pinned in `global.json`) | API, Worker, Simulator, tests |
| Node.js | 24 (pinned in `web/.nvmrc`) | SPA dev server, build and tests |
| Docker (Desktop on Windows/macOS) | any recent | Local PostgreSQL + Redis, and Testcontainers in integration tests |

## Repository layout

```
ThreatLock/
├── ThreatLock.slnx                 Solution (new XML format)
├── global.json                     Pins the SDK; selects the Microsoft.Testing.Platform test runner
├── Directory.Build.props           Compiler settings for every project (nullable, warnings = errors, analyzers)
├── Directory.Packages.props        Every NuGet version, in one place (central package management)
├── .editorconfig                   Formatting + analyzer severities (tests/.editorconfig relaxes naming)
├── src/
│   ├── ThreatLock.Core/            Domain + detectors. No I/O (enforced by a test)
│   ├── ThreatLock.Infrastructure/  PostgreSQL, Redis, health checks
│   ├── ThreatLock.Api/             HTTP API (port 5080 in dev)
│   ├── ThreatLock.Worker/          Background processing
│   └── ThreatLock.Simulator/       Attack + evaluation CLI (M9)
├── tests/
│   ├── ThreatLock.Core.Tests/      Unit tests, no Docker
│   └── ThreatLock.IntegrationTests/ Real PostgreSQL + Redis via Testcontainers
├── web/                            React + Vite + TypeScript SPA (port 5173 in dev)
├── deploy/compose/                 Docker Compose for local dependencies
└── docs/                           Spec, ADRs, learning notes, experiment reports
```

## Run everything

```bash
# 0. GeoIP database, ~120 MB, git-ignored (first time, then monthly). Optional: without it
#    locations are "unknown" and impossible travel never fires.
scripts/download-geoip.sh

# 1. Dependencies (PostgreSQL on 127.0.0.1:5433, Redis on 127.0.0.1:6379)
docker compose -f deploy/compose/docker-compose.yml up -d --wait

# 2. API  (terminal 1)  ->  http://127.0.0.1:5080
dotnet run --project src/ThreatLock.Api

# 3. Worker  (terminal 2)
dotnet run --project src/ThreatLock.Worker

# 4. SPA  (terminal 3)  ->  http://localhost:5173
cd web
npm install        # first time only
npm run dev
```

Open http://localhost:5173. The page shows the running version and whether PostgreSQL and Redis are reachable.

### Useful URLs

| URL | Meaning |
| --- | --- |
| `http://127.0.0.1:5080/healthz` | Liveness: is the process up? Always 200 while it runs |
| `http://127.0.0.1:5080/readyz` | Readiness: are PostgreSQL and Redis reachable? 200 or 503, with JSON naming each dependency |
| `http://127.0.0.1:5080/api/info` | Name, version (including commit), environment |

### Try an outage

```bash
docker compose -f deploy/compose/docker-compose.yml stop redis
curl -i http://127.0.0.1:5080/readyz     # 503, "redis":"Unhealthy", answers in milliseconds
curl -i http://127.0.0.1:5080/healthz    # still 200: the process itself is fine
docker compose -f deploy/compose/docker-compose.yml start redis
```

### Try the app from the command line

```bash
B=http://127.0.0.1:5080; J='Content-Type: application/json'

# Create an org; the response contains an access token for its owner.
curl -s -H "$J" -d '{"orgName":"Acme","displayName":"Asha","email":"asha@acme.test","password":"correct horse battery"}' $B/api/auth/register-org

# Sign in and keep the token.
T=$(curl -s -H "$J" -d '{"email":"asha@acme.test","password":"correct horse battery"}' $B/api/auth/login | python -c "import sys,json;print(json.load(sys.stdin)['accessToken'])")

curl -s -H "Authorization: Bearer $T" -H "$J" -d '{"title":"Hello","body":"first note","shared":true}' $B/api/notes
curl -s -H "Authorization: Bearer $T" $B/api/notes
curl -s -H "Authorization: Bearer $T" -H "$J" -d '{"email":"ben@acme.test","displayName":"Ben","password":"another long password","roles":["admin"]}' $B/api/admin/users

# Peek inside the token (it's signed, not encrypted: never put secrets in it).
echo $T | cut -d. -f2 | python -c "import sys,base64;s=sys.stdin.read().strip();print(base64.urlsafe_b64decode(s+'='*(-len(s)%4)).decode())"
```

### Watch detection work

With the API and the Worker running (the Worker downloads the live Tor exit list at startup):

```bash
scripts/experiments/m4-detection-smoke.sh
```

It signs in from a simulated Indian IP, uses the session from a UK IP, then signs in through a real Tor exit, and prints the anomalies the Worker created, e.g.:

```
  impossible_travel  medium  events=1  Bengaluru, IN -> London, GB: 7933 km in 0.0 s  simulated=True
  tor                high    events=2  171.25.193.25 (SE) on login_succeeded  simulated=True
```

In the SPA (signed in as an owner or security admin): **Anomalies** lists them with filters and links to each anomaly's evidence and decision; **Policy** edits the org's policy (try switching Tor to *observe*, then rerun the smoke test: the new anomaly says `observed`, policy v1); **Users** adds people and signs them out everywhere. The screens you see depend on your roles.

From M6 the Worker also **acts**. A responded anomaly gets a response job: the user's sessions are revoked (their next request gets `401`), and the admins get a notification. Watch the **Notifications** badge, the anomaly page's **Response** timeline, and, for security admins, **Jobs** (failed and dead jobs, with Retry). To see a lock, set the policy's response action to `revoke_and_lock`. **Wait 10 s** (the Worker's policy cache), then sign in through Tor again. The user's next login gets `403` "locked after suspicious activity" until someone presses **Unlock** on the Users screen.

From M7 every security action is also written to the org's **audit log**, a hash chain (security admins: **Audit log** screen). **Verify chain** recomputes every hash. When the chain is intact it also gives you the head (seq and hash); save it somewhere outside ThreatLock and paste it back in as an anchor later. To see tampering, run `scripts/experiments/b5-audit-tamper.sh` (it edits the database directly; development only) and sign in as the owner it creates.

Simulated IPs work only because Development enables `Simulation` with a dev key (ADR-0007). To poke around yourself: `GET /api/admin/anomalies` as an admin; the stream with `docker compose -f deploy/compose/docker-compose.yml exec redis redis-cli XINFO GROUPS tl:events`; events with `SELECT type, host(ip), geo->>'city' FROM activity_events ORDER BY occurred_at DESC LIMIT 10;`.

The refresh cookie is `Secure`, so curl (unlike a browser) won't send it back over plain `http://127.0.0.1`. To try refresh from the command line, copy the `tl_refresh` value from the login response's `Set-Cookie` header and send it yourself:

```bash
curl -s -i -H "$J" -d '{"email":"asha@acme.test","password":"correct horse battery"}' $B/api/auth/login | grep -i set-cookie
curl -s -X POST -H "X-Requested-With: threatlock" -H "Cookie: tl_refresh=<value>" $B/api/auth/refresh
curl -s -H "Authorization: Bearer $T" $B/api/me/sessions     # where you're signed in
```

The Break B1 experiment is scripted: `scripts/experiments/b1-stateless-jwt.sh` (see [the report](experiments/B1-stateless-jwt.md)); `scripts/experiments/session-check-latency.py` measures what the session check costs per request. Break B5 is `scripts/experiments/b5-audit-tamper.sh` (needs the API running; [report](experiments/B5-audit-tamper.md)). Break B4 is `scripts/experiments/b4-responder-crashes.sh`. It needs only Docker, not the running app: it runs the 100-crash test at the tag `break/b4-naive-responder` and at your commit, and prints both results ([report](experiments/B4-idempotent-responder.md)).

## Database migrations

The schema is defined by the EF Core model in `src/ThreatLock.Infrastructure/Persistence` and versioned as migrations in `Persistence/Migrations`. In Development the API applies pending migrations at startup (`Database:MigrateOnStartup`). Deployments will run them as a separate step (M10).

```bash
dotnet tool restore     # installs the pinned dotnet-ef from dotnet-tools.json (first time only)

# After changing the model: create a migration, then READ the generated file before committing.
dotnet ef migrations add <Name> --project src/ThreatLock.Infrastructure --startup-project src/ThreatLock.Infrastructure --output-dir Persistence/Migrations

# See the SQL a migration will run.
dotnet ef migrations script --project src/ThreatLock.Infrastructure --startup-project src/ThreatLock.Infrastructure

# Start from scratch locally (deletes all local data).
docker compose -f deploy/compose/docker-compose.yml down -v
```

Using the Infrastructure project as its own startup project means `dotnet ef` doesn't boot the API; `DesignTimeDbContextFactory` builds the model directly.

## Test

```bash
dotnet test                 # all .NET tests (integration tests need Docker running)
dotnet test --project tests/ThreatLock.Core.Tests   # unit tests only, no Docker

cd web
npm test                    # Vitest, once
npm run test:watch          # Vitest, re-run on save
npm run lint                # oxlint
npm run build               # type-check + production build into web/dist
```

## Configuration

Settings come from `appsettings.json`, then `appsettings.{Environment}.json`, then environment variables (later wins). Nested keys use `__` in environment variables, e.g. `ConnectionStrings__Redis=127.0.0.1:6379`.

| Key | Development default | Notes |
| --- | --- | --- |
| `ConnectionStrings:Postgres` | `Host=127.0.0.1;Port=5433;...` | Required; the app refuses to start without it |
| `ConnectionStrings:Redis` | `127.0.0.1:6379` | Required |
| `Auth:SigningKey` | a fixed dev-only key | Base64, ≥ 32 bytes. Anyone with it can mint tokens for any user; deployments use a secret |
| `Auth:Mode` | `SessionChecked` | `StatelessJwt` switches off the per-request session check. Only for reproducing Break B1 |
| `Auth:AccessTokenMinutes` | `5` | Access-token lifetime. B1 break runs use `60` |
| `Auth:SessionIdleTimeout` | `12:00:00` | A session dies after this long without a refresh |
| `Auth:SessionAbsoluteTimeout` | `7.00:00:00` | A session dies this long after login, however active |
| `Auth:RefreshReuseGrace` | `00:00:05` | Second use of a refresh token within this window → `409` (race); later → session revoked (theft) |
| `Auth:RefreshCookieSecure` | `true` | Browsers accept `Secure` cookies on `http://localhost`, so it stays on in development |
| `Simulation:Enabled`, `Simulation:Key` | `true`, a dev key | Lets requests with `X-Simulator-Key` choose their client IP via `X-Simulated-Client-Ip` (ADR-0007). **Must be off** anywhere reachable from the internet |
| `GeoIp:DatabasePath` | `../../data/geoip/dbip-city-lite.mmdb` | Relative to the app's content root. Missing file → warning, locations unknown |
| `GeoIp:DefaultAccuracyKm` | `50` | DB-IP Lite has no accuracy radius, so this is assumed for every point |
| `Events:StreamName`, `Events:ConsumerGroup`, `Events:ConsumerName` | `tl:events`, `detectors`, machine name | Redis stream wiring (Worker and API must agree on the stream) |
| `Events:MaxDeliveries`, `Events:ClaimIdle`, `Events:ClaimInterval` | `5`, `00:01:00`, `00:00:30` | When a pending message is reclaimed, and when it's dead-lettered |
| `Events:SweepInterval`, `Events:SweepMinAge`, `Events:RetentionDays` | `00:00:05`, `00:00:05`, `30` | Outbox sweeper and the activity-event purge |
| `Policy:CacheSeconds` | `10` | How long the Worker reuses an org's policy; a policy edit applies within this many seconds |
| `Responses:Enabled` | `true` | Whether this Worker runs response jobs. Off for extra Workers in tests |
| `Responses:PollInterval`, `Responses:Lease` | `00:00:00.250`, `00:01:00` | How often an idle Worker checks for due jobs (a NOTIFY usually wakes it first), and how long a claimed job is reserved before another Worker may take it |
| `Tor:ListUrl`, `Tor:ListPath`, `Tor:RefreshInterval` | Tor Project URL, none, `01:00:00` | Set `ListPath` to a local file to work offline |
| `Network:KnownProxies`, `Network:KnownNetworks` | empty | Proxies allowed to set `X-Forwarded-For` (IPs, CIDRs). Empty = trust nobody, use the TCP peer address (ADR-0007) |
| `Auth:Issuer`, `Auth:Audience` | `threatlock`, `threatlock-api` | Checked on every token |
| `Demo:AllowSignup` | `true` | Enables `POST /api/auth/register-org`; `false` returns 404 |
| `Database:MigrateOnStartup` | `true` | Apply migrations when the API starts. Off in tests (the fixture migrates once) and in deployment |

The development password in `appsettings.Development.json` and `.env.example` only protects a database bound to `127.0.0.1` on your own machine. Real secrets never go in files (SPEC §19).

To change Compose ports or credentials, copy `.env.example` to `.env` in the repository root (git-ignored) and run Compose with `--env-file .env`.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `ports are not available ... 5432` | A PostgreSQL is already installed on your machine | That's why Compose uses host port **5433**. Keep it, or set `POSTGRES_PORT` in `.env` and update the connection string |
| Redis `Unhealthy` locally but the container is up | Using `localhost`: on Windows it resolves to IPv6 `::1` first, while Docker publishes on IPv4 `127.0.0.1`. Npgsql retries the next address; StackExchange.Redis doesn't | Use `127.0.0.1`, as the dev settings do |
| `Testing with VSTest target is no longer supported` | .NET 10 SDK + xUnit v3 need the new test platform | Already set in `global.json` (`"test": { "runner": "Microsoft.Testing.Platform" }`) |
| Integration tests hang or fail to start containers | Docker isn't running | Start Docker Desktop |
| `Cannot consume scoped service ... from singleton` at startup | A singleton depends on a scoped service (captive dependency); Development turns on scope validation to catch this | Don't inject scoped services into singletons; see concepts.md §6.4 |
| Signed out after every page reload | The `Secure` refresh cookie isn't being stored or sent back | Open the SPA at `http://localhost:5173` (the setup verified in M3); browsers accept `Secure` cookies over plain http only on hosts they consider secure contexts, such as `localhost`. Don't open the API port directly |
| `401` with `error_description="session_revoked"` | The token is fine but its session was logged out, revoked or idle-expired | Sign in again (the SPA does this for you) |
| `503` on every authenticated request | The session check can reach neither Redis nor PostgreSQL, so it fails closed | Start the databases: `docker compose ... up -d` |
| API logs `GeoIP database not found` | `data/geoip/dbip-city-lite.mmdb` is missing | `scripts/download-geoip.sh` (the app works without it; impossible travel just never fires) |
| Worker logs `Restored N Tor exit addresses from the snapshot` | The Tor list download failed (offline?) and the last saved copy is in use | Fine for development; or set `Tor:ListPath` to a local file |
| No anomalies appear | The Worker isn't running, or the API and Worker use different `Events:StreamName` | Start the Worker; check `XINFO GROUPS tl:events` shows `lag 0` |
| A Tor login only revoked, though the policy says `revoke_and_lock` (or any policy edit "didn't apply") | The Worker reused the policy it had read in the last `Policy:CacheSeconds` (10 s). The anomaly page shows which policy version judged it | Wait 10 s after a policy edit. Tests set `Policy:CacheSeconds=0` |
| Worker logs `Could not claim response jobs` with `relation "response_jobs" does not exist` | The Worker started before the API applied the migrations | Harmless: it keeps retrying and recovers once the API has migrated |
| A user can't sign in: `403` "locked after suspicious activity" | A `revoke_and_lock` response locked the account | An owner or security admin presses **Unlock** on the Users screen |
| `audit_log is append-only: UPDATE is not allowed` (or DELETE, TRUNCATE) | A trigger blocks changes to the audit log for every role, on purpose (SPEC §11.3) | Don't change audit entries. To reset a development database, drop and recreate it (`docker compose ... down -v`) |
| Audit verify says `hash_mismatch` on a database nobody touched | Something changed the canonical form, or details hold a number format `jsonb` rewrites (e.g. `1e2`) | Never change `AuditChain.Canonical` for existing rows; keep details to strings, integers, booleans, arrays and objects |
| Experiment script says `Python was not found` | On Windows, `python3` can be a Microsoft Store stub | The scripts detect this and fall back to `python` |
| Worker fails at startup: `ConnectionStrings:Postgres is required` | Running with environment `Production`, so dev settings weren't loaded | Use `dotnet run` (it reads `launchSettings.json`, which sets `DOTNET_ENVIRONMENT=Development`) |
