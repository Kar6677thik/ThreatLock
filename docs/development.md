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

The Break B1 experiment is scripted: `scripts/experiments/b1-stateless-jwt.sh` (see [the report](experiments/B1-stateless-jwt.md)).

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
| `Auth:AccessTokenMinutes` | `60` | Deliberately long in M2 for Break B1; M3 lowers it to 5 |
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
| Experiment script says `Python was not found` | On Windows, `python3` can be a Microsoft Store stub | The scripts detect this and fall back to `python` |
| Worker fails at startup: `ConnectionStrings:Postgres is required` | Running with environment `Production`, so dev settings weren't loaded | Use `dotnet run` (it reads `launchSettings.json`, which sets `DOTNET_ENVIRONMENT=Development`) |
