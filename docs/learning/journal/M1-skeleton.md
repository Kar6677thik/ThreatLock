# M1. Skeleton

- Dates: 2026-10-22 →
- PR(s): M1 skeleton PR
- Spec sections: §5.1 components, §17 testing, §18 observability (health), §20.1 local development
- Concepts: [6.2 Testable time](../concepts.md#62-testable-time-timeprovider-fg-23), [6.3 Testcontainers](../concepts.md#63-testcontainers-fg-23)

## Goal

Every project from spec §5.1 exists, builds with zero warnings, and has the plumbing later milestones rely on: configuration, connections to PostgreSQL and Redis, liveness and readiness endpoints, unit and integration test projects that run against real databases, a SPA that talks to the API, a Compose file for local dependencies, and CI on every pull request. There are no features yet. Done when `dotnet test`, `npm test` and CI are green.

Why a whole milestone for "nothing"? Every later milestone adds code *and* tests. If the test harness, the build rules and the CI are wobbly, every milestone pays for it. Getting them right once, while the codebase is tiny, is the cheapest it will ever be.

## What I did, in order

1. **Pinned the toolchain** (`global.json`: SDK 10.0.401, roll forward to later 10.0 feature bands). *Why first:* a build that works with "whatever SDK is installed" eventually breaks on someone else's machine or in CI.
2. **Created the solution and seven projects** with `dotnet new` and the new `.slnx` solution format: Core, Infrastructure, Api, Worker, Simulator, Core.Tests, IntegrationTests. *Why all seven now:* the dependency arrows (Api → Infrastructure → Core, never Core → anything) are easiest to set before code exists to tangle them.
3. **Centralised build settings** in `Directory.Build.props` (nullable reference types, warnings as errors, recommended analyzers, code style enforced at build) and **package versions** in `Directory.Packages.props` (central package management). *Why:* one place to read and change; no project can drift onto a different package version.
4. **Wrote the Infrastructure registration** (`AddThreatLockInfrastructure`): one `NpgsqlDataSource` (owns the connection pool), one Redis `ConnectionMultiplexer` (thread-safe, designed to be shared), options validated at startup, and two readiness health checks. Both API and Worker call it, so they connect identically.
5. **API: `/healthz`, `/readyz`, `/api/info`**, problem-details error responses, JSON logs outside Development, `TimeProvider` registered. *Why two health endpoints:* see "Decisions".
6. **Worker: `DependencyHeartbeat`**, a `BackgroundService` that runs the readiness checks every 30 s and logs only when the status changes. It proves the Worker host is wired up; M4 adds the real consumers next to it.
7. **Tests.** Unit: an *architecture test* asserting Core references no infrastructure assemblies. Integration: Testcontainers starts PostgreSQL 17.11 and Redis 8.10.2 once per test run (xUnit v3 assembly fixture); `WebApplicationFactory` boots the real API in memory against them; tests cover liveness, readiness when healthy, readiness 503 for each dependency down, and liveness staying 200 during an outage.
8. **Proved the architecture test can fail** by temporarily adding an `HttpClient` reference to Core: the test failed naming `System.Net.Http`, then I removed it. *Why:* a test you've never seen fail might not be testing anything.
9. **Compose file** for local PostgreSQL + Redis, bound to `127.0.0.1` only, with health checks and named volumes.
10. **Ran the real API and Worker against Compose**, then stopped Redis by hand to watch readiness change. This found two real problems (see "What broke").
11. **SPA shell**: `create-vite` React + TypeScript template, stripped of demo content; a `SystemStatus` component calling `/api/info` and `/readyz` through `src/api/`; the Vite dev proxy so the browser sees one origin; Vitest + Testing Library with three tests (healthy, 503 dependency down, API unreachable).
12. **CI workflow**: two parallel jobs (backend, frontend) on every PR and push to `main`, read-only permissions, actions pinned to commit SHAs, cancel superseded PR runs.

## Decisions

| Decision | Alternative | Why |
| --- | --- | --- |
| Separate `/healthz` (no checks) and `/readyz` (PostgreSQL + Redis) | One `/health` that checks everything | Kubernetes *restarts* pods failing liveness. If liveness checked the database, a database blip would restart every healthy API pod at once and make the outage worse. Readiness only removes the pod from traffic. |
| Fail-fast Redis client (`BacklogPolicy.FailFast`, 2 s timeouts) | Library defaults (queue commands while disconnected, 5 s timeout) | Measured: readiness during a Redis outage went from **6.1 s to 47 ms**. M3's session check must fall back to PostgreSQL quickly, not wait for Redis to come back. |
| `AbortOnConnectFail = false` | Crash at boot if Redis is down | The process should start and become ready when Redis appears; Kubernetes handles the waiting. Whether a feature can work *without* Redis is decided per feature. |
| Options validated at startup (`ValidateOnStart`) | Discover a missing connection string on first use | Fail fast with a clear message at deploy time, not a confusing error on the first request. |
| Services resolve connection strings lazily from `IOptions` | Read `builder.Configuration` in `Program.cs` | `WebApplicationFactory` overrides configuration after `Program.cs` starts running. Lazy resolution means tests can point the app at their containers. |
| xUnit v3 on Microsoft.Testing.Platform | xUnit v2 / VSTest | The .NET 10 SDK no longer runs this setup through VSTest. MTP is the new default runner; test projects are now plain executables. |
| One set of containers per test run (assembly fixture) | Containers per test class | PostgreSQL takes seconds to start. Per-test databases (for isolation) come in M2, inside this one server. |
| Underscored test names (`Readyz_is_503_when...`), CA1707 off for `tests/` only | Analyzer default (no underscores) | Test names are sentences that show up in failure output. The rule still applies to production code. |
| Source-generated logging (`[LoggerMessage]`) | `logger.LogInformation(...)` | The analyzers demand it (CA1848/CA1873): no formatting or allocation when a level is disabled. A good habit before the hot paths of M4 exist. |
| Compose PostgreSQL on host port **5433** | 5432 | This machine already runs a native PostgreSQL on 5432 (left untouched). Configurable via `POSTGRES_PORT`. |
| GitHub Actions pinned to commit SHAs | `@v7` tags | A tag can be moved to different code by whoever controls the action repository; a SHA can't (supply-chain security, FG 25.27). |
| Redis 8.10.2 (resolves spec Q2) | Valkey | Official image, the client library targets it, nothing in our usage differs. |
| Static SPA serving from the API: **deferred to M10** | Wire up now | Nothing to serve until there's a Dockerfile that builds the SPA into the API image. In development the Vite proxy gives the same single-origin setup. |

## Commands I ran

    dotnet new globaljson --sdk-version 10.0.401 --roll-forward latestFeature
    dotnet new sln -n ThreatLock                     # creates ThreatLock.slnx on .NET 10
    dotnet new classlib|web|worker|console -n ThreatLock.<Name> -o src/ThreatLock.<Name>
    dotnet add <project> package <Name>              # with central management, writes the version to Directory.Packages.props
    dotnet add <project> reference <other project>
    dotnet sln add src/*/*.csproj --solution-folder src

    dotnet build                                     # must show 0 warnings
    dotnet test                                      # 8 passed

    docker compose -f deploy/compose/docker-compose.yml up -d --wait
    dotnet run --project src/ThreatLock.Api
    curl -s -w ' %{http_code}\n' localhost:5080/readyz
    docker compose -f deploy/compose/docker-compose.yml stop redis   # outage drill
    curl -s -o /dev/null -w '%{http_code} %{time_total}s\n' localhost:5080/readyz

    npx create-vite@latest web --template react-ts
    npm install -D vitest jsdom @testing-library/react @testing-library/jest-dom
    npm run lint && npm test && npm run build

    gh api repos/actions/checkout/commits/v7.0.1 --jq .sha   # resolve a tag to a SHA for pinning

## What broke / surprised me

- **`dotnet test` refused to run** ("Testing with VSTest target is no longer supported"). .NET 10 SDK + xUnit v3 → opt into Microsoft.Testing.Platform in `global.json`, and drop `Microsoft.NET.Test.Sdk` and `xunit.runner.visualstudio`, which only exist for VSTest.
- **Port 5432 already in use**: a native PostgreSQL on this machine. Didn't stop it; moved Compose to 5433.
- **Redis "Unhealthy" while the container was healthy.** `localhost` resolved to IPv6 `::1` first, and Docker Desktop publishes the port on IPv4 `127.0.0.1` only. Npgsql quietly tries the next address; StackExchange.Redis doesn't. Fix: use `127.0.0.1` in dev settings. Lesson: "localhost" is a name, not an address.
- **Readiness took 6 s to say "Redis is down".** The health check's 3 s timeout only cancels a token, and `PING` doesn't accept one. The client was also *queueing* the command, waiting for a reconnect. Fix: fail-fast backlog policy + 2 s command timeout → 47 ms.
- **Analyzers rejected a single `LogInformation` call.** Fixed properly with a source-generated `StartupLog` instead of suppressing the rule.
- **The SPA template had no `"strict": true`.** TypeScript 6 turns strict on by default, but it's now set explicitly so the setting doesn't depend on knowing that.

## Numbers

| Metric | Value | Conditions |
| --- | --- | --- |
| `/readyz` response time with Redis stopped, before fix | 6.16 s | Local, Windows 11, Docker Desktop |
| `/readyz` response time with Redis stopped, after fix | 4–47 ms | Same (first request slowest) |
| Full .NET test run | ~34 s | Includes pulling/starting both containers; unit tests alone ~1 s |
| SPA production bundle | 221 kB JS (69 kB gzipped) | React 19, no router yet |

## What I'd explain in an interview

I set the project up so the rules are enforced by tools rather than memory: warnings fail the build, package versions live in one file, and an architecture test fails if the detection code ever starts doing I/O. Liveness and readiness are separate on purpose: a database outage should take pods out of rotation, not trigger a restart storm. Integration tests run against real PostgreSQL and Redis in throwaway containers, because the things we depend on later (`SKIP LOCKED`, advisory locks, Redis Streams) can't be mocked honestly. Running the real stack and pulling Redis out from under it found two bugs no unit test would have: an IPv6 `localhost` mismatch and a 6-second readiness probe, now 47 ms.

## Open threads

- Per-test database isolation (template database or Respawn): M2, when there are tables.
- Serving the built SPA from the API, Dockerfiles, image build in CI: M10.
- Worker readiness for Kubernetes (it has no HTTP port; exec or file-based probe): M10.
- Code coverage reporting in CI: nice to have; revisit after M3.
