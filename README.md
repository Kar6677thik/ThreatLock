# ThreatLock

Detect a stolen session and kill it in seconds, not hours.

ThreatLock is a learning-scale rebuild of Slack's **Anomaly Event Response** (2025): a small multi-tenant notes app with real logins, plus a security pipeline that

1. **detects** suspicious activity (Tor exit nodes, impossible travel, scraping, new device followed by bulk export, session hijack signals),
2. **decides** what to do using each organisation's own policy, exclusions and per-user baselines, and
3. **responds** automatically by revoking every session of the affected user, writing a tamper-evident audit entry, and notifying admins exactly once.

> **Status:** M9, measured. All five detectors run, each org's policy decides, and the Worker responds idempotently ([B4](docs/experiments/B4-idempotent-responder.md)). On a labelled dataset of 1,200 scenario instances every attack was caught, and benign users were signed out only in the deliberately included legitimate-migration scenario plus one statistical outlier. A stolen session is revoked, as the attacker sees it, in **p95 199 ms** (Tor) and **142 ms** (replayed token) ([evaluation](docs/experiments/Eval-detection-and-time-to-revoke.md)). Every security action is hash-chained ([B5](docs/experiments/B5-audit-tamper.md)). Next: deployment to the home server (M10). See the [roadmap](docs/spec/SPEC.md#21-milestones).

## Run it locally

```bash
docker compose -f deploy/compose/docker-compose.yml up -d --wait
dotnet run --project src/ThreatLock.Api      # http://127.0.0.1:5080
dotnet run --project src/ThreatLock.Worker
cd web && npm install && npm run dev         # http://localhost:5173
```

Prerequisites, tests, configuration and troubleshooting: [docs/development.md](docs/development.md).

## Where to start reading

| If you want to... | Read |
| --- | --- |
| Understand what we are building and why | [docs/spec/SPEC.md](docs/spec/SPEC.md) |
| Learn the concepts before the code | [docs/learning/concepts.md](docs/learning/concepts.md) |
| See why each big choice was made | [docs/adr/](docs/adr/README.md) |
| Follow the build step by step | [docs/learning/journal/](docs/learning/journal/README.md) |
| Build, run and test locally | [docs/development.md](docs/development.md) |
| Find a specific doc | [docs/README.md](docs/README.md) |

## Stack

C# / ASP.NET Core (.NET 10) with ASP.NET Core Identity · React + Vite + TypeScript · PostgreSQL · Redis (Streams + cache) · xUnit + Testcontainers · Docker Compose for local dev · k3s on a home server, deployed by GitHub Actions over Tailscale.

## Data sources

- IP Geolocation by [DB-IP](https://db-ip.com) (DB-IP Lite, CC BY 4.0), downloaded by `scripts/download-geoip.sh`.
- Tor exit list from the [Tor Project](https://check.torproject.org/torbulkexitlist).

## Inspiration

- Slack Engineering, [Building Slack's Anomaly Event Response](https://slack.engineering/building-slacks-anomaly-event-response/)
- InfoQ, [Slack's AER security system](https://www.infoq.com/news/2025/10/slack-aer-security-system)

All attacks in this repository are run only against our own app.
