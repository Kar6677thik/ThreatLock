# 0001. Stack: .NET 10, React + Vite, PostgreSQL, Redis

- Status: Accepted
- Date: 2026-10-22
- Milestone: M0

## Context

The project guide allows "ASP.NET Core or Python, choose most suitable" and names ASP.NET Core Identity, PostgreSQL, Redis, a background worker and a small admin UI. The .NET 10 SDK is already installed, and another project (Slate) runs ASP.NET Core on the same home server.

## Decision

- **Backend:** C# on .NET 10 (LTS). ASP.NET Core minimal APIs for the API, ASP.NET Core Identity for users and password hashing, a .NET Generic Host with `BackgroundService`s for the Worker.
- **Data access:** EF Core with Npgsql for normal CRUD and migrations; hand-written SQL where precision matters (job claiming with `SKIP LOCKED`, audit append under an advisory lock).
- **Database:** PostgreSQL 17.
- **Cache and stream:** Redis, via StackExchange.Redis.
- **Frontend:** React + Vite + TypeScript single-page app, built to static files and served by the API container.
- **Tests:** xUnit, Testcontainers for real PostgreSQL and Redis, Vitest for the SPA, Playwright for one end-to-end smoke test.

Exact package versions are pinned in M1 and recorded in the journal.

## Alternatives considered

- **Python + FastAPI:** quicker for statistics and dataset generation, but there's no equivalent of Identity, so login, lockout and password hashing would have to be assembled by hand. That's exactly where beginners introduce security bugs. It also departs from the guide's default stack.
- **Razor Pages instead of an SPA:** least tooling, but it pushes the whole app toward cookie authentication, which hides the bearer-token revocation problem that Break B1 is about.
- **Plain HTML + fetch:** too clunky for an admin UI with filters, forms and detail pages.

## Consequences

- One language for API, Worker, Simulator and tests; the Simulator can reuse Core detector code for replay.
- We learn a second toolchain (Node, Vite, npm) for the SPA; keep it small.
- The deploy pattern from Slate (ASP.NET Core on k3s) transfers almost unchanged.
