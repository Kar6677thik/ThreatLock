# 0008. Deploy to home-server k3s via GitHub Actions over Tailscale, tailnet only

- Status: Accepted (details finalised in M10)
- Date: 2026-10-22
- Milestone: M10

## Context

The target is a single home server that already runs k3s for other projects, has no Docker, and is reachable over Tailscale. Requirements: deploys happen **only** through GitHub Actions (never by hand), the app must not be reachable from the public internet, and CI must not get broad root access to the server.

## Decision

1. CI builds and tests on every PR. On `main`, it builds the `threatlock-api` image (with the SPA baked in) and the `threatlock-worker` image, and pushes both to GHCR tagged with the commit SHA. The repository is public, so k3s can pull without credentials.
2. The deploy job joins the tailnet as an **ephemeral, tagged** node through a Tailscale OAuth client. Tailnet ACLs allow that tag to reach only SSH on the server.
3. It connects with a **dedicated deploy SSH key** (not a personal key), uploads that commit's manifests to a per-commit directory, and runs a **root-owned helper script** permitted by a narrow `sudoers` rule. The helper only applies ThreatLock manifests in the `threatlock` namespace: migration Job first, then Deployments pinned to image digests, then it waits for rollout.
4. Runtime secrets (JWT key, DB passwords, simulator key) come from GitHub environment secrets and are written to a Kubernetes Secret by the helper. They never appear in the repository or logs.
5. Exposure is tailnet-only with `tailscale serve`.

One-time bootstrap steps that need `sudo` are a checklist the owner runs personally.

## Alternatives considered

- **Self-hosted GitHub runner on the server:** no inbound SSH needed, but letting a public repository's workflows (including ones from forks) run on your home machine is a serious risk.
- **Pull-based GitOps (Argo CD / Flux):** the best practice at scale, heavy for one app on a small shared server. A possible later project.
- **Public via Cloudflare Tunnel:** shareable, but a deliberately attackable lab app with a spoofable-IP simulation mode does not belong on the internet.

## Consequences

- Rollback is "re-run the deploy workflow for an older commit".
- The server's k3s storage class and free memory need checking in M10.
- Server addresses and usernames are configuration (GitHub secrets), never written into the docs of a public repository.
