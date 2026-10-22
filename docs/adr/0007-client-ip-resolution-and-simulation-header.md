# 0007. Client IP from trusted proxies only, plus a keyed simulation header

- Status: Accepted
- Date: 2026-10-22
- Milestone: M2 (resolution), M4 (simulation)

## Context

Detectors are only as good as the client IP. `X-Forwarded-For` is trivially spoofable if trusted blindly. But every test we run comes from one home network, so to exercise geography we must be able to *pretend* to be elsewhere.

## Decision

- Use ASP.NET Core `ForwardedHeaders` with an explicit list of known proxy networks, and ignore forwarding headers from anyone else.
- When `Simulation:Enabled=true` **and** `X-Simulator-Key` matches a secret, use `X-Simulated-Client-Ip` instead. Mark such events `simulated=true`.
- Simulation is acceptable on the home server only because the deployment is tailnet-only (ADR-0008). It must be disabled if ThreatLock is ever exposed publicly.

## Alternatives considered

- **Trust `X-Forwarded-For` from anyone:** the classic spoofing bug; an attacker picks the IP our detectors see.
- **Real proxies or VPN exits in other countries for tests:** costly, slow and not reproducible.
- **Only offline replay for geography:** we would never test the real request path end to end.

## Consequences

- The simulator key is a real secret in deployment.
- Reports must say which events were simulated.
