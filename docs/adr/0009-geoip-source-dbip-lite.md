# 0009. GeoIP from DB-IP Lite City (CC BY 4.0)

- Status: Accepted
- Date: 2026-10-22
- Milestone: M4

## Context

Impossible travel needs IP → latitude/longitude. The common free sources are MaxMind GeoLite2 (requires an account and licence key) and DB-IP Lite (downloadable without an account, Creative Commons Attribution licence). Both ship the `.mmdb` format.

## Decision

Use **DB-IP IP to City Lite** in `.mmdb` format, read with the `MaxMind.Db` library behind an `IGeoIpLookup` interface. A script downloads it into `data/geoip/` (git-ignored), and the container build does the same. Show the required attribution ("IP Geolocation by DB-IP") in the README and the admin UI footer. Tests use a tiny fake lookup, not the real file.

## Alternatives considered

- **MaxMind GeoLite2:** slightly better known, but needs an account and a licence key in CI. Swappable later thanks to the interface and identical file format.
- **Online GeoIP APIs:** rate limits, latency on every event, and we would be sending users' IPs to a third party.

## Consequences

- Lite databases are city-level and often wrong by hundreds of kilometres, which is why D2 subtracts accuracy radii and ignores short distances.
- The database should be refreshed monthly; the pipeline pulls the latest one at image build time.
