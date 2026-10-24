#!/usr/bin/env bash
# M4 smoke test: real API + real Worker + real Tor list + real GeoIP database.
#   1. Sign in from a simulated Indian IP, then a few minutes' worth of events from a UK IP → D2.
#   2. Use a session from a live Tor exit address → D1.
#   3. Print the anomalies the Worker created.
#
# Needs: API with Simulation:Enabled=true (Development default) and the Worker running.
# Run only against your own ThreatLock instance.
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5080}"
SIM_KEY="${SIM_KEY:-dev-only-simulator-key-change-me}"
INDIA_IP="${INDIA_IP:-49.207.48.1}"
UK_IP="${UK_IP:-81.2.69.142}"
PASSWORD="correct horse battery staple"
RUN="$(date +%s)"
if python3 -c '' 2>/dev/null; then PY=python3; else PY=python; fi

json() { "$PY" -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }
as_ip() { local ip="$1"; shift; curl -sf -H "X-Simulator-Key: $SIM_KEY" -H "X-Simulated-Client-Ip: $ip" -H 'Content-Type: application/json' "$@"; }
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

TOR_IP="${TOR_IP:-$(curl -sf https://check.torproject.org/torbulkexitlist | sed -n 1p)}"   # sed reads it all; head would close the pipe early
log "Using India=$INDIA_IP UK=$UK_IP Tor=$TOR_IP"

OWNER=$(as_ip "$INDIA_IP" -d "{\"orgName\":\"Smoke $RUN\",\"orgSlug\":\"smoke-$RUN\",\"displayName\":\"Owner\",\"email\":\"owner-$RUN@smoke.test\",\"password\":\"$PASSWORD\"}" "$BASE_URL/api/auth/register-org" | json 'd["accessToken"]')
log "Owner registered from India."

# D2: same user, a moment later, from the UK (≈ 8,000 km in seconds).
as_ip "$UK_IP" -H "Authorization: Bearer $OWNER" "$BASE_URL/api/notes" > /dev/null
log "Same session used from the UK."

# D1: sign in again, this time through a Tor exit.
TOR_TOKEN=$(as_ip "$TOR_IP" -d "{\"email\":\"owner-$RUN@smoke.test\",\"password\":\"$PASSWORD\"}" "$BASE_URL/api/auth/login" | json 'd["accessToken"]')
as_ip "$TOR_IP" -H "Authorization: Bearer $TOR_TOKEN" "$BASE_URL/api/notes/export" > /dev/null
log "Signed in and exported through Tor."

for _ in $(seq 1 30); do
  COUNT=$(curl -sf -H "Authorization: Bearer $OWNER" "$BASE_URL/api/admin/anomalies" | json 'len(d)')
  [[ "$COUNT" -ge 2 ]] && break
  sleep 0.5
done

curl -sf -H "Authorization: Bearer $OWNER" "$BASE_URL/api/admin/anomalies" | "$PY" -c "
import sys, json
for a in json.load(sys.stdin):
    e = a['evidence']
    if a['detector'] == 'impossible_travel':
        detail = f\"{e['from']['city']}, {e['from']['country']} -> {e['to']['city']}, {e['to']['country']}: {e['distanceKm']:.0f} km in {e['hours']*3600:.1f} s\"
    else:
        detail = f\"{e['ip']} ({e.get('country')}) on {e['eventType']}\"
    print(f\"  {a['detector']:18} {a['severity']:7} events={a['eventCount']}  {detail}  simulated={e.get('simulated')}\")
"
