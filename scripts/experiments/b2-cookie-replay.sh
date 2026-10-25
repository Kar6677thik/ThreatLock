#!/usr/bin/env bash
# Break B2 (SPEC §15): a victim's access token is copied and replayed from another country, on
# another machine. How long does the thief keep access?
#
#   Break: the org's policy has D5 (session hijack) and D2 (impossible travel) switched off,
#          i.e. ThreatLock as it was before M8 for this attack.
#   Prove: the default policy (D5 respond, D2 notify).
#
# Each trial: a fresh victim signs in from India (device V, Chrome) and uses the app; the thief
# replays the same access token from the UK (device A, Firefox), polling every 50 ms, until the
# API answers 401 or MAX_SECONDS pass. Time to revoke = thief's first request → first 401,
# measured by the client (SPEC §16.2).
#
# Usage:   scripts/experiments/b2-cookie-replay.sh          (TRIALS=10, MAX_SECONDS=15)
# Requires: bash, curl, python3; the API and Worker running locally with Development settings
# (simulation key) and the GeoIP database. Run only against your own development instance.
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5080}"
SIM_KEY="${SIM_KEY:-dev-only-simulator-key-change-me}"
TRIALS="${TRIALS:-10}"
MAX_SECONDS="${MAX_SECONDS:-15}"
INDIA_IP="${INDIA_IP:-49.207.48.1}"
UK_IP="${UK_IP:-81.2.69.142}"
CHROME="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
FIREFOX="Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"
PASSWORD="correct horse battery staple"
RUN="$(date +%s)"

if python3 -c '' 2>/dev/null; then PY=python3; else PY=python; fi
json() { "$PY" -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }
ms() { "$PY" -c 'import time; print(int(time.time()*1000))'; }
as_client() {   # as_client <ip> <device> <user-agent> curl-args...
  local ip="$1" device="$2" agent="$3"; shift 3
  curl -s -H "X-Simulator-Key: $SIM_KEY" -H "X-Simulated-Client-Ip: $ip" -H "X-Device-Id: $device" -A "$agent" \
    -H 'Content-Type: application/json' "$@"
}

run_mode() {   # run_mode <break|prove>
  local mode="$1" slug="b2-$1-$RUN"
  local owner policy body
  owner=$(as_client "$INDIA_IP" "owner-device-$RUN" "$CHROME" -d \
    "{\"orgName\":\"B2 $mode\",\"orgSlug\":\"$slug\",\"displayName\":\"Owner\",\"email\":\"owner-$slug@b2.test\",\"password\":\"$PASSWORD\"}" \
    "$BASE_URL/api/auth/register-org" | json 'd["accessToken"]')
  if [ "$mode" = break ]; then
    policy=$(curl -s -H "Authorization: Bearer $owner" "$BASE_URL/api/admin/policy")
    body=$(echo "$policy" | "$PY" -c 'import json,sys; p=json.load(sys.stdin); d=p["policy"]["detectors"]
for k in ("session_hijack","impossible_travel"): d.setdefault(k, {"mode":"off","minSeverity":"low"}); d[k]["mode"]="off"
print(json.dumps({"expectedVersion":p["version"],"policy":p["policy"]}))')
    curl -s -X PUT -H "Authorization: Bearer $owner" -H 'Content-Type: application/json' -d "$body" "$BASE_URL/api/admin/policy" > /dev/null
    sleep 11   # the Worker caches policy for 10 s
  fi

  for t in $(seq 1 "$TRIALS"); do
    local email="victim-$t-$slug@b2.test" token start first401="" served=0 code
    curl -s -X POST -H "Authorization: Bearer $owner" -H 'Content-Type: application/json' \
      -d "{\"email\":\"$email\",\"displayName\":\"Victim $t\",\"password\":\"$PASSWORD\"}" "$BASE_URL/api/admin/users" > /dev/null
    token=$(as_client "$INDIA_IP" "victim-device-$t-$RUN" "$CHROME" -d "{\"email\":\"$email\",\"password\":\"$PASSWORD\"}" \
      "$BASE_URL/api/auth/login" | json 'd["accessToken"]')
    as_client "$INDIA_IP" "victim-device-$t-$RUN" "$CHROME" -o /dev/null -H "Authorization: Bearer $token" "$BASE_URL/api/notes"

    start=$(ms)
    while :; do
      code=$(as_client "$UK_IP" "thief-device-$RUN" "$FIREFOX" -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" "$BASE_URL/api/notes")
      if [ "$code" = 401 ]; then first401=$(( $(ms) - start )); break; fi
      served=$((served + 1))
      if [ $(( $(ms) - start )) -ge $((MAX_SECONDS * 1000)) ]; then break; fi
      sleep 0.05
    done
    echo "$mode trial $t: thief served $served requests; $( [ -n "$first401" ] && echo "revoked after ${first401} ms" || echo "still working after ${MAX_SECONDS} s")"
    [ -n "$first401" ] && echo "$first401" >> "/tmp/b2-$mode-$RUN.ms"
  done

  if [ -s "/tmp/b2-$mode-$RUN.ms" ]; then
    "$PY" - "/tmp/b2-$mode-$RUN.ms" "$mode" <<'PY'
import sys, statistics
v = sorted(int(x) for x in open(sys.argv[1]))
p = lambda q: v[min(len(v) - 1, int(round(q * (len(v) - 1))))]
print(f"{sys.argv[2]}: n={len(v)} p50={p(0.5)} ms p95={p(0.95)} ms max={v[-1]} ms mean={statistics.mean(v):.0f} ms")
PY
  else
    echo "$mode: no trial was revoked within ${MAX_SECONDS} s"
  fi
}

run_mode break
run_mode prove
