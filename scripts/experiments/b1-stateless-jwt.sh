#!/usr/bin/env bash
# Break B1 (SPEC §15): does a stolen access token keep working after logout and admin revocation?
#
#   Break (M2 behaviour):  Auth__Mode=StatelessJwt Auth__AccessTokenMinutes=60 dotnet run --project src/ThreatLock.Api
#   Prove (default, M3+):  dotnet run --project src/ThreatLock.Api
#
# Usage:
#   scripts/experiments/b1-stateless-jwt.sh                 # one-shot
#   POLL=1 scripts/experiments/b1-stateless-jwt.sh          # if still accepted, keep using it until rejected
#
# For a POLL run in break mode you don't want to wait an hour; use Auth__AccessTokenMinutes=2.
#
# Requires: bash, curl, python3. Run only against your own ThreatLock instance.
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5080}"
POLL="${POLL:-0}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"
PASSWORD="correct horse battery staple"
RUN="$(date +%s)"

# python3 on Linux/macOS; on Windows "python3" may be a Store stub that fails, so test it.
if python3 -c '' 2>/dev/null; then PY=python3; else PY=python; fi

json() { "$PY" -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }
post() { curl -sf -X POST -H 'Content-Type: application/json' "${@:3}" -d "$2" "$BASE_URL$1"; }
status() { curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $1" "$BASE_URL$2"; }
timed() { curl -s -o /dev/null -w '%{http_code} in %{time_total}s' -H "Authorization: Bearer $1" "$BASE_URL$2"; }
now() { "$PY" -c 'import time; print(f"{time.time():.3f}")'; }
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

log "Target: $BASE_URL"

# 1. An org with an owner (acting as security admin) and a victim user.
OWNER_TOKEN=$(post /api/auth/register-org \
  "{\"orgName\":\"B1 Lab $RUN\",\"orgSlug\":\"b1-lab-$RUN\",\"displayName\":\"Owner\",\"email\":\"owner-$RUN@b1.test\",\"password\":\"$PASSWORD\"}" \
  | json 'd["accessToken"]')
post /api/admin/users "{\"email\":\"victim-$RUN@b1.test\",\"displayName\":\"Victim\",\"password\":\"$PASSWORD\"}" \
  -H "Authorization: Bearer $OWNER_TOKEN" > /dev/null
LOGIN=$(post /api/auth/login "{\"email\":\"victim-$RUN@b1.test\",\"password\":\"$PASSWORD\"}")
VICTIM_TOKEN=$(echo "$LOGIN" | json 'd["accessToken"]')
VICTIM_ID=$(echo "$LOGIN" | json 'd["user"]["id"]')
EXPIRES_AT=$(echo "$LOGIN" | json 'd["expiresAt"]')
post /api/notes '{"title":"Quarterly numbers","body":"confidential","shared":false}' -H "Authorization: Bearer $VICTIM_TOKEN" > /dev/null
log "Victim signed in. Token expires at $EXPIRES_AT."

# 2. The attacker copies the token (cookie theft, malware, a leaked log line...).
STOLEN="$VICTIM_TOKEN"
log "Attacker copied the token. /api/notes/export -> $(status "$STOLEN" /api/notes/export)"

# 3. The victim signs out, and a security admin revokes all their sessions.
REVOKED_AT=$(now)
curl -sf -X POST -H "Authorization: Bearer $VICTIM_TOKEN" "$BASE_URL/api/auth/logout" > /dev/null
log "Victim signed out."
log "Attacker after logout:          /api/notes/export -> $(timed "$STOLEN" /api/notes/export)"
post "/api/admin/users/$VICTIM_ID/revoke-sessions" '{}' -H "Authorization: Bearer $OWNER_TOKEN" > /dev/null
log "Admin revoked the victim's sessions."

# 4. Does the stolen token still work?
CODE=$(status "$STOLEN" /api/notes/export)
log "Attacker after admin revoke:    /api/notes/export -> $CODE"
REMAINING=$("$PY" -c "from datetime import datetime,timezone; import sys; print(int((datetime.fromisoformat(sys.argv[1].replace('Z','+00:00'))-datetime.now(timezone.utc)).total_seconds()))" "$EXPIRES_AT")
if [[ "$CODE" == "200" ]]; then
  log "VULNERABLE: the token is accepted for about ${REMAINING}s more (+ up to 30s clock skew)."
else
  log "PROTECTED: rejected on the first request after revocation, although the token itself had ${REMAINING}s left."
fi

if [[ "$POLL" == "1" && "$CODE" == "200" ]]; then
  log "Polling every ${POLL_INTERVAL}s until the API rejects the stolen token..."
  while [[ "$(status "$STOLEN" /api/notes/export)" == "200" ]]; do sleep "$POLL_INTERVAL"; done
  END=$(now)
  log "Rejected. Continued access after revocation: $("$PY" -c "print(f'{$END-$REVOKED_AT:.1f}')")s"
fi
