#!/usr/bin/env bash
# Break B5 (SPEC §15): edit one audit entry as the PostgreSQL superuser. Can anyone tell?
#
# Against the local stack (Compose databases + `dotnet run` API). Creates an org with some
# audited history, then, acting as a database admin:
#   1. tries a plain UPDATE (the append-only trigger refuses it),
#   2. switches triggers off for the session and edits one entry's details,
#   3. deletes the newest entry,
# and asks the API to verify the chain after each step, with and without a saved anchor.
#
# Usage:   scripts/experiments/b5-audit-tamper.sh            (N=1000 extra entries by default)
#          N=0 scripts/experiments/b5-audit-tamper.sh        (skip the bulk entries)
# Requires: bash, curl, python3, docker (Compose stack running), the API on BASE_URL.
# Run only against your own development instance: it edits the database directly.
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:5080}"
N="${N:-1000}"
PG_CONTAINER="${PG_CONTAINER:-threatlock-postgres-1}"
PG_USER="${POSTGRES_USER:-threatlock}"
PG_DB="${POSTGRES_DB:-threatlock}"
PASSWORD="correct horse battery staple"
RUN="$(date +%s)"

if python3 -c '' 2>/dev/null; then PY=python3; else PY=python; fi
json() { "$PY" -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }
post() { curl -sf -X POST -H 'Content-Type: application/json' "${@:3}" -d "$2" "$BASE_URL$1"; }
psql_su() { docker exec -i "$PG_CONTAINER" psql -v ON_ERROR_STOP=1 -qAt -U "$PG_USER" -d "$PG_DB" "$@"; }
log() { printf '\n== %s\n' "$*"; }

log "1. An org with audited history"
TOKEN=$(post /api/auth/register-org \
  "{\"orgName\":\"B5 Lab $RUN\",\"orgSlug\":\"b5-lab-$RUN\",\"displayName\":\"Owner\",\"email\":\"owner-$RUN@b5.test\",\"password\":\"$PASSWORD\"}" \
  | json 'd["accessToken"]')
AUTH=(-H "Authorization: Bearer $TOKEN")
ORG=$(curl -sf "${AUTH[@]}" "$BASE_URL/api/me" | json 'd["orgId"]')
post /api/admin/users "{\"email\":\"ben-$RUN@b5.test\",\"displayName\":\"Ben\",\"password\":\"$PASSWORD\"}" "${AUTH[@]}" > /dev/null
for _ in $(seq 1 "$N"); do curl -sf -o /dev/null "${AUTH[@]}" "$BASE_URL/api/notes/export"; done   # each export is audited
verify() {
  curl -s -o /tmp/b5-verify.json -w '%{time_total}' -X POST -H 'Content-Type: application/json' "${AUTH[@]}" -d "${1:-{\}}" \
    "$BASE_URL/api/admin/audit/verify"
}
T=$(verify); RESULT=$(cat /tmp/b5-verify.json)
ENTRIES=$(echo "$RESULT" | json 'd["entries"]'); HEAD=$(echo "$RESULT" | json 'd["head"]')
echo "verify: $RESULT  (${T}s)"
ANCHOR="{\"anchor\":{\"seq\":$ENTRIES,\"hash\":\"$HEAD\"}}"
echo "anchor saved outside the database: seq $ENTRIES, hash $HEAD"

log "2. Entry 3 as it was"
psql_su -c "SELECT seq, action, details FROM audit_log WHERE org_id = '$ORG' AND seq = 3"

log "3. A plain UPDATE, even as the superuser, hits the append-only trigger"
psql_su -c "UPDATE audit_log SET details = '{\"email\":\"nobody@b5.test\"}' WHERE org_id = '$ORG' AND seq = 3" 2>&1 || true

log "4. With triggers off for the session, the edit succeeds and the row looks normal"
psql_su <<SQL
SET session_replication_role = replica;
UPDATE audit_log SET details = '{"email":"nobody@b5.test","roles":["member"]}' WHERE org_id = '$ORG' AND seq = 3;
SQL
psql_su -c "SELECT seq, action, details FROM audit_log WHERE org_id = '$ORG' AND seq = 3"
T=$(verify); echo "verify: $(cat /tmp/b5-verify.json)  (${T}s)"

log "5. A second org: delete its newest entry, which a chain alone cannot notice"
TOKEN2=$(post /api/auth/register-org \
  "{\"orgName\":\"B5 Lab b $RUN\",\"orgSlug\":\"b5-lab-b-$RUN\",\"displayName\":\"Owner\",\"email\":\"owner-b-$RUN@b5.test\",\"password\":\"$PASSWORD\"}" \
  | json 'd["accessToken"]')
AUTH=(-H "Authorization: Bearer $TOKEN2")
ORG=$(curl -sf "${AUTH[@]}" "$BASE_URL/api/me" | json 'd["orgId"]')
for _ in 1 2 3; do curl -sf -o /dev/null "${AUTH[@]}" "$BASE_URL/api/notes/export"; done
verify > /dev/null; RESULT=$(cat /tmp/b5-verify.json)
ENTRIES=$(echo "$RESULT" | json 'd["entries"]'); HEAD=$(echo "$RESULT" | json 'd["head"]')
ANCHOR="{\"anchor\":{\"seq\":$ENTRIES,\"hash\":\"$HEAD\"}}"
psql_su <<SQL
SET session_replication_role = replica;
DELETE FROM audit_log WHERE org_id = '$ORG' AND seq = $ENTRIES;
SQL
verify > /dev/null; echo "verify, no anchor:   $(cat /tmp/b5-verify.json)"
verify "$ANCHOR" > /dev/null; echo "verify, with anchor: $(cat /tmp/b5-verify.json)"
