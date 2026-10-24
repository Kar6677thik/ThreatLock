#!/usr/bin/env bash
# Downloads the DB-IP "IP to City Lite" database (CC BY 4.0) into data/geoip/ (ADR-0009).
# The file is ~120 MB unpacked and changes monthly, so it is git-ignored and fetched on demand.
#
# Usage: scripts/download-geoip.sh            # this month's file, or last month's if not out yet
# Attribution required by the licence: "IP Geolocation by DB-IP" (https://db-ip.com).
set -euo pipefail

DEST_DIR="$(cd "$(dirname "$0")/.." && pwd)/data/geoip"
DEST="$DEST_DIR/dbip-city-lite.mmdb"
mkdir -p "$DEST_DIR"

for month in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-01) -1 month" +%Y-%m 2>/dev/null || date -u -v-1m +%Y-%m)"; do
  url="https://download.db-ip.com/free/dbip-city-lite-$month.mmdb.gz"
  echo "Trying $url"
  if curl -fsSL "$url" -o "$DEST.gz.tmp"; then
    gunzip -c "$DEST.gz.tmp" > "$DEST.tmp" && rm "$DEST.gz.tmp"
    mv "$DEST.tmp" "$DEST"   # atomic replace: a running API never sees a half-written file
    echo "Saved $DEST ($(du -h "$DEST" | cut -f1))"
    exit 0
  fi
done

echo "Could not download a DB-IP Lite database." >&2
exit 1
