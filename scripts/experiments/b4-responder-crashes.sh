#!/usr/bin/env bash
# Break B4 (SPEC §15): what do admins receive when the responder crashes mid-job and retries?
#
# Runs the same 100-crash test twice, each in a real PostgreSQL + Redis (Testcontainers):
#   Break: the naive responder, from the git tag break/b4-naive-responder (in a temporary worktree)
#   Prove: the idempotent responder at the current commit
# and prints the numbers both runs report.
#
# Usage:   scripts/experiments/b4-responder-crashes.sh
# Requires: git, the .NET 10 SDK, Docker running.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
TAG="break/b4-naive-responder"
WORK="$(mktemp -d)"
REPORT="$WORK/b4-report.txt"
trap 'git -C "$ROOT" worktree remove --force "$WORK/naive" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

# .NET on Windows needs a Windows path for the report file; elsewhere this is a no-op.
if command -v cygpath >/dev/null 2>&1; then REPORT_PATH="$(cygpath -w "$REPORT")"; else REPORT_PATH="$REPORT"; fi

run() {   # run <checkout> <test method pattern>
  B4_REPORT="$REPORT_PATH" dotnet test --project "$1/tests/ThreatLock.IntegrationTests" -- --filter-method "$2" \
    | grep -E 'passed|failed' | tail -1
}

echo "Break: $TAG ($(git -C "$ROOT" rev-parse --short "$TAG"))"
git -C "$ROOT" worktree add --detach "$WORK/naive" "$TAG" >/dev/null 2>&1
run "$WORK/naive" "*Break_the_naive_responder*"

echo "Prove: HEAD ($(git -C "$ROOT" rev-parse --short HEAD))"
run "$ROOT" "*Prove_idempotent_steps*"

echo
cat "$REPORT"
