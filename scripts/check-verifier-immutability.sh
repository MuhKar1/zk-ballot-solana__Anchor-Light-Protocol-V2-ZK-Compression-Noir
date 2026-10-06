#!/usr/bin/env bash
# Asserts that both verifier programs are immutable (no upgrade authority).
#
# Usage:
#   VOTING_ID=... TALLY_ID=... RPC_URL=https://... ./scripts/check-verifier-immutability.sh
#
# On a live cluster, deploy immutably first:
#   solana program set-upgrade-authority <ID> --final
set -euo pipefail

VOTING_ID="${VOTING_ID:-9jjgdh8kXLqZEkAGYjXTXsXGQeGALJ6YYKn5Gz3KXgYj}"
TALLY_ID="${TALLY_ID:-AuSPaahFzAViTokdyhc6fYNe1gELiHRksbExo2YNptav}"
RPC_URL="${RPC_URL:-http://127.0.0.1:8899}"

check() {
  local id="$1"
  local out
  out="$(solana program show "$id" --url "$RPC_URL" 2>&1)"
  echo "$out"
  if echo "$out" | grep -qiE 'authority: none|not upgradeable|no upgrade authority|not upgradeable'; then
    echo "OK: $id is immutable"
  else
    echo "FAIL: $id appears to have an upgrade authority" >&2
    exit 1
  fi
}

check "$VOTING_ID"
check "$TALLY_ID"
echo "Both verifiers are immutable."
