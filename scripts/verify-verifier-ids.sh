#!/usr/bin/env bash
# Verifies both verifier programs against the pinned IDs:
#   1. the program account exists at the pinned address,
#   2. it has no upgrade authority (immutable),
#   3. its on-chain bytes match the locally-built .so (correct binary).
#
# Usage:
#   RPC_URL=https://api.devnet.solana.com ./scripts/verify-verifier-ids.sh
#
# (For a local validator, pass RPC_URL=http://127.0.0.1:8899.)
set -euo pipefail

VOTING_ID="${VOTING_ID:-9jjgdh8kXLqZEkAGYjXTXsXGQeGALJ6YYKn5Gz3KXgYj}"
TALLY_ID="${TALLY_ID:-AuSPaahFzAViTokdyhc6fYNe1gELiHRksbExo2YNptav}"
RPC_URL="${RPC_URL:-https://api.devnet.solana.com}"
TARGET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../circuits/target" && pwd)"

check() {
  local id="$1" name="$2" show dump onchain local

  echo "== $name ($id) =="

  show="$(solana program show "$id" --url "$RPC_URL" 2>&1)"
  if echo "$show" | grep -qiE 'authority: none|not upgradeable|no upgrade authority'; then
    echo "  authority: none (immutable) OK"
  else
    echo "  FAIL: $id is not immutable" >&2
    echo "$show" >&2
    exit 1
  fi

  dump="$(mktemp)"
  solana program dump "$id" "$dump" --url "$RPC_URL" >/dev/null 2>&1
  onchain="$(sha256sum "$dump" | awk '{print $1}')"
  local="$(sha256sum "$TARGET_DIR/${name}.so" | awk '{print $1}')"
  rm -f "$dump"

  if [ "$onchain" = "$local" ]; then
    echo "  binary sha256 match OK ($onchain)"
  else
    echo "  FAIL: on-chain $onchain != local $local" >&2
    exit 1
  fi
}

check "$VOTING_ID" voting_circuit
check "$TALLY_ID" tally_circuit
echo "Both verifiers verified: present, byte-identical, immutable."
