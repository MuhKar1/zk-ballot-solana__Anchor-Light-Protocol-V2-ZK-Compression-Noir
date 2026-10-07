#!/usr/bin/env bash
# Build the on-device Groth16 prover to WebAssembly and stage it in the app.
#
# Prereqs:
#   - Go 1.24+ on PATH
#   - a checkout of https://github.com/reilabs/sunspot at commit 43891c5 in
#     ../sunspot (see ../README.md)
#   - ../sunspot/go/acir/acir-bytes.go copied in (the byte-loaders patch)
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$DIR/../.." && pwd)"

echo "Building prover.wasm (GOOS=js GOARCH=wasm)..."
GOOS=js GOARCH=wasm go build -o "$APP_DIR/public/prover.wasm" ./cmd/wasm

echo "Copying the Go wasm runtime..."
WASM_EXEC="$(go env GOROOT)/lib/wasm/wasm_exec.js"
cp "$WASM_EXEC" "$APP_DIR/public/wasm_exec.js"

echo "Done. Staged:"
echo "  $APP_DIR/public/prover.wasm"
echo "  $APP_DIR/public/wasm_exec.js"
