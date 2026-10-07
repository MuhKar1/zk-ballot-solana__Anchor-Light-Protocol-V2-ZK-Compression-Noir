# On-device Groth16 prover (gnark → WASM)

This compiles the **Sunspot/gnark** prover to WebAssembly so the vote proof can be
generated **in the browser** — keeping the voter secret (`s`), Merkle path, and
choice on the device. It is the "Problem A" half of on-device proving.

> The "Problem B" half — producing the `nargo execute` witness stack in the browser
> — needs the Noir ACIR VM (`@noir-lang/noir_js` + `@noir-lang/acvm_js`, pinned to
> `1.0.0-beta.22`) plus a serializer for Sunspot's `WitnessStack` msgpack format.
> Until then the app uses `NodeProver` (server-side).

## Build (requires Go 1.24+)

1. Check out Sunspot at the pinned commit and add the byte-loaders:

   ```bash
   cd app/prisms
   git clone https://github.com/reilabs/sunspot.git sunspot
   cd sunspot && git checkout 43891c5 && cd ..
   cp prover/acir-bytes.go sunspot/go/acir/
   ```

   The gnark version must match the one the deployed verifiers were built from
   (`gnark v0.14.0`, `gnark-crypto v0.19.0`).

2. Build and stage:

   ```bash
   cd prover
   ./build.sh
   ```

   This produces `app/public/prover.wasm` + `app/public/wasm_exec.js`.

## JS interface

`cmd/wasm/main.go` registers two globals after `go.run(instance)`:

- `proverLoad(acirB64, ccsB64, pkB64)` — loads the circuit JSON, constraint system,
  and proving key (base64). Call once.
- `proverProve(witnessGzB64)` — proves a witness stack and returns the 388-byte
  Groth16 proof as base64.

The browser fetches the artifacts (`voting_circuit.json`, `.ccs`, `.pk`) from
`app/public/proving/` (copy them from `circuits/target/`).

## Important

- **Do not regenerate** `.ccs`/`.pk`/`.json` (a new `sunspot setup` changes the
  verifying key and invalidates the pinned on-chain verifier IDs).
- The proof is randomized (Groth16), so proofs differ each run; validate by
  verification, not byte-equality.
