// End-to-end smoke test for the on-device prover:
//
//   1. Load the Go-compiled prover.wasm in Node (same wasm the browser worker runs).
//   2. Generate the witness in-process with noir_js (Problem B).
//   3. Feed that witness to proverProve and assert a 388-byte Groth16 proof.
//
// The proof is written to /tmp/prover-wasm.proof so it can be checked with the
// deployed verifier (sunspot verify).
//
// Run from app/:  node scripts/prove-wasm-check.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { Noir } from "@noir-lang/noir_js";
import { PATHS, buildFixtureInputs } from "./fixture.mjs";

const require = createRequire(import.meta.url);
require(PATHS.wasmExec); // defines globalThis.Go

const b64 = (buf) => Buffer.from(buf).toString("base64");

function waitFor(fn, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const tick = () => {
      const value = fn();
      if (value) return resolve(value);
      if (Date.now() - start > timeoutMs) return reject(new Error("timed out waiting for Go wasm"));
      setTimeout(tick, 25);
    };
    tick();
  });
}

const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(readFileSync(PATHS.wasm), go.importObject);
go.run(instance); // do not await — Go main() blocks forever

await waitFor(
  () =>
    typeof globalThis.proverLoad === "function" &&
    typeof globalThis.proverProve === "function"
);
console.log("prover.wasm ready");

const acir = readFileSync(PATHS.circuitJson);
const ccs = readFileSync(PATHS.ccs);
const pk = readFileSync(PATHS.pk);

const loadErr = globalThis.proverLoad(b64(acir), b64(ccs), b64(pk));
if (loadErr && loadErr.error) throw new Error(loadErr.error);
console.log("prover.wasm loaded circuit + constraint system + proving key");

const circuit = JSON.parse(acir.toString("utf8"));
const noir = new Noir(circuit);
const { witness } = await noir.execute(buildFixtureInputs());
console.log(`noir_js witness: ${witness.length} bytes`);

const proofB64 = globalThis.proverProve(b64(Buffer.from(witness)));
if (proofB64 && proofB64.error) throw new Error(proofB64.error);
const proof = Buffer.from(proofB64, "base64");
console.log(`prover.wasm proof: ${proof.length} bytes`);
if (proof.length !== 388) throw new Error(`expected 388-byte Groth16 proof, got ${proof.length}`);

writeFileSync("/tmp/prover-wasm.proof", proof);
console.log("PASS: prover.wasm produced a 388-byte Groth16 proof -> /tmp/prover-wasm.proof");
