// Problem-B acceptance check: prove that the browser's witness generator
// (@noir-lang/noir_js) reproduces the exact `nargo execute` witness stack that
// the Go prover consumes.
//
// It reconstructs the deterministic fixture inputs (the same ones that produced
// the committed `circuits/target/voting_circuit.gz`), runs `Noir.execute`, and
// asserts the returned bytes are byte-for-byte identical to that `.gz`.
//
// Run from app/:  node scripts/witness-check.mjs
import { readFileSync } from "node:fs";
import { Noir } from "@noir-lang/noir_js";
import {
  PATHS,
  buildFixtureInputs,
  buildFixtureRaw,
  leafOf,
  nullifierOf,
  readFixture,
  rootFromPath,
} from "./fixture.mjs";

const fixture = readFixture();
const raw = buildFixtureRaw();

// Sanity-check the reconstructed Merkle path + nullifier against the committed fixture.
const rebuiltRoot = rootFromPath(leafOf(raw.secret), raw.bits, raw.sibs);
if (rebuiltRoot !== BigInt(fixture.root)) {
  throw new Error(`reconstructed root ${rebuiltRoot} != fixture root ${fixture.root}`);
}
const rebuiltNullifier = nullifierOf(raw.secret, raw.electionId, raw.positionId);
if (rebuiltNullifier !== BigInt(fixture.nullifier)) {
  throw new Error("reconstructed nullifier mismatch");
}
console.log("root/nullifier reconstruction OK");

// --- Solve the circuit and compare against the committed nargo witness. ---
const circuit = JSON.parse(readFileSync(PATHS.circuitJson, "utf8"));
const expected = readFileSync(PATHS.witnessGz);

console.log("executing voting_circuit with noir_js (acvm_js) ...");
const noir = new Noir(circuit);
const { witness } = await noir.execute(buildFixtureInputs());

console.log(`noir_js witness: ${witness.length} bytes`);
console.log(`nargo .gz      : ${expected.length} bytes`);

if (witness.length !== expected.length) {
  throw new Error(`length mismatch: ${witness.length} vs ${expected.length}`);
}
for (let i = 0; i < witness.length; i++) {
  if (witness[i] !== expected[i]) {
    throw new Error(`byte mismatch at offset ${i}: 0x${witness[i].toString(16)} vs 0x${expected[i].toString(16)}`);
  }
}

console.log("PASS: noir_js witness is byte-identical to nargo execute output");

