// Shared deterministic fixture inputs for the on-device proving checks.
//
// These are the exact values from `zkp-voting/client/make_inputs.mjs` that
// produced the committed `circuits/target/voting_circuit.gz` witness. They let
// us validate the browser witness generator (noir_js) and the Go WASM prover
// against the committed artifacts without a live chain.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { poseidon2, poseidon4 } from "poseidon-lite";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));

export const PATHS = {
  circuitJson: here("../../circuits/target/voting_circuit.json"),
  witnessGz: here("../../circuits/target/voting_circuit.gz"),
  fixture: here("../../circuits/target/voting_circuit.fixture.json"),
  vk: here("../../circuits/target/voting_circuit.vk"),
  pw: here("../../circuits/target/voting_circuit.pw"),
  ccs: here("../public/proving/voting_circuit.ccs"),
  pk: here("../public/proving/voting_circuit.pk"),
  wasmExec: here("../public/wasm_exec.js"),
  wasm: here("../public/prover.wasm"),
};

// --- Minimal Merkle helpers, mirroring zkp-voting/client/tree.mjs (DEPTH=24). ---
export const DEPTH = 24;
export const TAG_LEAF = 1n;
export const TAG_NULL = 2n;
export const leafOf = (s) => poseidon2([TAG_LEAF, s]);
export const nullifierOf = (s, electionId, positionId) => poseidon4([TAG_NULL, s, electionId, positionId]);

export function buildTree(leaves, depth = DEPTH) {
  const zeros = [0n];
  for (let i = 0; i < depth; i++) zeros.push(poseidon2([zeros[i], zeros[i]]));
  let level = leaves.slice();
  const levels = [level];
  for (let d = 0; d < depth; d++) {
    const next = [];
    for (let i = 0; i < Math.max(1, Math.ceil(level.length / 2)); i++) {
      next.push(poseidon2([level[2 * i] ?? zeros[d], level[2 * i + 1] ?? zeros[d]]));
    }
    level = next;
    levels.push(level);
  }
  return {
    root: level[0],
    path(index) {
      const bits = [];
      const sibs = [];
      let current = index;
      for (let d = 0; d < depth; d++) {
        bits.push(current & 1);
        sibs.push(levels[d][current ^ 1] ?? zeros[d]);
        current >>= 1;
      }
      return { bits, sibs };
    },
  };
}

export function rootFromPath(leaf, pathBits, pathSibs) {
  let cur = leaf;
  for (let i = 0; i < pathBits.length; i++) {
    cur = pathBits[i] === 0 ? poseidon2([cur, pathSibs[i]]) : poseidon2([pathSibs[i], cur]);
  }
  return cur;
}

export function readFixture() {
  return JSON.parse(readFileSync(PATHS.fixture, "utf8"));
}

// Raw (bigint) reconstruction of the deterministic fixture, for sanity checks.
export function buildFixtureRaw() {
  const secret = 987654321n;
  const tree = buildTree([11n, 22n, 33n, secret].map(leafOf));
  const { bits, sibs } = tree.path(3);
  const fixture = readFixture();
  return {
    secret,
    bits, // number[] (0/1)
    sibs, // bigint[]
    electionId: BigInt(fixture.electionId),
    positionId: BigInt(fixture.positionId),
    fixture,
  };
}

// Returns the flat `Noir.execute` input map (matching `VoteWitness`) that
// reproduces the committed witness.
export function buildFixtureInputs() {
  const { secret, bits, sibs, electionId, positionId, fixture } = buildFixtureRaw();
  return {
    merkle_root_pub: BigInt(fixture.root).toString(),
    nullifier: BigInt(fixture.nullifier).toString(),
    election_id: electionId.toString(),
    position_id: positionId.toString(),
    max_candidates: fixture.maxCandidates,
    pk_hash: BigInt(fixture.pkHash).toString(),
    ballot_commitment: BigInt(fixture.commitment).toString(),
    s: secret.toString(),
    bits: bits.map((b) => b === 1),
    sibs: sibs.map((s) => s.toString()),
    choice: [false, true, false, false],
    r_seed: (55555n).toString(),
    pk_x: BigInt(fixture.pkX).toString(),
    pk_y: BigInt(fixture.pkY).toString(),
  };
}
