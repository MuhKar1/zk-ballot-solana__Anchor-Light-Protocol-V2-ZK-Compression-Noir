// Generates the Layer-2 tally witness from the ballot fixture produced by make_inputs.mjs.
//
// The tally circuit re-derives the on-chain transcript and decrypts each ballot, so the only
// on-chain data it needs per ballot is the compressed ciphertext (xs + parity bits) plus the
// nullifier. The secret key is sk = 1 because the fixture's public key is the Grumpkin
// generator (pk = 1 * G).
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { poseidon2 } from "poseidon-lite";

const root = fileURLToPath(new URL("../../circuits/", import.meta.url));

// Grumpkin base field = BN254 scalar field.
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const N_BALLOTS = 8;
const K_MAX = 4;
const TAG_TRANSCRIPT = 5n;
const TAG_BALLOT = 4n;
const SK = 1n; // pk = 1 * G in the fixture
const TOTALS = [0n, 1n, 0n, 0n]; // the fixture's known choice [false, true, false, false]

function modPow(base, exp, mod) {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

// Tonelli-Shanks square root in the Grumpkin base field.
function modSqrt(a) {
  if (a === 0n) return 0n;
  let q = P - 1n;
  let s = 0n;
  while ((q & 1n) === 0n) {
    q >>= 1n;
    s += 1n;
  }
  let z = 2n;
  while (modPow(z, (P - 1n) / 2n, P) !== P - 1n) z += 1n;
  let m = s;
  let c = modPow(z, q, P);
  let t = modPow(a, q, P);
  let r = modPow(a, (q + 1n) / 2n, P);
  while (t !== 1n) {
    let i = 0n;
    let t2 = t;
    while (t2 !== 1n) {
      t2 = (t2 * t2) % P;
      i += 1n;
      if (i >= m) throw new Error("value is not a quadratic residue");
    }
    const b = modPow(c, 1n << (m - i - 1n), P);
    m = i;
    c = (b * b) % P;
    t = (t * c) % P;
    r = (r * b) % P;
  }
  return r;
}

function recoverY(x, parityBit) {
  const rhs = (((x * x * x - 17n) % P) + P) % P;
  let y = modSqrt(rhs);
  if ((y & 1n) !== BigInt(parityBit)) y = P - y;
  return y;
}

// Mirrors the Solana program's expand_ballot + ballot_commitment (Poseidon fold over 16 fields).
function ballotCommitment(xs, parities) {
  let acc = TAG_BALLOT;
  for (let slot = 0; slot < K_MAX; slot++) {
    acc = poseidon2([acc, xs[slot * 2]]);
    acc = poseidon2([acc, BigInt((parities >> (slot * 2)) & 1)]);
    acc = poseidon2([acc, xs[slot * 2 + 1]]);
    acc = poseidon2([acc, BigInt((parities >> (slot * 2 + 1)) & 1)]);
  }
  return acc;
}

const quote = (value) => `"${value}"`;

const fixture = JSON.parse(
  readFileSync(`${root}/target/voting_circuit.fixture.json`, "utf8")
);

const pkX = BigInt(fixture.pkX);
const pkY = BigInt(fixture.pkY);
const nullifier = BigInt(fixture.nullifier);
const parities = fixture.parityBits;
const xs = fixture.xs.map((value) => BigInt(value));
const ys = xs.map((x, k) => recoverY(x, (parities >> k) & 1));
const commitment = ballotCommitment(xs, parities);
const transcript = poseidon2([TAG_TRANSCRIPT, poseidon2([nullifier, commitment])]);
const pkHash = poseidon2([pkX, pkY]);

const originalProver = (() => {
  try {
    return readFileSync(`${root}/tally_circuit/Prover.toml`, "utf8");
  } catch {
    return null;
  }
})();

try {
  const lines = [];
  lines.push(`transcript = ${quote(transcript)}`);
  lines.push(`ballot_count = ${quote(1)}`);
  lines.push(`max_candidates = ${quote(4)}`);
  lines.push(`pk_hash = ${quote(pkHash)}`);
  lines.push(`totals = [${TOTALS.map(quote).join(", ")}]`);

  const ballotList = (values) =>
    `[${Array.from({ length: N_BALLOTS }, (_, i) =>
      i === 0 ? `[${values.map(quote).join(", ")}]` : `[${values.map(quote).join(", ")}]`
    ).join(", ")}]`;
  // Inactive slots are padding: copy the real ballot so they stay valid one-hot encryptions.
  lines.push(`xs = ${ballotList(xs)}`);
  lines.push(`ys = ${ballotList(ys)}`);
  lines.push(`parities = [${Array.from({ length: N_BALLOTS }, () => quote(parities)).join(", ")}]`);
  lines.push(`nullifiers = [${Array.from({ length: N_BALLOTS }, () => quote(nullifier)).join(", ")}]`);
  lines.push(`pk_x = ${quote(pkX)}`);
  lines.push(`pk_y = ${quote(pkY)}`);
  lines.push(`sk = ${quote(SK)}`);

  writeFileSync(`${root}/tally_circuit/Prover.toml`, `${lines.join("\n")}\n`);
  writeFileSync(
    `${root}/target/tally_circuit.fixture.json`,
    `${JSON.stringify(
      {
        transcript: `0x${transcript.toString(16).padStart(64, "0")}`,
        ballotCount: 1,
        maxCandidates: 4,
        pkHash: `0x${pkHash.toString(16).padStart(64, "0")}`,
        totals: TOTALS.map((value) => value.toString()),
      },
      null,
      2
    )}\n`
  );

  console.log(execFileSync("nargo", ["execute", "--package", "tally_circuit"], { cwd: root }).toString().trim());
} finally {
  if (originalProver !== null) {
    writeFileSync(`${root}/tally_circuit/Prover.toml`, originalProver);
  }
}
