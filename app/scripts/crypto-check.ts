/**
 * Parity check for `src/lib/crypto` against the Noir circuits and the client
 * reference scripts. Run with: npm run check (i.e. tsx scripts/crypto-check.ts).
 *
 * The vectors are taken verbatim from:
 *   - circuits/target/voting_circuit.fixture.json  (nargo execute output)
 *   - circuits/target/tally_circuit.fixture.json
 *   - zkp-voting/client/check.mjs
 */
import assert from "node:assert/strict";

import {
  BN254_MODULUS as P,
  buildBallotCiphertext,
  buildTree,
  deriveSecret,
  G,
  hex,
  isOnCurve,
  leafOf,
  nullifierOf,
  poseidon2,
  poseidon3,
  poseidon4,
  rootFromPath,
  scalarMul,
  transcriptFold,
  transcriptInit,
} from "../src/lib/crypto";
import { buildTallyWitness } from "../src/lib/tally";

const fieldFromHex = (h: string) => {
  const v = BigInt(h);
  assert.ok(v >= 0n && v < P, `non-canonical: ${h}`);
  return v;
};

let passed = 0;
const ok = (name: string) => {
  passed += 1;
  console.log(`ok ${passed} - ${name}`);
};

async function main() {
  // ---- Poseidon / leaf / nullifier (from check.mjs) ----
  assert.equal(
    hex(poseidon2([1n, 2n])),
    "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"
  );
  ok("poseidon2(1,2) matches Noir vector");

  const secret = 987654321n;
  assert.equal(
    hex(leafOf(secret)),
    "0x2d1a37d46019f0c5d46d149263448d286c1601c47ea3b1053ac5825bcad13a54"
  );
  ok("leafOf(secret) matches Noir vector");

  assert.equal(
    hex(nullifierOf(secret, 7n, 1n)),
    "0x037e92195747fe291df2bb9d2a9523c2de5c514205380a2ee8d10578516372d9"
  );
  ok("nullifierOf(secret,7,1) matches Noir vector");

  // ---- Merkle rootFromPath (from check.mjs) ----
  const bits = [] as number[];
  const sibs = [] as bigint[];
  for (let i = 0; i < 24; i++) {
    bits.push(i % 3 === 0 ? 1 : 0);
    sibs.push(1000n + BigInt(i));
  }
  assert.equal(
    hex(rootFromPath(leafOf(secret), bits, sibs)),
    "0x0b674b13552d092b0afd70da6db218987e463631095638fa779f8ec6fbe282b8"
  );
  ok("rootFromPath matches Noir vector");

  // ---- buildTree consistency ----
  const leaves = [11n, 22n, 33n, 44n, 55n].map(leafOf);
  const tree = buildTree(leaves);
  for (let i = 0; i < leaves.length; i++) {
    const path = tree.path(i);
    assert.equal(rootFromPath(leaves[i], path.bits, path.sibs), tree.root);
  }
  ok("buildTree paths land on the root");

  // ---- Grumpkin curve / generator ----
  assert.ok(isOnCurve(G), "generator G must be on the curve");
  assert.deepEqual(scalarMul(G, 1n), G, "1 * G == G");
  ok("Grumpkin generator is on-curve and 1*G == G");

  // ---- pk_hash = H(pk_x, pk_y) ----
  const pk = G; // fixture sk = 1, so pk = G
  const pkHash = poseidon2([pk.x, pk.y]);
  assert.equal(
    hex(pkHash),
    "0x1b2231fbfcbdc8e78a98d738945989141683623400dafa121b10cd8e00b9b395"
  );
  ok("pk_hash matches fixture");

  // ---- ballot encryption + commitment (the hard end-to-end check) ----
  const choice = [false, true, false, false];
  const rSeed = 55555n;
  const ct = buildBallotCiphertext(pk, rSeed, choice);

  const fixture = {
    xs: [
      "0x10b75300c2fa898983b5dbc432f4dcb67ad1352c61464d83286eb07611bc2f4a",
      "0x10b75300c2fa898983b5dbc432f4dcb67ad1352c61464d83286eb07611bc2f4a",
      "0x1de875a73f5c453cebfef531032933621f90d81b8788db882042d983384669f9",
      "0x1eeac3200ad7a653e10dc6ac33efbde32b1188c25013f22ff2f2a032e95b4b2f",
      "0x25be218c110eb15d70f7165495d7c003ee3c6df9312423b0c26bd5289b55498c",
      "0x25be218c110eb15d70f7165495d7c003ee3c6df9312423b0c26bd5289b55498c",
      "0x0c25b8cecce4164af847a77d7b8c4dffcb074b934b813c8d071bb828f758d876",
      "0x0c25b8cecce4164af847a77d7b8c4dffcb074b934b813c8d071bb828f758d876",
    ],
    parityBits: 199,
    commitment: "0x214c2146b7f84ae19622a3adf2e0c647bd41c241669013c8ae5305c087b23dc4",
  };

  assert.deepEqual(
    ct.xs.map(hex),
    fixture.xs,
    "ciphertext x-coordinates must match nargo execute"
  );
  assert.equal(ct.parityBits, fixture.parityBits, "parity byte must match nargo execute");
  assert.equal(hex(ct.commitment), fixture.commitment, "commitment must match nargo execute");
  ok("ballot ciphertext + commitment match the Noir ballot_encoder output");

  // ---- transcript fold (tally fixture) ----
  const nullifier = fieldFromHex("0x0bb23642a92f07f36712f8f7c831d6cf5f0e1bfb46f3cf0d75b624fd163af5dc");
  const commitment = fieldFromHex(fixture.commitment);
  assert.equal(transcriptInit(), 5n);
  const transcript = transcriptFold(transcriptInit(), nullifier, commitment);
  assert.equal(
    hex(transcript),
    "0x085e551ca5f103422de094137a0ce7325b7815fd9c20d2916f4d15a2e6b62fa7"
  );
  ok("transcript fold matches the tally fixture");

  // ---- tally witness: recover-y + decrypt + totals (vs tally_circuit fixture) ----
  const tally = buildTallyWitness({
    sk: 1n,
    pkX: pk.x,
    pkY: pk.y,
    maxCandidates: 4,
    ballots: [{ nullifier, xs: ct.xs, parity: ct.parityBits }],
  });
  assert.equal(
    tally.transcript,
    fieldFromHex("0x085e551ca5f103422de094137a0ce7325b7815fd9c20d2916f4d15a2e6b62fa7").toString()
  );
  assert.deepEqual(tally.totals, ["0", "1", "0", "0"]);
  assert.equal(tally.ballot_count, "1");
  assert.equal(tally.pk_hash, pkHash.toString());
  ok("tally witness decrypts + folds to the tally fixture");

  // ---- identity determinism + canonical ----
  const s1 = await deriveSecret("12345", "s3cret");
  const s2 = await deriveSecret("12345", "s3cret");
  assert.equal(s1, s2, "secret must be deterministic");
  assert.ok(s1 > 0n && s1 < P, "secret must be canonical");
  assert.notEqual(s1, await deriveSecret("12345", "other"), "different password -> different secret");
  ok("identity KDF is deterministic and credential-bound");

  console.log(`\nAll crypto parity checks passed (${passed}/${passed}).`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
