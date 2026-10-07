// Ballot encryption (ElGamal over Grumpkin) + the Poseidon ballot commitment.
// Ported from `circuits/voting_lib/src/lib.nr` (encrypt_slot / ballot_fields /
// ballot_commitment_of) and `zkp-voting/client/make_inputs.mjs` (the xs/parity
// packing). Byte-for-byte compatible with the Noir circuits.

import { add, compress, G, scalarMul, type Point } from "./grumpkin";
import { poseidon2, poseidon3 } from "./poseidon";

export const K_MAX = 4;
export const XS_LEN = K_MAX * 2; // 8 compressed x-coordinates
export const BALLOT_LEN = K_MAX * 4; // 16 flattened fields
export const TAG_RAND = 3n;
export const TAG_BALLOT = 4n;

/** r_i = H(TAG_RAND, r_seed, i) — per-slot randomness (must be non-zero). */
export function slotRandomness(rSeed: bigint, i: number): bigint {
  const r = poseidon3([TAG_RAND, rSeed, BigInt(i)]);
  if (r === 0n) throw new Error("slot randomness must be non-zero");
  return r;
}

/** Encrypt one bit: C1 = r·G, C2 = r·PK + bit·G. */
export function encryptSlot(pk: Point, r: bigint, bit: boolean): [Point, Point] {
  const c1 = scalarMul(G, r);
  const shared = scalarMul(pk, r);
  const c2 = bit ? add(shared, G) : shared;
  return [c1, c2];
}

/** Flatten a whole ballot into [C1.x, C1.parity, C2.x, C2.parity] × K_MAX. */
export function ballotFields(pk: Point, rSeed: bigint, choice: boolean[]): bigint[] {
  const out: bigint[] = [];
  for (let i = 0; i < K_MAX; i++) {
    const [c1, c2] = encryptSlot(pk, slotRandomness(rSeed, i), choice[i] ?? false);
    const a = compress(c1);
    const b = compress(c2);
    out.push(a.x, BigInt(a.parity), b.x, BigInt(b.parity));
  }
  return out;
}

/** Poseidon fold over all 16 ballot fields, seeded with TAG_BALLOT. */
export function ballotCommitment(fields: bigint[]): bigint {
  let acc = TAG_BALLOT;
  for (const f of fields) acc = poseidon2([acc, f]);
  return acc;
}

/** Rebuild the 16-field flattened ballot from compact (xs, parity) — the inverse
 * of `buildBallotCiphertext`, mirroring `voting_lib::ballot_fields_from_xs`. */
export function ballotFieldsFromXs(xs: bigint[], parityBits: number): bigint[] {
  const out: bigint[] = [];
  for (let slot = 0; slot < K_MAX; slot++) {
    out.push(
      xs[slot * 2],
      BigInt((parityBits >> (slot * 2)) & 1),
      xs[slot * 2 + 1],
      BigInt((parityBits >> (slot * 2 + 1)) & 1)
    );
  }
  return out;
}

export interface BallotCiphertext {
  /** 8 x-coordinates: slot i -> [C1.x, C2.x]. */
  xs: bigint[];
  /** Packed parity byte: bit (2i) = C1 parity, bit (2i+1) = C2 parity. */
  parityBits: number;
  commitment: bigint;
}

/** Build the on-chain ciphertext representation from (pk, r_seed, choice). */
export function buildBallotCiphertext(
  pk: Point,
  rSeed: bigint,
  choice: boolean[]
): BallotCiphertext {
  const fields = ballotFields(pk, rSeed, choice);
  const xs: bigint[] = [];
  let parityBits = 0;
  for (let slot = 0; slot < K_MAX; slot++) {
    xs.push(fields[slot * 4], fields[slot * 4 + 2]);
    parityBits |= Number(fields[slot * 4 + 1] & 1n) << (slot * 2);
    parityBits |= Number(fields[slot * 4 + 3] & 1n) << (slot * 2 + 1);
  }
  return { xs, parityBits, commitment: ballotCommitment(fields) };
}
