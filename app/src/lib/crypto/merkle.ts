// Merkle tree + leaf/nullifier derivation. Ported from `zkp-voting/client/tree.mjs`
// and `circuits/voting_lib/src/lib.nr` (DEPTH = 24, domain-separated tags).

import { poseidon2, poseidon4 } from "./poseidon";
import { assertField, isCanonical } from "./field";

export const DEPTH = 24;
export const TAG_LEAF = 1n;
export const TAG_NULL = 2n;

/** H(TAG_LEAF, s) — a voter's leaf in the registration tree. */
export function leafOf(s: bigint): bigint {
  return poseidon2([TAG_LEAF, s]);
}

/** H(TAG_NULL, s, election_id, position_id) — the one-time nullifier. */
export function nullifierOf(s: bigint, electionId: bigint, positionId: bigint): bigint {
  return poseidon4([TAG_NULL, s, electionId, positionId]);
}

export interface MerklePath {
  bits: number[];
  sibs: bigint[];
}

export interface MerkleTree {
  root: bigint;
  path(index: number): MerklePath;
}

/** Build a depth-DEPTH Merkle tree from canonical leaves (empty pads use zero subtrees). */
export function buildTree(leaves: bigint[], depth: number = DEPTH): MerkleTree {
  if (!Array.isArray(leaves) || leaves.length === 0) {
    throw new Error("tree requires at least one leaf");
  }
  if (!Number.isInteger(depth) || depth <= 0) throw new Error("depth must be a positive integer");
  if (leaves.length > 2 ** depth) throw new Error("tree capacity exceeded");
  leaves.forEach((leaf, i) => assertField(leaf, `leaf[${i}]`));

  const zeros: bigint[] = [0n];
  for (let i = 0; i < depth; i++) zeros.push(poseidon2([zeros[i], zeros[i]]));

  let level = leaves.slice();
  const levels: bigint[][] = [level];
  for (let d = 0; d < depth; d++) {
    const next: bigint[] = [];
    for (let i = 0; i < Math.max(1, Math.ceil(level.length / 2)); i++) {
      next.push(poseidon2([level[2 * i] ?? zeros[d], level[2 * i + 1] ?? zeros[d]]));
    }
    level = next;
    levels.push(level);
  }

  return {
    root: level[0],
    path(index: number): MerklePath {
      if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
        throw new Error("leaf index out of range");
      }
      const bits: number[] = [];
      const sibs: bigint[] = [];
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

/** Recompute the root from a leaf + authentication path (verifies inclusion). */
export function rootFromPath(leaf: bigint, bits: number[], sibs: bigint[]): bigint {
  assertField(leaf, "leaf");
  if (!Array.isArray(bits) || !Array.isArray(sibs)) throw new Error("path must contain arrays");
  if (bits.length !== DEPTH) throw new Error(`path must contain exactly ${DEPTH} levels`);
  if (bits.length !== sibs.length) throw new Error("path arrays must have equal length");
  bits.forEach((bit, i) => {
    if (bit !== 0 && bit !== 1) throw new Error(`invalid path bit at ${i}`);
  });
  sibs.forEach((sib, i) => assertField(sib, `sibling[${i}]`));

  let current = leaf;
  for (let i = 0; i < bits.length; i++) {
    current = bits[i] === 0 ? poseidon2([current, sibs[i]]) : poseidon2([sibs[i], current]);
  }
  return current;
}

export { isCanonical };
