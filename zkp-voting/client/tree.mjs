import assert from "node:assert/strict";
import { poseidon2, poseidon4 } from "poseidon-lite";

export const DEPTH = 24;
export const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const TAG_LEAF = 1n;
export const TAG_NULL = 2n;
export const leafOf = (s) => poseidon2([TAG_LEAF, s]);
export const nullifierOf = (s, electionId, positionId) => poseidon4([TAG_NULL, s, electionId, positionId]);
export const hex = (x) => "0x" + x.toString(16).padStart(64, "0");

function assertField(value, name) {
  assert.equal(typeof value, "bigint", `${name} must be a bigint`);
  assert.ok(value >= 0n && value < BN254_MODULUS, `${name} must be canonical`);
}

export function buildTree(leaves, depth = DEPTH) {
  assert.ok(Array.isArray(leaves) && leaves.length > 0, "tree requires at least one leaf");
  assert.ok(Number.isInteger(depth) && depth > 0, "depth must be a positive integer");
  assert.ok(leaves.length <= 2 ** depth, "tree capacity exceeded");
  leaves.forEach((leaf, index) => assertField(leaf, `leaf[${index}]`));
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
      assert.ok(Number.isInteger(index) && index >= 0 && index < leaves.length, "leaf index out of range");
      const bits = [], sibs = [];
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

export function rootFromPath(leaf, bits, sibs) {
  assertField(leaf, "leaf");
  assert.ok(Array.isArray(bits) && Array.isArray(sibs), "path must contain arrays");
  assert.equal(bits.length, DEPTH, `path must contain exactly ${DEPTH} levels`);
  assert.equal(bits.length, sibs.length, "path arrays must have equal length");
  bits.forEach((bit, index) => assert.ok(bit === 0 || bit === 1, `invalid path bit at ${index}`));
  sibs.forEach((sibling, index) => assertField(sibling, `sibling[${index}]`));
  let current = leaf;
  for (let i = 0; i < bits.length; i++) {
    current = bits[i] === 0 ? poseidon2([current, sibs[i]]) : poseidon2([sibs[i], current]);
  }
  return current;
}