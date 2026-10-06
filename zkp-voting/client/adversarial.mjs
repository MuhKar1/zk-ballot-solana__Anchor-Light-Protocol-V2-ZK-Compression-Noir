import assert from "node:assert/strict";
import { poseidon2, poseidon4 } from "poseidon-lite";
import {
  BN254_MODULUS,
  DEPTH,
  TAG_LEAF,
  TAG_NULL,
  buildTree,
  leafOf,
  nullifierOf,
  rootFromPath,
} from "./tree.mjs";

const tests = [];
const test = (name, fn) => tests.push([name, fn]);
const expectReject = (fn, message) => assert.throws(fn, /./, message);
const leaves = [11n, 22n, 33n, 44n, 55n].map(leafOf);
const tree = buildTree(leaves);

test("all registered leaves have valid paths", () => {
  for (let index = 0; index < leaves.length; index++) {
    const path = tree.path(index);
    assert.equal(rootFromPath(leaves[index], path.bits, path.sibs), tree.root);
  }
});

test("wrong leaf cannot use another voter's path", () => {
  const path = tree.path(0);
  assert.notEqual(rootFromPath(leaves[1], path.bits, path.sibs), tree.root);
});

test("changing a sibling invalidates membership", () => {
  const path = tree.path(2);
  const siblings = [...path.sibs];
  siblings[7] += 1n;
  assert.notEqual(rootFromPath(leaves[2], path.bits, siblings), tree.root);
});

test("changing path direction invalidates membership", () => {
  const path = tree.path(3);
  const bits = [...path.bits];
  bits[0] = bits[0] === 0 ? 1 : 0;
  assert.notEqual(rootFromPath(leaves[3], bits, path.sibs), tree.root);
});

test("truncating or extending a path is rejected", () => {
  const path = tree.path(0);
  expectReject(() => rootFromPath(leaves[0], path.bits.slice(1), path.sibs), "truncated path");
  expectReject(() => rootFromPath(leaves[0], [...path.bits, 0], [...path.sibs, 0n]), "extended path");
});

test("malformed path bits are rejected", () => {
  const path = tree.path(0);
  for (const invalid of [-1, 2, true, "0"]) {
    const bits = [...path.bits];
    bits[4] = invalid;
    expectReject(() => rootFromPath(leaves[0], bits, path.sibs), `bit ${String(invalid)}`);
  }
});

test("malformed sibling field values are rejected", () => {
  const path = tree.path(0);
  for (const invalid of [-1n, BN254_MODULUS, BN254_MODULUS + 1n, 1]) {
    const siblings = [...path.sibs];
    siblings[4] = invalid;
    expectReject(() => rootFromPath(leaves[0], path.bits, siblings), `sibling ${String(invalid)}`);
  }
});

test("invalid leaf indices are rejected", () => {
  for (const index of [-1, leaves.length, 1.5, "0"]) {
    expectReject(() => tree.path(index), `index ${String(index)}`);
  }
});

test("tree capacity and empty-tree inputs are rejected", () => {
  expectReject(() => buildTree([]), "empty tree");
  expectReject(() => buildTree([0n], 0), "zero depth");
  expectReject(() => buildTree(new Array(5).fill(0n), 2), "capacity overflow");
});

test("non-canonical leaves are rejected before hashing", () => {
  expectReject(() => buildTree([BN254_MODULUS]), "modulus alias");
  expectReject(() => buildTree([-1n]), "negative leaf");
  expectReject(() => rootFromPath(BN254_MODULUS, [], []), "non-canonical path leaf");
});

test("leaf and nullifier domains are different", () => {
  const secret = 987654321n;
  assert.notEqual(poseidon2([TAG_LEAF, secret]), poseidon2([TAG_NULL, secret]));
});

test("nullifiers bind both election and position", () => {
  const secret = 987654321n;
  const expected = nullifierOf(secret, 7n, 1n);
  assert.notEqual(expected, nullifierOf(secret, 8n, 1n));
  assert.notEqual(expected, nullifierOf(secret, 7n, 2n));
  assert.equal(expected, nullifierOf(secret, 7n, 1n));
});

test("nullifier is not the registration leaf", () => {
  const secret = 987654321n;
  assert.notEqual(leafOf(secret), nullifierOf(secret, 7n, 1n));
});

test("commitment fold is order-sensitive", () => {
  const fold = (values) => values.reduce((acc, value) => poseidon2([acc, value]), 4n);
  const values = [1n, 2n, 3n, 4n];
  assert.notEqual(fold(values), fold([...values].reverse()));
  assert.notEqual(fold(values), fold([1n, 2n, 3n, 5n]));
});

test("repeated tree construction is deterministic", () => {
  assert.equal(buildTree(leaves).root, tree.root);
  assert.deepEqual(buildTree(leaves).path(4), tree.path(4));
});

let passed = 0;
for (const [name, fn] of tests) {
  fn();
  passed++;
  console.log(`ok ${passed} - ${name}`);
}
console.log(`Adversarial client tests passed: ${passed}/${tests.length}`);