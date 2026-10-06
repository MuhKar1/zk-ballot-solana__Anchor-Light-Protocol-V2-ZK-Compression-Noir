import assert from "node:assert";
import { poseidon2 } from "poseidon-lite";
import { buildTree, leafOf, nullifierOf, rootFromPath, hex, DEPTH } from "./tree.mjs";

assert.equal(hex(poseidon2([1n, 2n])), "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a");
const secret = 987654321n;
assert.equal(hex(leafOf(secret)), "0x2d1a37d46019f0c5d46d149263448d286c1601c47ea3b1053ac5825bcad13a54");
assert.equal(hex(nullifierOf(secret, 7n, 1n)), "0x037e92195747fe291df2bb9d2a9523c2de5c514205380a2ee8d10578516372d9");
const bits = [], sibs = [];
for (let i = 0; i < DEPTH; i++) { bits.push(i % 3 === 0 ? 1 : 0); sibs.push(1000n + BigInt(i)); }
assert.equal(hex(rootFromPath(leafOf(secret), bits, sibs)), "0x0b674b13552d092b0afd70da6db218987e463631095638fa779f8ec6fbe282b8");
const leaves = [11n, 22n, 33n, 44n, 55n].map(leafOf);
const tree = buildTree(leaves);
for (let i = 0; i < leaves.length; i++) {
  const path = tree.path(i);
  assert.equal(rootFromPath(leaves[i], path.bits, path.sibs), tree.root);
}
console.log("TS tree and Noir vectors OK; root =", hex(tree.root));