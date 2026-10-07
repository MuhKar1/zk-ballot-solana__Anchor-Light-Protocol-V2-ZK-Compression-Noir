// Grumpkin — the embedded curve used for ElGamal ballot encryption:
//   y^2 = x^3 - 17  over the BN254 scalar field.
//
// The generator G is the curve's fixed base point (x = 1). Its y-coordinate is
// confirmed by the on-chain fixture: pk = 1 * G = (1, G_Y).

import { BN254_MODULUS as P, mod, modInv, modSqrt } from "./field";

export interface Point {
  x: bigint;
  y: bigint;
}

export const G: Point = {
  x: 1n,
  y: 17631683881184975370165255887551781615748388533673675138860n,
};

export function isOnCurve(p: Point): boolean {
  return mod(p.y * p.y - p.x * p.x * p.x + 17n) === 0n;
}

export function negate(p: Point): Point {
  return { x: p.x, y: mod(-p.y) };
}

/** Affine addition for y^2 = x^3 - 17. Throws on the point at infinity. */
export function add(p: Point, q: Point): Point {
  if (p.x === q.x) {
    if (p.y === q.y) return double(p);
    throw new Error("point at infinity (adding inverses)");
  }
  const lambda = mod((q.y - p.y) * modInv(mod(q.x - p.x)));
  const x = mod(lambda * lambda - p.x - q.x);
  const y = mod(lambda * (p.x - x) - p.y);
  return { x, y };
}

/** Affine doubling. */
export function double(p: Point): Point {
  if (p.y === 0n) throw new Error("point at infinity (doubling)");
  const lambda = mod(3n * p.x * p.x * modInv(2n * p.y));
  const x = mod(lambda * lambda - 2n * p.x);
  const y = mod(lambda * (p.x - x) - p.y);
  return { x, y };
}

/** Scalar multiplication via double-and-add. Requires k > 0. */
export function scalarMul(p: Point, k: bigint): Point {
  if (k <= 0n) throw new Error("scalar must be positive");
  let result: Point | null = null;
  let addend: Point = p;
  let n = k;
  while (n > 0n) {
    if (n & 1n) result = result === null ? addend : add(result, addend);
    addend = double(addend);
    n >>= 1n;
  }
  if (result === null) throw new Error("point at infinity");
  return result;
}

/** Compress to (x, parity of y) — matches `voting_lib::compress_point`. */
export function compress(p: Point): { x: bigint; parity: number } {
  return { x: p.x, parity: Number(p.y & 1n) };
}

/** Recover y from x and its parity — matches `make_tally_inputs.mjs::recoverY`. */
export function recoverY(x: bigint, parityBit: number): bigint {
  const rhs = mod(x * x * x - 17n);
  let y = modSqrt(rhs);
  if ((y & 1n) !== BigInt(parityBit)) y = P - y;
  return y;
}

/** Decompress (x, parity) into a full point. */
export function decompress(x: bigint, parityBit: number): Point {
  const y = recoverY(x, parityBit);
  const p: Point = { x, y };
  if (!isOnCurve(p)) throw new Error("decompressed point is not on the Grumpkin curve");
  return p;
}
