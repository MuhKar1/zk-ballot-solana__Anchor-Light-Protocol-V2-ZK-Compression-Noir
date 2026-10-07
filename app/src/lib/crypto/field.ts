// BN254 scalar field — the field every Poseidon hash and the Grumpkin
// embedded curve live in. Mirrors `BN254_MODULUS` in the client scripts and
// the Rust program's canonical-field check.

export const BN254_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Reduce `a` into [0, modulus). */
export function mod(a: bigint, m: bigint = BN254_MODULUS): bigint {
  return ((a % m) + m) % m;
}

/** True when `x` is a canonical field element (0 <= x < modulus). */
export function isCanonical(x: bigint): boolean {
  return typeof x === "bigint" && x >= 0n && x < BN254_MODULUS;
}

export function assertField(x: bigint, name = "value"): void {
  if (!isCanonical(x)) throw new Error(`${name} must be a canonical BN254 field element`);
}

/** Format a field element as a 0x-prefixed 64-hex-digit string. */
export function hex(x: bigint): string {
  return "0x" + x.toString(16).padStart(64, "0");
}

/** Parse a 0x-prefixed hex string (e.g. from the fixture) into a bigint. */
export function fieldFromHex(h: string): bigint {
  const value = BigInt(h);
  if (value < 0n || value >= BN254_MODULUS) {
    throw new Error(`value is not a canonical field element: ${h}`);
  }
  return value;
}

/** Encode a field element as 32 big-endian bytes. */
export function fieldBytes(x: bigint): number[] {
  assertField(x);
  const out = new Array<number>(32).fill(0);
  let v = x;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Decode 32 big-endian bytes (number[] or Uint8Array) back into a bigint. */
export function bytesToBigInt(bytes: number[] | Uint8Array): bigint {
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b & 0xff);
  return x;
}


export function modPow(base: bigint, exp: bigint, m: bigint = BN254_MODULUS): bigint {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return result;
}

export function modInv(a: bigint, m: bigint = BN254_MODULUS): bigint {
  return modPow(a, m - 2n, m);
}

/** Cryptographically random scalar in [1, modulus-1] (used for tally key / r_seed). */
export function randomField(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  return (x % (BN254_MODULUS - 1n)) + 1n;
}


/** Tonelli–Shanks square root in the BN254 field (throws if non-residue). */
export function modSqrt(a: bigint): bigint {
  const P = BN254_MODULUS;
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
