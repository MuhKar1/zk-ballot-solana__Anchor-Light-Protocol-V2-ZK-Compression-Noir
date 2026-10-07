// Voter identity: derive the private secret `s` from the credential (id + password).
//
// IMPORTANT (documented trade-off): because the admin *supplies* the password in
// this demo, anyone who knows a voter's password can re-derive their secret. This
// is acceptable for the demo UX but NOT for production — a real deployment should
// use voter self-enrollment (only the leaf is shared) or a proper passkey.

import { poseidon2 } from "./poseidon";
import { BN254_MODULUS as P, isCanonical } from "./field";

async function sha256ToField(domain: string): Promise<bigint> {
  const data = new TextEncoder().encode(domain);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  let x = 0n;
  for (const byte of digest) x = (x << 8n) | BigInt(byte);
  return x % P;
}

/**
 * Deterministic secret from (id, password). The id and password are hashed with
 * SHA-256, reduced into the field, then combined with Poseidon — so the secret
 * only depends on the credential, never on the display name.
 */
export async function deriveSecret(id: string, password: string): Promise<bigint> {
  const idField = await sha256ToField(`zkp-voting:id:${id.trim()}`);
  const passField = await sha256ToField(`zkp-voting:password:${password}`);
  const s = poseidon2([idField, passField]);
  if (!isCanonical(s)) throw new Error("derived secret is non-canonical");
  return s;
}
