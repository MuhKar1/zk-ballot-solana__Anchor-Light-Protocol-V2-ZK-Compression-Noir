// Poseidon (BN254) wrappers around `poseidon-lite`. The underlying library is
// the exact dialect the Noir circuits and the Rust program use (it is pinned by
// `zkp-voting/client` for the same reason — see `check.mjs` parity vectors).

import {
  poseidon2 as _p2,
  poseidon3 as _p3,
  poseidon4 as _p4,
} from "poseidon-lite";

/** hash_2([a, b]) — matches Noir `voting_lib` hash_2 and Solana Bn254X5 syscall. */
export function poseidon2(input: bigint[]): bigint {
  return BigInt(_p2(input as never));
}

/** hash_3([a, b, c]) — used by slot randomness. */
export function poseidon3(input: bigint[]): bigint {
  return BigInt(_p3(input as never));
}

/** hash_4([a, b, c, d]) — used by the nullifier. */
export function poseidon4(input: bigint[]): bigint {
  return BigInt(_p4(input as never));
}
