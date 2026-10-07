// Running tally transcript: acc = H(acc, H(nullifier, commitment)), starting at
// TAG_TRANSCRIPT. Matches `voting_lib::transcript_fold`.

import { poseidon2 } from "./poseidon";

export const TAG_TRANSCRIPT = 5n;

export function transcriptInit(): bigint {
  return TAG_TRANSCRIPT;
}

export function transcriptFold(acc: bigint, nullifier: bigint, commitment: bigint): bigint {
  return poseidon2([acc, poseidon2([nullifier, commitment])]);
}
