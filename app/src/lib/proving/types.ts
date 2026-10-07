// Proving strategy interface.
//
// The Groth16 proving key + circuit must match the *already deployed* Sunspot
// verifier programs (pinned IDs). Proving currently runs through the Node/sunspot
// CLI via a server route (`/api/prove`) — the fastest path to a working demo.
// The on-device WASM prover (gnark -> wasm, running in a Web Worker) will implement
// this same interface later so the witness never leaves the browser.

/** Flat Prover.toml inputs for `voting_circuit` (Noir `main` parameters). */
export interface VoteWitness {
  merkle_root_pub: string;
  nullifier: string;
  election_id: string;
  position_id: string;
  max_candidates: string;
  pk_hash: string;
  ballot_commitment: string;
  s: string;
  bits: boolean[];
  sibs: string[];
  choice: boolean[];
  r_seed: string;
  pk_x: string;
  pk_y: string;
}

export interface Prover {
  /** Return the 388-byte Groth16 proof for the voting circuit. */
  proveVote(witness: VoteWitness): Promise<Uint8Array>;
  /** Return the 388-byte Groth16 proof for the tally circuit. */
  proveTally(inputs: object): Promise<Uint8Array>;
}
