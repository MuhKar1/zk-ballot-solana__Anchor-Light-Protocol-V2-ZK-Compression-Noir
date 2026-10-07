// Tally witness builder — the client half of `tally_circuit`. Given the ordered
// ballots and the election secret key, it recovers y-coordinates, decrypts each
// slot, sums the totals, and folds the transcript. Mirrors `circuits/tally_circuit`
// and `zkp-voting/client/make_tally_inputs.mjs`.

import { add, G, recoverY, scalarMul } from "./crypto/grumpkin";
import { poseidon2 } from "./crypto/poseidon";
import { ballotCommitment, ballotFieldsFromXs } from "./crypto/ballot";
import { transcriptFold, transcriptInit } from "./crypto/transcript";

export const N_BALLOTS = 8;
const K_MAX = 4;

export interface TallyBallot {
  nullifier: bigint;
  /** 8 x-coordinates (slot i -> [C1.x, C2.x]). */
  xs: bigint[];
  /** Packed y-parity byte. */
  parity: number;
}

export interface TallyInputs {
  sk: bigint;
  pkX: bigint;
  pkY: bigint;
  maxCandidates: number;
  /** Real ballots in cast order (length <= 8). */
  ballots: TallyBallot[];
}

/** Prover.toml-shaped witness for `tally_circuit`. */
export interface TallyWitness {
  transcript: string;
  ballot_count: string;
  max_candidates: string;
  pk_hash: string;
  totals: string[];
  xs: string[][];
  ys: string[][];
  parities: string[];
  nullifiers: string[];
  pk_x: string;
  pk_y: string;
  sk: string;
}

const toDec = (x: bigint) => x.toString();

function recoverBallotYs(xs: bigint[], parity: number): bigint[] {
  return xs.map((x, k) => recoverY(x, (parity >> k) & 1));
}

/** Decrypt each of the 4 slots: C2 == sk·C1 (bit 0) or sk·C1 + G (bit 1). */
function decryptChoice(sk: bigint, xs: bigint[], ys: bigint[]): boolean[] {
  const choice: boolean[] = [];
  for (let slot = 0; slot < K_MAX; slot++) {
    const c1 = { x: xs[slot * 2], y: ys[slot * 2] };
    const c2 = { x: xs[slot * 2 + 1], y: ys[slot * 2 + 1] };
    const skC1 = scalarMul(c1, sk);
    const one = add(skC1, G);
    if (c2.x === skC1.x && c2.y === skC1.y) choice.push(false);
    else if (c2.x === one.x && c2.y === one.y) choice.push(true);
    else throw new Error(`slot ${slot}: ciphertext is neither sk*C1 nor sk*C1 + G`);
  }
  return choice;
}

export function buildTallyWitness(input: TallyInputs): TallyWitness {
  if (input.ballots.length > N_BALLOTS) throw new Error("too many ballots (max 8)");

  const pkHash = poseidon2([input.pkX, input.pkY]);
  let acc = transcriptInit();
  const totals = [0n, 0n, 0n, 0n];

  const xs: string[][] = [];
  const ys: string[][] = [];
  const parities: string[] = [];
  const nullifiers: string[] = [];

  // Inactive slots still get decompressed + decrypted by the circuit, so pad them
  // with a valid one-hot ballot (the last real one) — same as make_tally_inputs.mjs.
  const template: TallyBallot =
    input.ballots[input.ballots.length - 1] ??
    { nullifier: 0n, xs: new Array(8).fill(0n), parity: 0 };

  for (let i = 0; i < N_BALLOTS; i++) {
    const active = i < input.ballots.length;
    const ballot = active ? input.ballots[i] : template;
    const ballotYs = recoverBallotYs(ballot.xs, ballot.parity);

    if (active) {
      const commitment = ballotCommitment(ballotFieldsFromXs(ballot.xs, ballot.parity));
      acc = transcriptFold(acc, ballot.nullifier, commitment);
      const choice = decryptChoice(input.sk, ballot.xs, ballotYs);
      for (let j = 0; j < K_MAX; j++) if (choice[j]) totals[j] += 1n;
    }

    xs.push(ballot.xs.map(toDec));
    ys.push(ballotYs.map(toDec));
    parities.push(String(ballot.parity));
    nullifiers.push(toDec(ballot.nullifier));
  }

  return {
    transcript: toDec(acc),
    ballot_count: String(input.ballots.length),
    max_candidates: String(input.maxCandidates),
    pk_hash: toDec(pkHash),
    totals: totals.map(toDec),
    xs,
    ys,
    parities,
    nullifiers,
    pk_x: toDec(input.pkX),
    pk_y: toDec(input.pkY),
    sk: toDec(input.sk),
  };
}
