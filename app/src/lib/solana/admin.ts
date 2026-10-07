import { PublicKey, SystemProgram } from "@solana/web3.js";
import BN from "bn.js";
import type { Program } from "@coral-xyz/anchor";
import type { ZkpVoting } from "@/idl/zkp_voting";
import { fieldBytes, G, scalarMul } from "@/lib/crypto";
import { programId, tallyVerifierId } from "./connection";
import { electionPda, positionPda, tallyPda, transcriptPda } from "./pda";
import { sendLegacy, sendLegacyWithBudget } from "./send";
import type { SolanaWallet } from "./wallet";

/** Random scalar in [1, p-1] used as the tally secret key. */
export function generateTallyKey(): { sk: bigint; pkX: bigint; pkY: bigint } {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  const order = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const sk = (x % (order - 1n)) + 1n;
  const pk = scalarMul(G, sk);
  return { sk, pkX: pk.x, pkY: pk.y };
}

export interface InitializeElectionArgs {
  electionId: BN;
  pkX: bigint;
  pkY: bigint;
  voteStartTs: BN;
  voteEndTs: BN;
}

export async function initializeElection(
  program: Program<ZkpVoting>,
  wallet: SolanaWallet,
  args: InitializeElectionArgs
): Promise<string> {
  const [election] = electionPda(wallet.publicKey, args.electionId, programId);
  const ix = await program.methods
    .initializeElection(
      args.electionId,
      fieldBytes(args.pkX),
      fieldBytes(args.pkY),
      args.voteStartTs,
      args.voteEndTs
    )
    .accountsStrict({
      election,
      authority: wallet.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .instruction();
  return sendLegacy(wallet, ix);
}

export async function initializePosition(
  program: Program<ZkpVoting>,
  wallet: SolanaWallet,
  args: { electionId: BN; positionId: BN; maxCandidates: number }
): Promise<string> {
  const [election] = electionPda(wallet.publicKey, args.electionId, programId);
  const [position] = positionPda(election, args.positionId, programId);
  const [transcript] = transcriptPda(position, programId);
  const ix = await program.methods
    .initializePosition(args.positionId, args.maxCandidates)
    .accountsStrict({
      election,
      position,
      transcript,
      authority: wallet.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .instruction();
  return sendLegacy(wallet, ix);
}

export async function freezeVoterRoot(
  program: Program<ZkpVoting>,
  wallet: SolanaWallet,
  args: { electionId: BN; root: bigint; leafCount: number }
): Promise<string> {
  const [election] = electionPda(wallet.publicKey, args.electionId, programId);
  const ix = await program.methods
    .freezeVoterRoot(fieldBytes(args.root), new BN(args.leafCount))
    .accountsStrict({ election, authority: wallet.publicKey })
    .instruction();
  return sendLegacy(wallet, ix);
}

export async function postTally(
  program: Program<ZkpVoting>,
  wallet: SolanaWallet,
  args: {
    electionId: BN;
    positionId: BN;
    totals: number[];
    proof: Uint8Array;
  }
): Promise<string> {
  const [election] = electionPda(wallet.publicKey, args.electionId, programId);
  const [position] = positionPda(election, args.positionId, programId);
  const [transcript] = transcriptPda(position, programId);
  const [tally] = tallyPda(position, programId);
  const ix = await program.methods
    .postTally(args.totals.map((t) => new BN(t)), Buffer.from(args.proof))
    .accountsStrict({
      election,
      position,
      transcript,
      tally,
      authority: wallet.publicKey,
      verifier: tallyVerifierId,
      systemProgram: SystemProgram.programId,
    })
    .instruction();
  return sendLegacyWithBudget(wallet, ix);
}

export interface AdminElection {
  publicKey: PublicKey;
  electionId: BN;
  isFrozen: boolean;
  leafCount: number;
  voteStartTs: number;
  voteEndTs: number;
  state: "upcoming" | "ongoing" | "ended";
}

/** List every election this authority has created, newest first. */
export async function fetchAdminElections(
  program: Program<ZkpVoting>,
  authority: PublicKey
): Promise<AdminElection[]> {
  // `authority` is the first field after the 8-byte Anchor discriminator.
  const accounts = await program.account.electionConfig.all([
    { memcmp: { offset: 8, bytes: authority.toBase58() } },
  ]);
  const now = await chainNowSeconds(program);
  return accounts
    .map(({ publicKey, account }) => {
      const voteStartTs = (account.voteStartTs as BN).toNumber();
      const voteEndTs = (account.voteEndTs as BN).toNumber();
      const state: AdminElection["state"] =
        now < voteStartTs ? "upcoming" : now <= voteEndTs ? "ongoing" : "ended";
      return {
        publicKey,
        electionId: account.electionId as BN,
        isFrozen: account.isFrozen as boolean,
        leafCount: (account.leafCount as BN).toNumber(),
        voteStartTs,
        voteEndTs,
        state,
      };
    })
    .sort((a, b) => b.electionId.cmp(a.electionId));
}

/** Current unix seconds from the chain clock (falls back to the system clock). */
async function chainNowSeconds(program: Program<ZkpVoting>): Promise<number> {
  try {
    const slot = await program.provider.connection.getSlot("confirmed");
    const time = await program.provider.connection.getBlockTime(slot);
    if (time) return time;
  } catch {
    // fall through to the system clock
  }
  return Math.floor(Date.now() / 1000);
}
