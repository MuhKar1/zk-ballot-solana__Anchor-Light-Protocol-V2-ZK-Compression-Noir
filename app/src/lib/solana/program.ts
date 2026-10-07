import { AnchorProvider, Program } from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";
import idlJson from "@/idl/zkp_voting.json";
import type { ZkpVoting } from "@/idl/zkp_voting";
import { getConnection } from "./connection";
import type { SolanaWallet } from "./wallet";

export type { ZkpVoting };
export const idl = idlJson as unknown as ZkpVoting;

function providerFor(wallet: SolanaWallet): AnchorProvider {
  return new AnchorProvider(getConnection(), wallet, {
    commitment: "confirmed",
    preflightCommitment: "confirmed",
  });
}

/** Build an Anchor Program bound to a connected wallet (admin or payer). */
export function getProgram(wallet: SolanaWallet): Program<ZkpVoting> {
  return new Program(idl, providerFor(wallet)) as Program<ZkpVoting>;
}

/** Read-only program for account fetches (no signer required). */
export function getReadonlyProgram(): Program<ZkpVoting> {
  const readOnly: SolanaWallet = {
    publicKey: PublicKey.default,
    signTransaction: async (tx) => {
      throw new Error("read-only wallet cannot sign");
    },
    signAllTransactions: async (txs) => {
      throw new Error("read-only wallet cannot sign");
    },
  };
  return new Program(idl, providerFor(readOnly)) as Program<ZkpVoting>;
}


