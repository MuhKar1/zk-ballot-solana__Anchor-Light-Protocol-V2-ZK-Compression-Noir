// Shared transaction senders. The Light validator is picky about confirmation,
// so we use the explicit blockhash + lastValidBlockHeight pattern from the test
// suites instead of `sendAndConfirm`.

import {
  ComputeBudgetProgram,
  Transaction,
  TransactionMessage,
  VersionedTransaction,
  type AddressLookupTableAccount,
  type TransactionInstruction,
} from "@solana/web3.js";
import type { SolanaWallet } from "./wallet";
import { getConnection } from "./connection";

export async function sendLegacy(
  wallet: SolanaWallet,
  instruction: TransactionInstruction | TransactionInstruction[]
): Promise<string> {
  const connection = getConnection();
  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash("confirmed");
  const list = Array.isArray(instruction) ? instruction : [instruction];
  const transaction = new Transaction({ feePayer: wallet.publicKey, recentBlockhash: blockhash }).add(
    ...list
  );
  const signed = await wallet.signTransaction(transaction);
  const signature = await connection.sendRawTransaction(signed.serialize(), {
    preflightCommitment: "confirmed",
  });
  await connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
  return signature;
}

/** Legacy transaction with an elevated compute budget (post_tally needs 1.4M CU). */
export async function sendLegacyWithBudget(
  wallet: SolanaWallet,
  instruction: TransactionInstruction,
  units = 1_400_000
): Promise<string> {
  return sendLegacy(wallet, [
    ComputeBudgetProgram.setComputeUnitLimit({ units }),
    instruction,
  ]);
}

export async function sendVersioned(
  wallet: SolanaWallet,
  instructions: TransactionInstruction[],
  lookupTable: AddressLookupTableAccount
): Promise<string> {
  const connection = getConnection();
  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash("confirmed");
  const message = new TransactionMessage({
    payerKey: wallet.publicKey,
    recentBlockhash: blockhash,
    instructions,
  }).compileToV0Message([lookupTable]);
  const transaction = new VersionedTransaction(message);
  const signed = await wallet.signTransaction(transaction);
  const signature = await connection.sendRawTransaction(signed.serialize(), {
    preflightCommitment: "confirmed",
  });
  await connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
  return signature;
}
