// Server-only relayer wallet. The relayer signs and pays for every `cast_vote`
// transaction so the voter's public key never appears on-chain. This module must
// only be imported from server code (API routes) — it reads RELAYER_SECRET_KEY,
// which is intentionally not exposed via a NEXT_PUBLIC_* prefix.

import { Keypair, Transaction, VersionedTransaction } from "@solana/web3.js";
import type { SolanaWallet } from "./wallet";

let _relayer: SolanaWallet | null = null;

function buildWallet(secretKey: Uint8Array): SolanaWallet {
  const keypair = Keypair.fromSecretKey(secretKey);
  return {
    publicKey: keypair.publicKey,
    signTransaction: async (tx) => {
      if (tx instanceof VersionedTransaction) tx.sign([keypair]);
      else (tx as Transaction).partialSign(keypair);
      return tx;
    },
    signAllTransactions: async (txs) => {
      for (const tx of txs) {
        if (tx instanceof VersionedTransaction) tx.sign([keypair]);
        else (tx as Transaction).partialSign(keypair);
      }
      return txs;
    },
  };
}

/** Build (and cache) the relayer wallet from RELAYER_SECRET_KEY. */
export function getRelayerWallet(): SolanaWallet {
  if (_relayer) return _relayer;

  const raw = process.env.RELAYER_SECRET_KEY;
  if (!raw) {
    throw new Error("RELAYER_SECRET_KEY is not set — configure the relayer wallet in .env.local");
  }

  let secret: unknown;
  try {
    secret = JSON.parse(raw);
  } catch {
    throw new Error("RELAYER_SECRET_KEY must be a JSON array of 64 numbers");
  }
  if (!Array.isArray(secret) || secret.length !== 64) {
    throw new Error("RELAYER_SECRET_KEY must be a JSON array of 64 numbers (an ed25519 secret key)");
  }

  _relayer = buildWallet(Uint8Array.from(secret as number[]));
  return _relayer;
}
