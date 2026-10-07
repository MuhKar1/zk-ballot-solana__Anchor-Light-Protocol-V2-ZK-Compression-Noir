"use client";

// Minimal wallet abstraction over Phantom's injected provider, with a fallback
// for pasting a base58 secret key (useful for the devnet/local demo without the
// extension). Matches the Wallet shape AnchorProvider expects.

import {
  Keypair,
  PublicKey,
  Transaction,
  VersionedTransaction,
} from "@solana/web3.js";

export interface SolanaWallet {
  publicKey: PublicKey;
  signTransaction<T extends Transaction | VersionedTransaction>(tx: T): Promise<T>;
  signAllTransactions<T extends Transaction | VersionedTransaction>(txs: T[]): Promise<T[]>;
}

interface PhantomProvider {
  publicKey: PublicKey | null;
  connect(options?: { onlyIfTrusted?: boolean }): Promise<{ publicKey: PublicKey }>;
  disconnect(): Promise<void>;
  signTransaction<T extends Transaction | VersionedTransaction>(tx: T): Promise<T>;
  signAllTransactions<T extends Transaction | VersionedTransaction>(txs: T[]): Promise<T[]>;
  isPhantom?: boolean;
}

function getPhantom(): PhantomProvider | null {
  if (typeof window === "undefined") return null;
  const w = window as unknown as { phantom?: { solana?: PhantomProvider } };
  const provider = w.phantom?.solana;
  if (!provider || typeof provider.connect !== "function") return null;
  return provider;
}

export function hasPhantom(): boolean {
  return getPhantom() !== null;
}

export async function connectPhantom(): Promise<SolanaWallet> {
  const provider = getPhantom();
  if (!provider) {
    throw new Error("Phantom wallet not detected. Install the Phantom extension, or use a pasted key.");
  }
  const resp = await provider.connect();
  return {
    publicKey: resp.publicKey,
    signTransaction: (tx) => provider.signTransaction(tx),
    signAllTransactions: (txs) => provider.signAllTransactions(txs),
  };
}

export async function disconnectPhantom(): Promise<void> {
  const provider = getPhantom();
  if (provider && typeof provider.disconnect === "function") await provider.disconnect();
}

/** Build a wallet from a 64-byte secret key (dev/demo convenience). */
export function walletFromSecretKey(secretKey: Uint8Array): SolanaWallet {
  const keypair = Keypair.fromSecretKey(secretKey);
  return {
    publicKey: keypair.publicKey,
    signTransaction: async (tx) => {
      if (tx instanceof VersionedTransaction) tx.sign([keypair]);
      else tx.partialSign(keypair);
      return tx;
    },
    signAllTransactions: async (txs) => {
      for (const tx of txs) {
        if (tx instanceof VersionedTransaction) tx.sign([keypair]);
        else tx.partialSign(keypair);
      }
      return txs;
    },
  };
}

/** Parse a base58 secret key string into a wallet. */
export function walletFromSecretKeyString(secretKey: string): SolanaWallet {
  return walletFromSecretKey(Uint8Array.from(JSON.parse(secretKey)));
}
