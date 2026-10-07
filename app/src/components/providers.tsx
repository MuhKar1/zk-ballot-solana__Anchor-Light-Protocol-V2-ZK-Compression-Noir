"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { LAMPORTS_PER_SOL } from "@solana/web3.js";
import type { SolanaWallet } from "@/lib/solana/wallet";
import {
  connectPhantom,
  disconnectPhantom,
  hasPhantom,
  walletFromSecretKeyString,
} from "@/lib/solana/wallet";
import { getConnection } from "@/lib/solana/connection";

interface WalletContextValue {
  wallet: SolanaWallet | null;
  connecting: boolean;
  error: string | null;
  balance: number | null;
  hasPhantom: boolean;
  connectPhantomWallet: () => Promise<void>;
  connectKey: (secret: string) => Promise<void>;
  disconnect: () => Promise<void>;
  refreshBalance: () => Promise<void>;
}

const WalletContext = createContext<WalletContextValue | null>(null);

export function useSolanaWallet(): WalletContextValue {
  const value = useContext(WalletContext);
  if (!value) throw new Error("useSolanaWallet must be used inside <Providers>");
  return value;
}

export function Providers({ children }: { children: ReactNode }) {
  const [wallet, setWallet] = useState<SolanaWallet | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [balance, setBalance] = useState<number | null>(null);

  const refreshBalance = useCallback(async () => {
    if (!wallet) return;
    try {
      const lamports = await getConnection().getBalance(wallet.publicKey);
      setBalance(lamports / LAMPORTS_PER_SOL);
    } catch {
      setBalance(null);
    }
  }, [wallet]);

  const connectPhantomWallet = useCallback(async () => {
    setConnecting(true);
    setError(null);
    try {
      const w = await connectPhantom();
      setWallet(w);
      const lamports = await getConnection().getBalance(w.publicKey);
      setBalance(lamports / LAMPORTS_PER_SOL);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setConnecting(false);
    }
  }, []);

  const connectKey = useCallback(async (secret: string) => {
    setConnecting(true);
    setError(null);
    try {
      const w = walletFromSecretKeyString(secret.trim());
      setWallet(w);
      const lamports = await getConnection().getBalance(w.publicKey);
      setBalance(lamports / LAMPORTS_PER_SOL);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setConnecting(false);
    }
  }, []);

  const disconnect = useCallback(async () => {
    await disconnectPhantom();
    setWallet(null);
    setBalance(null);
  }, []);

  const value = useMemo(
    () => ({
      wallet,
      connecting,
      error,
      balance,
      hasPhantom: hasPhantom(),
      connectPhantomWallet,
      connectKey,
      disconnect,
      refreshBalance,
    }),
    [wallet, connecting, error, balance, connectPhantomWallet, connectKey, disconnect, refreshBalance]
  );

  return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>;
}
