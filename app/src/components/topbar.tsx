"use client";

import Link from "next/link";
import { useSolanaWallet } from "./providers";

export function Topbar() {
  const { wallet, balance, disconnect } = useSolanaWallet();
  return (
    <header className="topbar">
      <Link href="/" className="brand">
        ZKP<span className="accent">·</span>Voting
      </Link>
      <div className="row">
        {wallet ? (
          <>
            <span className="badge ok" title={wallet.publicKey.toBase58()}>
              {wallet.publicKey.toBase58().slice(0, 4)}…
              {wallet.publicKey.toBase58().slice(-4)}
            </span>
            {balance !== null && <span className="badge">{balance.toFixed(3)} SOL</span>}
            <button className="btn btn-ghost" onClick={disconnect}>
              Disconnect
            </button>
          </>
        ) : (
          <span className="badge">not connected</span>
        )}
      </div>
    </header>
  );
}
