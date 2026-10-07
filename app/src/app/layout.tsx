import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "@/components/providers";
import { Topbar } from "@/components/topbar";

export const metadata: Metadata = {
  title: "ZKP Voting",
  description:
    "Zero-knowledge voting on Solana — Anchor + Light Protocol V2 + Noir/Sunspot Groth16 proofs.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>
          <Topbar />
          {children}
        </Providers>
      </body>
    </html>
  );
}
