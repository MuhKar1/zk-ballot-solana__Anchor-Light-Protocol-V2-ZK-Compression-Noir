// Relayer cast_vote endpoint. The browser builds the Groth16 proof + encrypted
// ballot, then POSTs the *public* payload here. The relayer wallet signs and pays
// the transaction, so the voter's public key never appears on-chain.

import { NextResponse } from "next/server";
import { PublicKey } from "@solana/web3.js";
import { castVote } from "@/lib/solana/castVote";
import { getProgram } from "@/lib/solana/program";
import { getRelayerWallet } from "@/lib/solana/relayer";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function toUint8Array(value: unknown, name: string): Uint8Array {
  if (!Array.isArray(value)) throw new Error(`${name} must be an array of bytes`);
  return Uint8Array.from(value as number[]);
}

export async function POST(req: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
  }

  try {
    const election = new PublicKey(body.election as string);
    const position = new PublicKey(body.position as string);
    const transcript = new PublicKey(body.transcript as string);

    const proof = toUint8Array(body.proof, "proof");
    const nullifier = toUint8Array(body.nullifier, "nullifier");
    if (!Array.isArray(body.xs)) throw new Error("xs must be an array");
    const xs = (body.xs as unknown[]).map((x) => toUint8Array(x, "xs[i]"));
    const parityBits = Number(body.parityBits);

    const wallet = getRelayerWallet();
    const program = getProgram(wallet);

    const sig = await castVote({
      program,
      wallet,
      proof,
      nullifier,
      xs,
      parityBits,
      election,
      position,
      transcript,
    });

    return NextResponse.json({ sig });
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
