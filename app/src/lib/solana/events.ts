// Fetch and decode the on-chain `BallotCast` events (the order-preserving source of
// nullifiers + ciphertexts). We scan the *transcript* account's history (it is
// writable on every `cast_vote`, so it is indexed by `getSignaturesForAddress`),
// then filter decoded events by position.

import type { Connection } from "@solana/web3.js";
import { PublicKey } from "@solana/web3.js";
import { bytesToBigInt } from "@/lib/crypto";
import { programId } from "./connection";

const BALLOT_CAST_DISCRIMINATOR = [194, 0, 41, 178, 6, 3, 169, 32];
const EVENT_BYTES = 8 + 32 + 32 + 32 + 8 * 32 + 1; // disc + election + position + nullifier + xs + parity

export interface BallotCastEvent {
  election: string;
  position: string;
  nullifier: bigint;
  xs: bigint[];
  parityBits: number;
}

function decodeBallotCast(data: Uint8Array): BallotCastEvent | null {
  if (data.length !== EVENT_BYTES) return null;
  for (let i = 0; i < 8; i++) if (data[i] !== BALLOT_CAST_DISCRIMINATOR[i]) return null;

  let off = 8;
  const read32 = () => {
    const slice = data.slice(off, off + 32);
    off += 32;
    return slice;
  };

  const election = new PublicKey(read32()).toBase58();
  const position = new PublicKey(read32()).toBase58();
  const nullifier = bytesToBigInt(read32());
  const xs: bigint[] = [];
  for (let i = 0; i < 8; i++) xs.push(bytesToBigInt(read32()));
  const parityBits = data[off];

  return { election, position, nullifier, xs, parityBits };
}

function base64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

export async function fetchBallotCasts(
  connection: Connection,
  position: PublicKey
): Promise<BallotCastEvent[]> {
  // Scan the *program's* transaction history. The program is always a static
  // account key in every cast_vote transaction, whereas the ballot accounts
  // (transcript / election / position) are loaded via the address lookup table and
  // may not be indexed by `getSignaturesForAddress` on all RPCs (the Light
  // test-validator omits lookup-table addresses). We then filter by position.
  const signatures = await connection.getSignaturesForAddress(
    programId,
    { limit: 1000 },
    "confirmed"
  );

  const events: BallotCastEvent[] = [];
  for (const { signature } of signatures) {
    const tx = await connection.getTransaction(signature, {
      maxSupportedTransactionVersion: 0,
      commitment: "confirmed",
    });
    for (const line of tx?.meta?.logMessages ?? []) {
      const prefix = line.startsWith("Program data: ")
        ? "Program data: "
        : line.startsWith("Program log: ")
          ? "Program log: "
          : null;
      if (!prefix) continue;
      let data: Uint8Array;
      try {
        data = base64ToBytes(line.slice(prefix.length));
      } catch {
        continue;
      }
      const event = decodeBallotCast(data);
      if (event && event.position === position.toBase58()) events.push(event);
    }
  }

  // `getSignaturesForAddress` is newest-first; return in cast (chronological) order.
  events.reverse();
  return events;
}
