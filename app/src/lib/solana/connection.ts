import { Connection, PublicKey } from "@solana/web3.js";
import { RPC_URL, PROGRAM_ID, VOTING_VERIFIER_ID, TALLY_VERIFIER_ID } from "@/lib/config";

let _connection: Connection | null = null;

export function getConnection(): Connection {
  if (!_connection) _connection = new Connection(RPC_URL, "confirmed");
  return _connection;
}

export const programId = new PublicKey(PROGRAM_ID);
export const votingVerifierId = new PublicKey(VOTING_VERIFIER_ID);
export const tallyVerifierId = new PublicKey(TALLY_VERIFIER_ID);
