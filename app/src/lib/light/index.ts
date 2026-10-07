// Light Protocol V2 helpers. Wraps @lightprotocol/stateless.js (the same SDK the
// test suites use) so the UI can fetch validity proofs and derive compressed
// account addresses in the browser.

import {
  accountCompressionProgram,
  createRpc,
  deriveAddressSeedV2,
  deriveAddressV2,
  getAccountCompressionAuthority,
  getRegisteredProgramPda,
  lightSystemProgram,
  TreeType,
} from "@lightprotocol/stateless.js";
import { PublicKey } from "@solana/web3.js";
import BN from "bn.js";
import { LIGHT_INDEXER_URL, LIGHT_PROVER_URL, RPC_URL } from "@/lib/config";

export { accountCompressionProgram, getAccountCompressionAuthority, getRegisteredProgramPda, lightSystemProgram, TreeType };

export function createLightRpc(): ReturnType<typeof createRpc> {
  return createRpc(RPC_URL, LIGHT_INDEXER_URL, LIGHT_PROVER_URL);
}

export function ballotAddressSeed(position: PublicKey, nullifier: Uint8Array) {
  return deriveAddressSeedV2([Buffer.from("nullifier"), position.toBuffer(), Buffer.from(nullifier)]);
}

export function ballotAddress(seed: unknown, addressTree: PublicKey, programId: PublicKey): PublicKey {
  return deriveAddressV2(seed as never, addressTree, programId);
}

export function toAddressBn(pubkey: PublicKey): BN {
  return new BN(pubkey.toBytes());
}
