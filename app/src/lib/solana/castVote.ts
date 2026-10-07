// cast_vote — the full Light V2 + Sunspot transaction recipe, ported verbatim
// from `zkp-voting/tests/compressed-ballot.ts`. This is the Layer-1 (Light CPI)
// half of a vote: the caller supplies the Groth16 proof and the encrypted ballot,
// and this builds the versioned transaction with the address lookup table.

import {
  AddressLookupTableProgram,
  ComputeBudgetProgram,
  PublicKey,
  SystemProgram,
  type AccountMeta,
} from "@solana/web3.js";
import BN from "bn.js";
import type { Program } from "@coral-xyz/anchor";
import type { ZkpVoting } from "@/idl/zkp_voting";
import { votingVerifierId } from "./connection";
import {
  accountCompressionProgram,
  ballotAddress,
  ballotAddressSeed,
  createLightRpc,
  getAccountCompressionAuthority,
  getRegisteredProgramPda,
  lightSystemProgram,
  TreeType,
  toAddressBn,
} from "@/lib/light";
import { cpiSignerPda } from "./pda";
import { sendVersioned } from "./send";
import type { SolanaWallet } from "./wallet";

const OUTPUT_STATE_TREE_INDEX = 3;
const COMPUTE_BUDGET = ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 });

export interface CastVoteInput {
  program: Program<ZkpVoting>;
  wallet: SolanaWallet;
  proof: Uint8Array; // 388-byte Groth16 proof
  nullifier: Uint8Array; // 32 bytes
  xs: Uint8Array[]; // 8 × 32 bytes
  parityBits: number;
  election: PublicKey;
  position: PublicKey;
  transcript: PublicKey;
}

async function wait(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function createVoteLookupTable(
  wallet: SolanaWallet,
  addresses: PublicKey[]
): Promise<import("@solana/web3.js").AddressLookupTableAccount> {
  const { getConnection } = await import("./connection");
  const connection = getConnection();
  const { sendLegacy } = await import("./send");

  const recentSlot = await connection.getSlot("confirmed");
  const [createIx, lookupTableAddress] = AddressLookupTableProgram.createLookupTable({
    payer: wallet.publicKey,
    authority: wallet.publicKey,
    recentSlot,
  });
  await sendLegacy(wallet, createIx);

  const extendIx = AddressLookupTableProgram.extendLookupTable({
    payer: wallet.publicKey,
    authority: wallet.publicKey,
    lookupTable: lookupTableAddress,
    addresses,
  });
  await sendLegacy(wallet, extendIx);

  const lookupTableResult = await connection.getAddressLookupTable(lookupTableAddress);
  if (!lookupTableResult.value) throw new Error("failed to create the vote address lookup table");

  while ((await connection.getSlot("confirmed")) <= lookupTableResult.value.state.lastExtendedSlot) {
    await wait(100);
  }
  return lookupTableResult.value;
}

export async function castVote(input: CastVoteInput): Promise<string> {
  const { program, wallet, proof, nullifier, xs, parityBits, election, position, transcript } = input;

  const rpc = createLightRpc();
  const addressTree = await rpc.getAddressTreeInfoV2();
  const outputTree = (await rpc.getStateTreeInfos()).find(
    (t: { treeType: TreeType }) => t.treeType === TreeType.StateV2
  ) as { tree: PublicKey; queue: PublicKey; cpiContext: PublicKey } | undefined;
  if (!outputTree?.cpiContext) throw new Error("Light V2 state tree is not available");

  const seed = ballotAddressSeed(position, nullifier);
  const address = ballotAddress(seed, addressTree.tree, program.programId);

  const validity = await rpc.getValidityProofV0([], [
    { address: toAddressBn(address), tree: addressTree.tree, queue: addressTree.queue },
  ]);
  if (!validity.compressedProof) throw new Error("Light prover returned no validity proof");

  const [cpiSigner] = cpiSignerPda(program.programId);
  const systemAccounts: AccountMeta[] = [
    { pubkey: new PublicKey(lightSystemProgram), isSigner: false, isWritable: false },
    { pubkey: cpiSigner, isSigner: false, isWritable: false },
    { pubkey: getRegisteredProgramPda(), isSigner: false, isWritable: false },
    { pubkey: getAccountCompressionAuthority(), isSigner: false, isWritable: false },
    { pubkey: new PublicKey(accountCompressionProgram), isSigner: false, isWritable: false },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];
  const remainingAccounts: AccountMeta[] = [
    ...systemAccounts,
    { pubkey: addressTree.tree, isSigner: false, isWritable: true },
    { pubkey: addressTree.queue, isSigner: false, isWritable: true },
    { pubkey: outputTree.tree, isSigner: false, isWritable: true },
    { pubkey: outputTree.queue, isSigner: false, isWritable: true },
    { pubkey: outputTree.cpiContext, isSigner: false, isWritable: true },
  ];

  const lookupAddresses = [
    program.programId,
    election,
    position,
    transcript,
    votingVerifierId,
    ...remainingAccounts.map((a) => a.pubkey),
  ].filter(
    (key, index, keys) =>
      !key.equals(wallet.publicKey) &&
      !key.equals(SystemProgram.programId) &&
      keys.findIndex((c) => c.equals(key)) === index
  );
  const lookupTable = await createVoteLookupTable(wallet, lookupAddresses);

  const addressTreeInfo = {
    addressMerkleTreePubkeyIndex: 0,
    addressQueuePubkeyIndex: 1,
    rootIndex: validity.rootIndices[0],
  };
  const validityProof = {
    0: {
      a: Array.from(validity.compressedProof.a),
      b: Array.from(validity.compressedProof.b),
      c: Array.from(validity.compressedProof.c),
    },
  };

  const instruction = await program.methods
    .castVote(
      Buffer.from(proof),
      Array.from(nullifier),
      xs.map((x) => Array.from(x)),
      parityBits,
      validityProof,
      addressTreeInfo,
      OUTPUT_STATE_TREE_INDEX
    )
    .accountsStrict({
      payer: wallet.publicKey,
      election,
      position,
      transcript,
      verifier: votingVerifierId,
    })
    .remainingAccounts(remainingAccounts)
    .instruction();

  return sendVersioned(wallet, [COMPUTE_BUDGET, instruction], lookupTable);
}
