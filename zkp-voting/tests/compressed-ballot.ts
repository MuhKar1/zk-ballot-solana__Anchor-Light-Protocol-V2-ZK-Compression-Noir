import * as anchor from "@coral-xyz/anchor";
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
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import BN from "bn.js";
import type { AccountMeta } from "@solana/web3.js";
import {
  AddressLookupTableProgram,
  ComputeBudgetProgram,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import type { ZkpVoting } from "../target/types/zkp_voting";

interface BallotFixture {
  electionId: string;
  positionId: string;
  maxCandidates: number;
  root: string;
  nullifier: string;
  pkX: string;
  pkY: string;
  pkHash: string;
  commitment: string;
  xs: string[];
  parityBits: number;
}

const artifactDirectory = resolve(process.cwd(), "../circuits/target");
const fixture = JSON.parse(
  readFileSync(resolve(artifactDirectory, "voting_circuit.fixture.json"), "utf8")
) as BallotFixture;
const proof = readFileSync(resolve(artifactDirectory, "voting_circuit.proof"));
const publicWitness = readFileSync(resolve(artifactDirectory, "voting_circuit.pw"));
const verifierId = new PublicKey(
  "9jjgdh8kXLqZEkAGYjXTXsXGQeGALJ6YYKn5Gz3KXgYj"
);
const computeBudget = ComputeBudgetProgram.setComputeUnitLimit({
  units: 1_400_000,
});

function fieldBytes(value: string): Buffer {
  assert.match(value, /^0x[0-9a-f]{64}$/i);
  return Buffer.from(value.slice(2), "hex");
}

function witnessField(index: number): Buffer {
  return publicWitness.subarray(12 + index * 32, 12 + (index + 1) * 32);
}

function wait(milliseconds: number): Promise<void> {
  return new Promise((resolveWait) => setTimeout(resolveWait, milliseconds));
}

async function sendVersionedTransaction(
  provider: anchor.AnchorProvider,
  instructions: anchor.web3.TransactionInstruction[],
  lookupTable: anchor.web3.AddressLookupTableAccount
): Promise<string> {
  const { blockhash, lastValidBlockHeight } =
    await provider.connection.getLatestBlockhash("confirmed");
  const message = new TransactionMessage({
    payerKey: provider.wallet.publicKey,
    recentBlockhash: blockhash,
    instructions,
  }).compileToV0Message([lookupTable]);
  const transaction = new VersionedTransaction(message);
  const signedTransaction = await provider.wallet.signTransaction(transaction);
  const signature = await provider.connection.sendRawTransaction(
    signedTransaction.serialize(),
    { preflightCommitment: "confirmed" }
  );
  await provider.connection.confirmTransaction(
    { signature, blockhash, lastValidBlockHeight },
    "confirmed"
  );
  return signature;
}

async function sendLegacyTransaction(
  provider: anchor.AnchorProvider,
  instruction: anchor.web3.TransactionInstruction
): Promise<void> {
  const { blockhash, lastValidBlockHeight } =
    await provider.connection.getLatestBlockhash("confirmed");
  const transaction = new Transaction({
    feePayer: provider.wallet.publicKey,
    recentBlockhash: blockhash,
  }).add(instruction);
  const signedTransaction = await provider.wallet.signTransaction(transaction);
  const signature = await provider.connection.sendRawTransaction(
    signedTransaction.serialize(),
    { preflightCommitment: "confirmed" }
  );
  await provider.connection.confirmTransaction(
    { signature, blockhash, lastValidBlockHeight },
    "confirmed"
  );
}

describe("Light compressed ballot integration", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.ZkpVoting as anchor.Program<ZkpVoting>;

  const CLOCK = new PublicKey("SysvarC1ock11111111111111111111111111111111");

  async function validatorNow(): Promise<number> {
    const info = await provider.connection.getAccountInfo(CLOCK);
    return Number(info!.data.readBigInt64LE(32));
  }

  async function waitUntilValidator(ts: number): Promise<void> {
    while ((await validatorNow()) < ts) await wait(100);
  }

  it("verifies, stores, and prevents replay of a compressed ballot", async () => {
    assert.equal(proof.length, 388, "run the Sunspot proof preparation command");
    assert.equal(publicWitness.length, 236);
    assert.equal(publicWitness.readUInt32BE(0), 7);
    assert.equal(publicWitness.readUInt32BE(8), 7);
    assert.deepEqual(witnessField(0), fieldBytes(fixture.root));
    assert.deepEqual(witnessField(1), fieldBytes(fixture.nullifier));
    assert.deepEqual(
      witnessField(2),
      Buffer.from(new BN(fixture.electionId).toArray("be", 32))
    );
    assert.deepEqual(
      witnessField(3),
      Buffer.from(new BN(fixture.positionId).toArray("be", 32))
    );
    assert.deepEqual(
      witnessField(4),
      Buffer.from(new BN(fixture.maxCandidates).toArray("be", 32))
    );
    assert.deepEqual(witnessField(5), fieldBytes(fixture.pkHash));
    assert.deepEqual(witnessField(6), fieldBytes(fixture.commitment));

    const verifierAccount = await provider.connection.getAccountInfo(verifierId);
    assert.ok(verifierAccount?.executable, "preload the Sunspot verifier program");

    const rpc = createRpc(
      provider.connection.rpcEndpoint,
      process.env.LIGHT_INDEXER_URL ?? "http://127.0.0.1:8784",
      process.env.LIGHT_PROVER_URL ?? "http://127.0.0.1:3001"
    );
    const addressTree = await rpc.getAddressTreeInfoV2();
    assert.equal(
      addressTree.tree.toBase58(),
      "amt2kaJA14v3urZbZvnc5v2np8jqvc4Z8zDep5wbtzx"
    );
    const outputTree = (await rpc.getStateTreeInfos()).find(
      (tree) => tree.treeType === TreeType.StateV2
    );
    assert.ok(outputTree, "Light V2 state tree is not available");
    assert.ok(outputTree.cpiContext, "Light V2 output tree has no CPI context");

    const authority = provider.wallet.publicKey;
    const electionId = new BN(fixture.electionId);
    const positionId = new BN(fixture.positionId);
    const election = PublicKey.findProgramAddressSync(
      [
        Buffer.from("election"),
        authority.toBuffer(),
        electionId.toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    )[0];
    const position = PublicKey.findProgramAddressSync(
      [
        Buffer.from("position"),
        election.toBuffer(),
        positionId.toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    )[0];
    const transcript = PublicKey.findProgramAddressSync(
      [Buffer.from("transcript"), position.toBuffer()],
      program.programId
    )[0];
    const nullifier = fieldBytes(fixture.nullifier);
    const addressSeed = deriveAddressSeedV2([
      Buffer.from("nullifier"),
      position.toBuffer(),
      nullifier,
    ]);
    const ballotAddress = deriveAddressV2(
      addressSeed,
      addressTree.tree,
      program.programId
    );
    const validity = await rpc.getValidityProofV0([], [
      {
        address: new BN(ballotAddress.toBytes()),
        tree: addressTree.tree,
        queue: addressTree.queue,
      },
    ]);
    assert.ok(validity.compressedProof, "Light prover returned no validity proof");
    assert.equal(validity.treeInfos[0]?.tree.toBase58(), addressTree.tree.toBase58());
    assert.equal(validity.treeInfos[0]?.queue.toBase58(), addressTree.queue.toBase58());
    assert.equal(validity.rootIndices.length, 1);

    const [cpiSigner] = PublicKey.findProgramAddressSync(
      [Buffer.from("cpi_authority")],
      program.programId
    );
    const systemAccounts: AccountMeta[] = [
      { pubkey: new PublicKey(lightSystemProgram), isSigner: false, isWritable: false },
      { pubkey: cpiSigner, isSigner: false, isWritable: false },
      { pubkey: getRegisteredProgramPda(), isSigner: false, isWritable: false },
      { pubkey: getAccountCompressionAuthority(), isSigner: false, isWritable: false },
      {
        pubkey: new PublicKey(accountCompressionProgram),
        isSigner: false,
        isWritable: false,
      },
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
      verifierId,
      ...remainingAccounts.map((account) => account.pubkey),
    ].filter(
      (key, index, keys) =>
        !key.equals(authority) &&
        !key.equals(SystemProgram.programId) &&
        keys.findIndex((candidate) => candidate.equals(key)) === index
    );
    const recentSlot = await provider.connection.getSlot("confirmed");
    const [createLookupTableIx, lookupTableAddress] =
      AddressLookupTableProgram.createLookupTable({
        payer: authority,
        authority,
        recentSlot,
      });
    await sendLegacyTransaction(provider, createLookupTableIx);
    const extendLookupTableIx = AddressLookupTableProgram.extendLookupTable({
      payer: authority,
      authority,
      lookupTable: lookupTableAddress,
      addresses: lookupAddresses,
    });
    await sendLegacyTransaction(provider, extendLookupTableIx);
    const lookupTableResult =
      await provider.connection.getAddressLookupTable(lookupTableAddress);
    assert.ok(lookupTableResult.value, "failed to create the vote address lookup table");
    while (
      (await provider.connection.getSlot("confirmed")) <=
      lookupTableResult.value.state.lastExtendedSlot
    ) {
      await wait(100);
    }
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
    const voteArgs = (
      voteProof: Buffer,
      proofArg: typeof validityProof = validityProof
    ) =>
      program.methods.castVote(
        voteProof,
        [...nullifier],
        fixture.xs.map((value) => [...fieldBytes(value)]),
        fixture.parityBits,
        proofArg,
        addressTreeInfo,
        3
      );
    const voteAccounts = {
      payer: authority,
      election,
      position,
      transcript,
      verifier: verifierId,
    };
    const submitVote = async (voteProof: Buffer) => {
      const instruction = await voteArgs(voteProof)
        .accountsStrict(voteAccounts)
        .remainingAccounts(remainingAccounts)
        .instruction();
      return sendVersionedTransaction(
        provider,
        [computeBudget, instruction],
        lookupTableResult.value!
      );
    };

    const now = await validatorNow();
    const voteStart = new BN(now + 10);
    const voteEnd = new BN(now + 3600);
    await sendLegacyTransaction(
      provider,
      await program.methods
        .initializeElection(
        electionId,
        [...fieldBytes(fixture.pkX)],
        [...fieldBytes(fixture.pkY)],
        voteStart,
        voteEnd
      )
        .accountsStrict({
          election,
          authority,
          systemProgram: SystemProgram.programId,
        })
        .instruction()
    );
    await sendLegacyTransaction(
      provider,
      await program.methods
        .initializePosition(positionId, fixture.maxCandidates)
        .accountsStrict({
          election,
          position,
          transcript,
          authority,
          systemProgram: SystemProgram.programId,
        })
        .instruction()
    );

    await assert.rejects(
      sendLegacyTransaction(
        provider,
        await voteArgs(Buffer.alloc(0), { 0: null })
          .accountsStrict(voteAccounts)
          .instruction()
      ),
      "a ballot must not be accepted before the voter root is frozen"
    );
    await sendLegacyTransaction(
      provider,
      await program.methods
        .freezeVoterRoot([...fieldBytes(fixture.root)], new BN(4))
        .accountsStrict({ election, authority })
        .instruction()
    );

    await waitUntilValidator(voteStart.toNumber());
    const invalidProof = Buffer.from(proof);
    invalidProof[0] ^= 1;
    await assert.rejects(
      submitVote(invalidProof),
      "a modified Sunspot proof must be rejected"
    );

    const signature = await submitVote(proof);
    const status = await provider.connection.getSignatureStatus(signature);
    assert.ok(status.value?.slot, "cast transaction has no confirmed slot");
    await rpc.confirmTransactionIndexed(status.value.slot);

    const compressedBallot = await rpc.getCompressedAccount(
      new BN(ballotAddress.toBytes())
    );
    assert.ok(compressedBallot, "Light indexer did not find the compressed ballot");
    assert.equal(compressedBallot.owner.toBase58(), program.programId.toBase58());
    assert.deepEqual(compressedBallot.address, [...ballotAddress.toBytes()]);
    assert.ok(compressedBallot.data, "compressed ballot has no serialized data");
    assert.ok(
      Buffer.from(compressedBallot.data.data).includes(fieldBytes(fixture.commitment)),
      "compressed ballot data does not contain the proven commitment"
    );

    const transcriptAccount = await program.account.ballotTranscript.fetch(transcript);
    assert.equal(transcriptAccount.ballotCount.toNumber(), 1, "transcript must fold exactly one ballot");
    assert.ok(
      transcriptAccount.transcript.some((byte) => byte !== 0),
      "transcript must advance past the initial value"
    );

    await assert.rejects(
      submitVote(proof),
      "the same nullifier must not create a second compressed ballot"
    );
  });
});