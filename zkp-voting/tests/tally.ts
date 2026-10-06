// End-to-end post_tally success test.
//
// Casts a real compressed ballot (Light V2 + Sunspot), then proves — on-chain, via the
// Layer-2 tally circuit — that the published totals decrypt the ballot the chain folded.
// Requires the tally proof prepared by `npm run prepare:tally-proof` (which reads the same
// ballot fixture as the voting proof).
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

interface TallyFixture {
  transcript: string;
  ballotCount: number;
  maxCandidates: number;
  pkHash: string;
  totals: string[];
}

const artifactDirectory = resolve(process.cwd(), "../circuits/target");
const fixture = JSON.parse(readFileSync(resolve(artifactDirectory, "voting_circuit.fixture.json"), "utf8")) as BallotFixture;
const proof = readFileSync(resolve(artifactDirectory, "voting_circuit.proof"));
const publicWitness = readFileSync(resolve(artifactDirectory, "voting_circuit.pw"));
const tallyProof = readFileSync(resolve(artifactDirectory, "tally_circuit.proof"));
const tallyFixture = JSON.parse(readFileSync(resolve(artifactDirectory, "tally_circuit.fixture.json"), "utf8")) as TallyFixture;
const verifierId = new PublicKey("9jjgdh8kXLqZEkAGYjXTXsXGQeGALJ6YYKn5Gz3KXgYj");
const tallyVerifierId = new PublicKey("AuSPaahFzAViTokdyhc6fYNe1gELiHRksbExo2YNptav");
const computeBudget = ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 });

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
  const { blockhash, lastValidBlockHeight } = await provider.connection.getLatestBlockhash("confirmed");
  const message = new TransactionMessage({
    payerKey: provider.wallet.publicKey,
    recentBlockhash: blockhash,
    instructions,
  }).compileToV0Message([lookupTable]);
  const transaction = new VersionedTransaction(message);
  const signedTransaction = await provider.wallet.signTransaction(transaction);
  const signature = await provider.connection.sendRawTransaction(signedTransaction.serialize(), {
    preflightCommitment: "confirmed",
  });
  await provider.connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
  return signature;
}

async function sendLegacyTransaction(
  provider: anchor.AnchorProvider,
  instruction: anchor.web3.TransactionInstruction
): Promise<void> {
  const { blockhash, lastValidBlockHeight } = await provider.connection.getLatestBlockhash("confirmed");
  const transaction = new Transaction({
    feePayer: provider.wallet.publicKey,
    recentBlockhash: blockhash,
  }).add(instruction);
  const signedTransaction = await provider.wallet.signTransaction(transaction);
  const signature = await provider.connection.sendRawTransaction(signedTransaction.serialize(), {
    preflightCommitment: "confirmed",
  });
  await provider.connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
}

describe("trustless tally integration", () => {
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

  async function sendWithBudget(instruction: anchor.web3.TransactionInstruction): Promise<void> {
    const { blockhash, lastValidBlockHeight } = await provider.connection.getLatestBlockhash("confirmed");
    const transaction = new Transaction({
      feePayer: provider.wallet.publicKey,
      recentBlockhash: blockhash,
    }).add(computeBudget, instruction);
    const signedTransaction = await provider.wallet.signTransaction(transaction);
    const signature = await provider.connection.sendRawTransaction(signedTransaction.serialize(), {
      preflightCommitment: "confirmed",
    });
    await provider.connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
  }

  it("casts a ballot and posts a circuit-verified tally", async () => {
    assert.equal(proof.length, 388, "run the Sunspot proof preparation command");
    assert.equal(publicWitness.length, 236);
    assert.equal(tallyProof.length, 388, "run the tally proof preparation command");
    assert.equal(publicWitness.readUInt32BE(0), 7);
    assert.deepEqual(witnessField(6), fieldBytes(fixture.commitment));

    const verifierAccount = await provider.connection.getAccountInfo(verifierId);
    assert.ok(verifierAccount?.executable, "preload the Sunspot verifier program");
    const tallyVerifierAccount = await provider.connection.getAccountInfo(tallyVerifierId);
    assert.ok(tallyVerifierAccount?.executable, "preload the tally verifier program");

    const rpc = createRpc(
      provider.connection.rpcEndpoint,
      process.env.LIGHT_INDEXER_URL ?? "http://127.0.0.1:8784",
      process.env.LIGHT_PROVER_URL ?? "http://127.0.0.1:3001"
    );
    const addressTree = await rpc.getAddressTreeInfoV2();
    assert.equal(addressTree.tree.toBase58(), "amt2kaJA14v3urZbZvnc5v2np8jqvc4Z8zDep5wbtzx");
    const outputTree = (await rpc.getStateTreeInfos()).find((tree) => tree.treeType === TreeType.StateV2);
    assert.ok(outputTree, "Light V2 state tree is not available");
    assert.ok(outputTree.cpiContext, "Light V2 output tree has no CPI context");

    const authority = provider.wallet.publicKey;
    const electionId = new BN(fixture.electionId);
    const positionId = new BN(fixture.positionId);
    const election = PublicKey.findProgramAddressSync(
      [Buffer.from("election"), authority.toBuffer(), electionId.toArrayLike(Buffer, "le", 8)],
      program.programId
    )[0];
    const position = PublicKey.findProgramAddressSync(
      [Buffer.from("position"), election.toBuffer(), positionId.toArrayLike(Buffer, "le", 8)],
      program.programId
    )[0];
    const transcript = PublicKey.findProgramAddressSync(
      [Buffer.from("transcript"), position.toBuffer()],
      program.programId
    )[0];
    const tally = PublicKey.findProgramAddressSync(
      [Buffer.from("tally"), position.toBuffer()],
      program.programId
    )[0];

    const nullifier = fieldBytes(fixture.nullifier);
    const addressSeed = deriveAddressSeedV2([Buffer.from("nullifier"), position.toBuffer(), nullifier]);
    const ballotAddress = deriveAddressV2(addressSeed, addressTree.tree, program.programId);
    const validity = await rpc.getValidityProofV0([], [
      { address: new BN(ballotAddress.toBytes()), tree: addressTree.tree, queue: addressTree.queue },
    ]);
    assert.ok(validity.compressedProof, "Light prover returned no validity proof");
    assert.equal(validity.rootIndices.length, 1);

    const [cpiSigner] = PublicKey.findProgramAddressSync([Buffer.from("cpi_authority")], program.programId);
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
      verifierId,
      ...remainingAccounts.map((account) => account.pubkey),
    ].filter(
      (key, index, keys) =>
        !key.equals(authority) &&
        !key.equals(SystemProgram.programId) &&
        keys.findIndex((candidate) => candidate.equals(key)) === index
    );
    const recentSlot = await provider.connection.getSlot("confirmed");
    const [createLookupTableIx, lookupTableAddress] = AddressLookupTableProgram.createLookupTable({
      payer: authority,
      authority,
      recentSlot,
    });
    await sendLegacyTransaction(provider, createLookupTableIx);
    await sendLegacyTransaction(
      provider,
      AddressLookupTableProgram.extendLookupTable({
        payer: authority,
        authority,
        lookupTable: lookupTableAddress,
        addresses: lookupAddresses,
      })
    );
    const lookupTableResult = await provider.connection.getAddressLookupTable(lookupTableAddress);
    assert.ok(lookupTableResult.value, "failed to create the vote address lookup table");
    while (
      (await provider.connection.getSlot("confirmed")) <= lookupTableResult.value.state.lastExtendedSlot
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
    const voteArgs = (voteProof: Buffer) =>
      program.methods.castVote(
        voteProof,
        [...nullifier],
        fixture.xs.map((value) => [...fieldBytes(value)]),
        fixture.parityBits,
        validityProof,
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
      return sendVersionedTransaction(provider, [computeBudget, instruction], lookupTableResult.value!);
    };


    const now = await validatorNow();
    const voteStart = new BN(now + 3);
    const voteEnd = new BN(now + 6);
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
        .accountsStrict({ election, authority, systemProgram: SystemProgram.programId })
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
    await sendLegacyTransaction(
      provider,
      await program.methods
        .freezeVoterRoot([...fieldBytes(fixture.root)], new BN(4))
        .accountsStrict({ election, authority })
        .instruction()
    );

    await waitUntilValidator(now + 4);
    const signature = await submitVote(proof);
    const status = await provider.connection.getSignatureStatus(signature);
    assert.ok(status.value?.slot, "cast transaction has no confirmed slot");
    await rpc.confirmTransactionIndexed(status.value.slot);

    // Layer 1: the transcript was re-derived on-chain and matches the tally fixture.
    const transcriptAccount = await program.account.ballotTranscript.fetch(transcript);
    assert.equal(transcriptAccount.ballotCount.toNumber(), tallyFixture.ballotCount);
    assert.deepEqual(Buffer.from(transcriptAccount.transcript), fieldBytes(tallyFixture.transcript));

    await waitUntilValidator(now + 7);
    await sendWithBudget(
      await program.methods
        .postTally(
          tallyFixture.totals.map((value) => new BN(value)),
          tallyProof
        )
        .accountsStrict({
          election,
          position,
          transcript,
          tally,
          authority,
          verifier: tallyVerifierId,
          systemProgram: SystemProgram.programId,
        })
        .instruction()
    );

    const tallyAccount = await program.account.tallyResult.fetch(tally);
    assert.deepEqual(
      tallyAccount.totals.map((value) => value.toNumber()),
      [0, 1, 0, 0]
    );
    assert.deepEqual(Buffer.from(tallyAccount.transcriptHash), fieldBytes(tallyFixture.transcript));
  });
});

