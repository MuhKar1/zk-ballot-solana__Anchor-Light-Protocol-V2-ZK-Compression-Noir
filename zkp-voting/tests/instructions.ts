// On-chain instruction matrix for the hardened voting program.
//
// This suite exercises every instruction's success path and cheap rejection path. It is
// deliberately Light-free: every cast_vote/post_tally case here fails BEFORE the Sunspot
// verifier or the Light CPI, so no compressed-account or proof artifacts are required. The
// happy paths that need those systems live in compressed-ballot.ts (cast_vote) and
// tally.ts (post_tally).
//
// It requires a validator with the app program plus BOTH verifier programs loaded at their
// pinned addresses (see tests/README.md).
import * as anchor from "@coral-xyz/anchor";
import assert from "node:assert/strict";
import BN from "bn.js";
import { PublicKey, SystemProgram } from "@solana/web3.js";
import type { ZkpVoting } from "../target/types/zkp_voting";

const VERIFIER_ID = new PublicKey("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const TALLY_VERIFIER_ID = new PublicKey("AjGDxunAeXevv7AWyhK4jKDsunjbAoZDxzNqGdM2iZWw");

const ONE = [...Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", "hex")];
const TWO = [...Buffer.from("0000000000000000000000000000000000000000000000000000000000000002", "hex")];
const NON_CANONICAL = [...Buffer.alloc(32, 0xff)];
const CANONICAL_ROOT = [...Buffer.from("000000000000000000000000000000000000000000000000000000000000002a", "hex")];
const NULLIFIER = [...Buffer.from("0000000000000000000000000000000000000000000000000000000000000007", "hex")];

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntil(ts: number): Promise<void> {
  while (Math.floor(Date.now() / 1000) < ts) await wait(100);
}

function errorCode(err: unknown): string | undefined {
  const e = err as any;
  return e?.error?.errorCode?.code ?? e?.code ?? e?.error?.code;
}

async function expectErr(promise: Promise<unknown>, code: string, message?: string): Promise<void> {
  try {
    await promise;
  } catch (err) {
    const matches =
      errorCode(err) === code || ((err as any)?.logs ?? []).some((l: string) => l.includes(code));
    if (matches) return;
    const got = errorCode(err) ?? (err as any)?.message ?? String(err);
    throw new Error(`${message ?? `expected ${code}`} (got ${got})`);
  }
  throw new Error(`${message ?? `expected ${code}`} (transaction unexpectedly succeeded)`);
}


describe("instruction matrix", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.ZkpVoting as anchor.Program<ZkpVoting>;
  const authority = provider.wallet.publicKey;

  let electionCounter = 0;

  function pdas(electionId: BN, positionId: BN) {
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
    return { election, position, transcript, tally };
  }

  async function initializeElection(
    electionId: BN,
    opts: { pkX?: number[]; pkY?: number[]; voteStart?: BN; voteEnd?: BN } = {}
  ) {
    const { election } = pdas(electionId, new BN(1));
    const now = Math.floor(Date.now() / 1000);
    const instruction = await program.methods
      .initializeElection(
        electionId,
        opts.pkX ?? ONE,
        opts.pkY ?? TWO,
        opts.voteStart ?? new BN(now + 60),
        opts.voteEnd ?? new BN(now + 3600)
      )
      .accountsStrict({ election, authority, systemProgram: SystemProgram.programId })
      .instruction();
    return { instruction, election };
  }

  async function initializePosition(electionId: BN, positionId: BN, maxCandidates: number) {
    const { election, position, transcript } = pdas(electionId, positionId);
    const instruction = await program.methods
      .initializePosition(positionId, maxCandidates)
      .accountsStrict({
        election,
        position,
        transcript,
        authority,
        systemProgram: SystemProgram.programId,
      })
      .instruction();
    return { instruction, election, position, transcript };
  }

  async function freeze(electionId: BN, root = CANONICAL_ROOT, leafCount = 4) {
    const { election } = pdas(electionId, new BN(1));
    const instruction = await program.methods
      .freezeVoterRoot([...root], new BN(leafCount))
      .accountsStrict({ election, authority })
      .instruction();
    return { instruction, election };
  }

  async function castVote(
    electionId: BN,
    positionId: BN,
    opts: { nullifier?: number[]; proof?: Buffer; verifier?: PublicKey } = {}
  ) {
    const { election, position, transcript } = pdas(electionId, positionId);
    const instruction = await program.methods
      .castVote(
        opts.proof ?? Buffer.alloc(0),
        opts.nullifier ?? NULLIFIER,
        [[...ONE], [...ONE], [...ONE], [...ONE], [...ONE], [...ONE], [...ONE], [...ONE]],
        0,
        { 0: null } as any,
        { addressMerkleTreePubkeyIndex: 0, addressQueuePubkeyIndex: 1, rootIndex: 0 },
        0
      )
      .accountsStrict({
        payer: authority,
        election,
        position,
        transcript,
        verifier: opts.verifier ?? VERIFIER_ID,
      })
      .instruction();
    return { instruction, election, position, transcript };
  }

  async function postTally(
    electionId: BN,
    positionId: BN,
    opts: { totals?: BN[]; proof?: Buffer; verifier?: PublicKey } = {}
  ) {
    const { election, position, transcript, tally } = pdas(electionId, positionId);
    const instruction = await program.methods
      .postTally(
        opts.totals ?? [new BN(0), new BN(0), new BN(0), new BN(0)],
        opts.proof ?? Buffer.alloc(0)
      )
      .accountsStrict({
        election,
        position,
        transcript,
        tally,
        authority,
        verifier: opts.verifier ?? TALLY_VERIFIER_ID,
        systemProgram: SystemProgram.programId,
      })
      .instruction();
    return { instruction, election, position, transcript, tally };
  }

  async function send(instruction: anchor.web3.TransactionInstruction): Promise<void> {
    const { blockhash, lastValidBlockHeight } = await provider.connection.getLatestBlockhash("confirmed");
    const transaction = new anchor.web3.Transaction({
      feePayer: authority,
      recentBlockhash: blockhash,
    }).add(instruction);
    const signedTransaction = await provider.wallet.signTransaction(transaction);
    const signature = await provider.connection.sendRawTransaction(signedTransaction.serialize(), {
      preflightCommitment: "confirmed",
    });
    await provider.connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
  }

  const CLOCK = new PublicKey("SysvarC1ock11111111111111111111111111111111");

  async function validatorNow(): Promise<number> {
    const info = await provider.connection.getAccountInfo(CLOCK);
    return Number(info!.data.readBigInt64LE(32));
  }

  async function waitUntilValidator(ts: number): Promise<void> {
    while ((await validatorNow()) < ts) await wait(100);
  }

  describe("initialize_election", () => {
    it("accepts a canonical key and valid window", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await send((await initializeElection(id)).instruction);
      const { election } = pdas(id, new BN(1));
      const account = await program.account.electionConfig.fetch(election);
      assert.ok(account.authority.equals(authority));
      assert.ok(account.electionId.eq(id));
    });

    it("rejects vote_start >= vote_end", async () => {
      const id = new BN(Date.now() + electionCounter++);
      const now = Math.floor(Date.now() / 1000);
      await expectErr(
        send((await initializeElection(id, { voteStart: new BN(now + 10), voteEnd: new BN(now + 10) })).instruction),
        "BadWindow"
      );
    });

    it("rejects a non-canonical pk_x", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await expectErr(send((await initializeElection(id, { pkX: NON_CANONICAL })).instruction), "NonCanonicalField");
    });
  });

  describe("initialize_position", () => {
    it("accepts a valid position and creates the transcript", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await send((await initializeElection(id)).instruction);
      await send((await initializePosition(id, new BN(1), 4)).instruction);
      const { transcript } = pdas(id, new BN(1));
      const t = await program.account.ballotTranscript.fetch(transcript);
      assert.equal(t.ballotCount.toNumber(), 0);
      assert.deepEqual(Array.from(t.transcript), [...Array(31).fill(0), 5]);
    });

    it("rejects candidate count 0", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await send((await initializeElection(id)).instruction);
      await expectErr(send((await initializePosition(id, new BN(1), 0)).instruction), "CandidateOutOfBounds");
    });

    it("rejects candidate count above K_MAX", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await send((await initializeElection(id)).instruction);
      await expectErr(send((await initializePosition(id, new BN(1), 5)).instruction), "CandidateOutOfBounds");
    });

    it("rejects a frozen election", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await send((await initializeElection(id)).instruction);
      await send((await freeze(id)).instruction);
      await expectErr(send((await initializePosition(id, new BN(1), 4)).instruction), "AlreadyFrozen");
    });
  });

  describe("freeze_voter_root", () => {
    it("accepts a canonical root before the window opens", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await send((await initializeElection(id)).instruction);
      await send((await initializePosition(id, new BN(1), 4)).instruction);
      await send((await freeze(id)).instruction);
      const { election } = pdas(id, new BN(1));
      const account = await program.account.electionConfig.fetch(election);
      assert.ok(account.isFrozen);
    });

    it("rejects a non-canonical root", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await send((await initializeElection(id)).instruction);
      await expectErr(send((await freeze(id, NON_CANONICAL)).instruction), "NonCanonicalField");
    });

    it("rejects a zero leaf count", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await send((await initializeElection(id)).instruction);
      await expectErr(send((await freeze(id, CANONICAL_ROOT, 0)).instruction), "InvalidLeafCount");
    });

    it("rejects a leaf count above capacity", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await send((await initializeElection(id)).instruction);
      await expectErr(
        send((await freeze(id, CANONICAL_ROOT, (1 << 24) + 1)).instruction),
        "InvalidLeafCount"
      );
    });

    it("rejects freezing twice", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await send((await initializeElection(id)).instruction);
      await send((await freeze(id)).instruction);
      await expectErr(send((await freeze(id)).instruction), "AlreadyFrozen");
    });
  });


  describe("cast_vote", () => {
    it("rejects an unfrozen election", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await send((await initializeElection(id)).instruction);
      await send((await initializePosition(id, new BN(1), 4)).instruction);
      await expectErr(send((await castVote(id, new BN(1))).instruction), "NotFrozen");
    });

    it("rejects a vote before the window opens", async () => {
      const id = new BN(Date.now() + electionCounter++);
      const now = Math.floor(Date.now() / 1000);
      await send((await initializeElection(id, { voteStart: new BN(now + 30), voteEnd: new BN(now + 3600) })).instruction);
      await send((await initializePosition(id, new BN(1), 4)).instruction);
      await send((await freeze(id)).instruction);
      await expectErr(send((await castVote(id, new BN(1))).instruction), "VotingClosed");
    });

    it("rejects a non-pinned verifier", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await send((await initializeElection(id)).instruction);
      await send((await initializePosition(id, new BN(1), 4)).instruction);
      await expectErr(
        send((await castVote(id, new BN(1), { verifier: SystemProgram.programId })).instruction),
        "InvalidVerifier"
      );
    });

    it("rejects a non-canonical nullifier, an empty proof, and an oversized proof", async () => {
      const id = new BN(Date.now() + electionCounter++);
      const now = await validatorNow();
      await send((await initializeElection(id, { voteStart: new BN(now + 6), voteEnd: new BN(now + 3600) })).instruction);
      await send((await initializePosition(id, new BN(1), 4)).instruction);
      await send((await freeze(id)).instruction);
      await waitUntilValidator(now + 7);

      await expectErr(send((await castVote(id, new BN(1), { nullifier: NON_CANONICAL })).instruction), "NonCanonicalField");
      await expectErr(send((await castVote(id, new BN(1), { proof: Buffer.alloc(0) })).instruction), "BadProofLength");
      await expectErr(
        send((await castVote(id, new BN(1), { proof: Buffer.alloc(513) })).instruction),
        "BadProofLength"
      );
    });
  });

  describe("post_tally", () => {
    it("rejects an unfrozen election", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await send((await initializeElection(id)).instruction);
      await send((await initializePosition(id, new BN(1), 4)).instruction);
      await expectErr(send((await postTally(id, new BN(1))).instruction), "NotFrozen");
    });

    it("rejects before the window has ended", async () => {
      const id = new BN(Date.now() + electionCounter++);
      const now = Math.floor(Date.now() / 1000);
      await send((await initializeElection(id, { voteStart: new BN(now + 30), voteEnd: new BN(now + 3600) })).instruction);
      await send((await initializePosition(id, new BN(1), 4)).instruction);
      await send((await freeze(id)).instruction);
      await expectErr(send((await postTally(id, new BN(1))).instruction), "VotingStillOpen");
    });

    it("rejects a non-pinned tally verifier", async () => {
      const id = new BN(Date.now() + electionCounter++);
      await send((await initializeElection(id)).instruction);
      await send((await initializePosition(id, new BN(1), 4)).instruction);
      await expectErr(
        send((await postTally(id, new BN(1), { verifier: SystemProgram.programId })).instruction),
        "InvalidVerifier"
      );
    });

    it("rejects invalid totals, an empty proof, and a garbage proof", async () => {
      const id = new BN(Date.now() + electionCounter++);
      const now = await validatorNow();
      await send((await initializeElection(id, { voteStart: new BN(now + 6), voteEnd: new BN(now + 9) })).instruction);
      await send((await initializePosition(id, new BN(1), 2)).instruction);
      await send((await freeze(id)).instruction);
      await waitUntilValidator(now + 10);

      await expectErr(
        send((await postTally(id, new BN(1), { totals: [new BN(0), new BN(0), new BN(1), new BN(0)] })).instruction),
        "InvalidTally"
      );
      await expectErr(
        send((await postTally(id, new BN(1), { totals: [new BN(1), new BN(0), new BN(0), new BN(0)] })).instruction),
        "InvalidTally"
      );
      await expectErr(
        send((await postTally(id, new BN(1), { proof: Buffer.alloc(0) })).instruction),
        "BadTallyProofLength"
      );
      await assert.rejects(
        send((await postTally(id, new BN(1), { proof: Buffer.alloc(256) })).instruction),
        "a garbage tally proof must be rejected"
      );
    });
  });
});

