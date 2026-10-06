/** Validator-backed tests for election setup and administrative instructions. */
import * as anchor from "@coral-xyz/anchor";
import assert from "node:assert/strict";
import BN from "bn.js";
import { Keypair, SystemProgram } from "@solana/web3.js";
import type { ZkpVoting } from "../target/types/zkp_voting";

describe("zkp-voting Anchor integration", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.ZkpVoting as anchor.Program<ZkpVoting>;

  it("initializes elections and positions, freezes one root, and rejects invalid transitions", async () => {
    const authority = provider.wallet.publicKey;
    const electionId = new BN(Date.now());
    const positionId = new BN(1);
    const now = Math.floor(Date.now() / 1000);
    const voteStart = new BN(now + 3600);
    const voteEnd = new BN(now + 7200);
    const zeroField = Array(32).fill(0);
    const election = anchor.web3.PublicKey.findProgramAddressSync(
      [
        Buffer.from("election"),
        authority.toBuffer(),
        electionId.toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    )[0];
    const position = anchor.web3.PublicKey.findProgramAddressSync(
      [
        Buffer.from("position"),
        election.toBuffer(),
        positionId.toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    )[0];
    const tally = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("tally"), position.toBuffer()],
      program.programId
    )[0];
    const transcript = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("transcript"), position.toBuffer()],
      program.programId
    )[0];

    await assert.rejects(
      program.methods
        .initializeElection(
          electionId,
          zeroField,
          zeroField,
          voteEnd,
          voteStart
        )
        .accountsStrict({
          election,
          authority,
          systemProgram: SystemProgram.programId,
        })
        .rpc()
    );

    await program.methods
      .initializeElection(electionId, zeroField, zeroField, voteStart, voteEnd)
      .accountsStrict({
        election,
        authority,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const initializedElection = await program.account.electionConfig.fetch(
      election
    );
    assert.equal(
      initializedElection.authority.toBase58(),
      authority.toBase58()
    );
    assert.equal(
      initializedElection.electionId.toString(),
      electionId.toString()
    );
    assert.equal(initializedElection.isFrozen, false);

    await assert.rejects(
      program.methods
        .initializePosition(positionId, 0)
        .accountsStrict({
          election,
          position,
          transcript,
          authority,
          systemProgram: SystemProgram.programId,
        })
        .rpc()
    );

    await program.methods
      .initializePosition(positionId, 3)
      .accountsStrict({
        election,
        position,
        transcript,
        authority,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    const initializedPosition = await program.account.positionConfig.fetch(
      position
    );
    assert.equal(initializedPosition.maxCandidates, 3);

    await assert.rejects(
      program.methods
        .freezeVoterRoot(zeroField, new BN(0))
        .accountsStrict({ election, authority })
        .rpc()
    );

    const unauthorized = Keypair.generate();
    await assert.rejects(
      program.methods
        .freezeVoterRoot(zeroField, new BN(1))
        .accountsStrict({ election, authority: unauthorized.publicKey })
        .signers([unauthorized])
        .rpc()
    );

    await program.methods
      .freezeVoterRoot(zeroField, new BN(1))
      .accountsStrict({ election, authority })
      .rpc();

    const frozenElection = await program.account.electionConfig.fetch(election);
    assert.equal(frozenElection.isFrozen, true);
    assert.equal(frozenElection.leafCount.toString(), "1");

    await assert.rejects(
      program.methods
        .freezeVoterRoot(zeroField, new BN(1))
        .accountsStrict({ election, authority })
        .rpc()
    );

    // post_tally rejections are covered in instructions.ts (which runs against a validator
    // preloaded with the Sunspot tally verifier).
  });
});
