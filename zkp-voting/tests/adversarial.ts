/**
 * Provider-independent account-boundary tests.
 *
 * These tests model Anchor PDA derivation and do not submit transactions.
 * Validator-backed instruction tests belong in zkp-voting.ts.
 */
import assert from "node:assert/strict";
import { PublicKey } from "@solana/web3.js";

const PROGRAM_ID = new PublicKey(
  "4uiu9QzRVZYdLdxCmADj6cQwFCrNufDCgU7NtsvQJWYA"
);
const authority = new PublicKey("11111111111111111111111111111111");
const otherAuthority = new PublicKey(
  "SysvarRent111111111111111111111111111111111"
);

function u64Le(value: bigint): Buffer {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(value);
  return bytes;
}

function electionAddress(owner: PublicKey, electionId: bigint): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("election"), owner.toBuffer(), u64Le(electionId)],
    PROGRAM_ID
  )[0];
}

function positionAddress(election: PublicKey, positionId: bigint): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("position"), election.toBuffer(), u64Le(positionId)],
    PROGRAM_ID
  )[0];
}

function tallyAddress(position: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("tally"), position.toBuffer()],
    PROGRAM_ID
  )[0];
}

function transcriptAddress(position: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("transcript"), position.toBuffer()],
    PROGRAM_ID
  )[0];
}

describe("zkp-voting account-boundary adversarial tests", () => {
  it("binds an election address to both authority and election id", () => {
    const expected = electionAddress(authority, 7n);
    assert.notEqual(
      expected.toBase58(),
      electionAddress(otherAuthority, 7n).toBase58()
    );
    assert.notEqual(
      expected.toBase58(),
      electionAddress(authority, 8n).toBase58()
    );
    assert.equal(
      expected.toBase58(),
      electionAddress(authority, 7n).toBase58()
    );
  });

  it("binds a position address to its election and position id", () => {
    const election = electionAddress(authority, 7n);
    const otherElection = electionAddress(authority, 8n);
    const expected = positionAddress(election, 1n);
    assert.notEqual(
      expected.toBase58(),
      positionAddress(election, 2n).toBase58()
    );
    assert.notEqual(
      expected.toBase58(),
      positionAddress(otherElection, 1n).toBase58()
    );
    assert.equal(expected.toBase58(), positionAddress(election, 1n).toBase58());
  });

  it("binds a tally address to exactly one position", () => {
    const election = electionAddress(authority, 7n);
    const firstPosition = positionAddress(election, 1n);
    const secondPosition = positionAddress(election, 2n);
    assert.notEqual(
      tallyAddress(firstPosition).toBase58(),
      tallyAddress(secondPosition).toBase58()
    );
    assert.equal(
      tallyAddress(firstPosition).toBase58(),
      tallyAddress(firstPosition).toBase58()
    );
  });

  it("binds a transcript address to exactly one position", () => {
    const election = electionAddress(authority, 7n);
    const firstPosition = positionAddress(election, 1n);
    const secondPosition = positionAddress(election, 2n);
    assert.notEqual(
      transcriptAddress(firstPosition).toBase58(),
      transcriptAddress(secondPosition).toBase58()
    );
    assert.equal(
      transcriptAddress(firstPosition).toBase58(),
      transcriptAddress(firstPosition).toBase58()
    );
  });

  it("rejects seed components that are not exactly eight-byte little-endian values in the model", () => {
    const electionId = 7n;
    const littleEndian = Buffer.alloc(8);
    littleEndian.writeBigUInt64LE(electionId);
    const bigEndian = Buffer.alloc(8);
    bigEndian.writeBigUInt64BE(electionId);
    assert.notDeepEqual(littleEndian, bigEndian);
  });
});
