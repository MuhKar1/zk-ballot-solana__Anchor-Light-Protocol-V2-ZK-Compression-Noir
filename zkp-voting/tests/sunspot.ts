/** Local integration checks for the Sunspot verifier program. */
import * as anchor from "@coral-xyz/anchor";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  ComputeBudgetProgram,
  PublicKey,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";

const verifierId = new PublicKey(
  "9jjgdh8kXLqZEkAGYjXTXsXGQeGALJ6YYKn5Gz3KXgYj"
);
const artifactDirectory = resolve(process.cwd(), "../circuits/target");
const proof = readFileSync(resolve(artifactDirectory, "voting_circuit.proof"));
const publicWitness = readFileSync(
  resolve(artifactDirectory, "voting_circuit.pw")
);
const computeBudget = ComputeBudgetProgram.setComputeUnitLimit({
  units: 1_400_000,
});

function verifierTransaction(witness: Buffer): Transaction {
  return new Transaction().add(
    computeBudget,
    new TransactionInstruction({
      programId: verifierId,
      keys: [],
      data: Buffer.concat([proof, witness]),
    })
  );
}

describe("Sunspot verifier integration", () => {
  const provider = anchor.AnchorProvider.env();

  it("accepts a valid proof and rejects a modified public witness", async () => {
    assert.equal(proof.length, 388);
    assert.equal(publicWitness.length, 236);

    await provider.sendAndConfirm(verifierTransaction(publicWitness), []);

    const modifiedWitness = Buffer.from(publicWitness);
    modifiedWitness[modifiedWitness.length - 1] ^= 1;
    await assert.rejects(
      provider.sendAndConfirm(verifierTransaction(modifiedWitness), [])
    );
  });
});
