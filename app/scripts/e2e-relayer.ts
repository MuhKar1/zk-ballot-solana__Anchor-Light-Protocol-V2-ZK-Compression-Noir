// Headless end-to-end test for the RELAYER vote path + admin election listing.
//
// Requires (all already running for the local demo):
//   - Next dev server on http://127.0.0.1:3000 (serves /api/prove and /api/cast-vote)
//   - Light test-validator on :8899, indexer on :8784, prover on :3001
//
// Run (from app/):
//   npm run dev &
//   NEXT_PUBLIC_PROVER=node npx tsx scripts/e2e-relayer.mts
//
// It proves the key privacy property: the cast_vote transaction is signed and
// paid by the RELAYER, and the voter/admin public key never appears on-chain.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Keypair } from "@solana/web3.js";
import BN from "bn.js";

import { getProgram } from "@/lib/solana/program";
import { getConnection, programId } from "@/lib/solana/connection";
import { electionPda, positionPda, transcriptPda } from "@/lib/solana/pda";
import { walletFromSecretKey } from "@/lib/solana/wallet";
import {
  fetchAdminElections,
  freezeVoterRoot,
  generateTallyKey,
  initializeElection,
  initializePosition,
  postTally,
} from "@/lib/solana/admin";
import {
  buildBallotCiphertext,
  buildTree,
  bytesToBigInt,
  deriveSecret,
  fieldBytes,
  hex,
  leafOf,
  nullifierOf,
  poseidon2,
  randomField,
  rootFromPath,
} from "@/lib/crypto";
import { prover, type VoteWitness } from "@/lib/proving";
import { castVoteRelayed } from "@/lib/solana/relayVote";
import { fetchBallotCasts } from "@/lib/solana/events";
import { buildTallyWitness } from "@/lib/tally";

// The relayer keypair is configured server-side in .env.local. Its public key is
// the one we airdropped 2 SOL to. We hardcode it here only to *assert* the fee payer.
const RELAYER_PUBKEY = "GMzkxAkajnwp21A9aaMWYbv3ygZQJRv6Xoo2SYKWnZkt";

// NodeProver + castVoteRelayed use relative /api/* fetches; resolve them to the dev server.
const realFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
  if (typeof input === "string" && input.startsWith("/")) {
    input = `http://127.0.0.1:3000${input}`;
  }
  return realFetch(input, init);
}) as typeof fetch;

const log = (...a: unknown[]) => console.log("[e2e]", ...a);

function adminKeypair(): Keypair {
  const p = join(homedir(), ".config", "solana", "id.json");
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(p, "utf8"))));
}

async function main() {
  const connection = getConnection();
  const admin = adminKeypair();
  const adminWallet = walletFromSecretKey(admin.secretKey);
  const program = getProgram(adminWallet);

  log("admin authority:", admin.publicKey.toBase58());
  log("admin balance:", (await connection.getBalance(admin.publicKey)) / 1e9, "SOL");

  // 1) Create an election: single position, 2 aspirants.
  // NOTE: use the validator's clock (block time) — it runs ahead of the wall clock.
  const validatorNow =
    (await connection.getBlockTime(await connection.getSlot())) ?? Math.floor(Date.now() / 1000);
  const tallyKey = generateTallyKey();
  const electionId = new BN(Date.now());
  const startTs = validatorNow + 12; // the voter root must be frozen before voting starts
  const endTs = validatorNow + 45; // short window so we can also exercise post_tally

  let sig = await initializeElection(program, adminWallet, {
    electionId,
    pkX: tallyKey.pkX,
    pkY: tallyKey.pkY,
    voteStartTs: new BN(startTs),
    voteEndTs: new BN(endTs),
  });
  log("initializeElection:", sig);

  const positionId = new BN(1);
  const maxCandidates = 2;
  sig = await initializePosition(program, adminWallet, { electionId, positionId, maxCandidates });
  log("initializePosition:", sig);

  // 2) Register 3 voters and freeze the Merkle tree.
  const voters = [
    { id: "Alice", password: "passA" },
    { id: "Bob", password: "passB" },
    { id: "Carol", password: "passC" },
  ];
  const secrets: bigint[] = [];
  for (const v of voters) secrets.push(await deriveSecret(v.id, v.password));
  const leaves = secrets.map(leafOf);
  const tree = buildTree(leaves);
  const root = tree.root;

  sig = await freezeVoterRoot(program, adminWallet, { electionId, root, leafCount: leaves.length });
  log("freezeVoterRoot:", sig, "root:", hex(root));

  // 3) Re-derive PDAs + ElGamal public info (the admin's published manifest).
  const [election] = electionPda(admin.publicKey, electionId, programId);
  const [position] = positionPda(election, positionId, programId);
  const [transcript] = transcriptPda(position, programId);
  const pk = { x: tallyKey.pkX, y: tallyKey.pkY };
  const pkHash = poseidon2([tallyKey.pkX, tallyKey.pkY]);

  // 4) Voter "Alice" casts through the RELAYER route (no voter wallet involved).
  const voterIndex = 0;
  const s = secrets[voterIndex];
  const leaf = leafOf(s);
  const path = tree.path(voterIndex);
  if (rootFromPath(leaf, path.bits, path.sibs) !== root) {
    throw new Error("merkle path check failed");
  }

  const choice = 1; // picks the 2nd aspirant
  const choiceArr = [false, true, false, false];
  const rSeed = randomField();
  const ct = buildBallotCiphertext(pk, rSeed, choiceArr);
  const nullifier = nullifierOf(s, BigInt(electionId.toString()), BigInt(positionId.toString()));

  const witness: VoteWitness = {
    merkle_root_pub: root.toString(),
    nullifier: nullifier.toString(),
    election_id: electionId.toString(),
    position_id: positionId.toString(),
    max_candidates: String(maxCandidates),
    pk_hash: pkHash.toString(),
    ballot_commitment: ct.commitment.toString(),
    s: s.toString(),
    bits: path.bits.map(Boolean),
    sibs: path.sibs.map((x) => x.toString()),
    choice: choiceArr,
    r_seed: rSeed.toString(),
    pk_x: tallyKey.pkX.toString(),
    pk_y: tallyKey.pkY.toString(),
  };

  log("proving vote via /api/prove (nargo + sunspot)…");
  const proof = await prover.proveVote(witness);
  log("proof bytes:", proof.length);

  log("waiting for the voting window to open…");
  let clockNow = validatorNow;
  while (clockNow < startTs) {
    await new Promise((r) => setTimeout(r, 500));
    clockNow = (await connection.getBlockTime(await connection.getSlot())) ?? clockNow;
  }

  log("submitting via relayer /api/cast-vote…");
  const txSig = await castVoteRelayed({
    election: election.toBase58(),
    position: position.toBase58(),
    transcript: transcript.toBase58(),
    proof,
    nullifier: Uint8Array.from(fieldBytes(nullifier)),
    xs: ct.xs.map((x) => Uint8Array.from(fieldBytes(x))),
    parityBits: ct.parityBits,
  });
  log("cast_vote tx:", txSig);

  // 5) Assert the relayer paid/signed, and the voter/admin pubkey is absent.
  const tx = await connection.getTransaction(txSig, {
    maxSupportedTransactionVersion: 0,
    commitment: "confirmed",
  });
  if (!tx) throw new Error("could not fetch the cast_vote transaction");

  const feePayer = tx.transaction.message.staticAccountKeys[0].toBase58();
  log("cast_vote fee payer:", feePayer);
  if (feePayer !== RELAYER_PUBKEY) {
    throw new Error(`expected relayer fee payer ${RELAYER_PUBKEY}, got ${feePayer}`);
  }

  const accountKeys = tx.transaction.message.staticAccountKeys.map((k) => k.toBase58());
  if (accountKeys.includes(admin.publicKey.toBase58())) {
    throw new Error("voter/admin pubkey leaked into the cast_vote transaction");
  }
  log("voter/admin pubkey absent from cast_vote transaction ✔");

  // 6) Assert the ballot actually landed on-chain. The Light validator's address
  // index can lag a beat after confirmation, so poll briefly.
  let casts = await fetchBallotCasts(connection, position);
  for (let attempt = 0; attempt < 10 && !casts.some((c) => c.nullifier === nullifier); attempt++) {
    await new Promise((r) => setTimeout(r, 1000));
    casts = await fetchBallotCasts(connection, position);
  }
  log("ballot casts for position:", casts.length);
  if (!casts.some((c) => c.nullifier === nullifier)) {
    throw new Error("cast ballot not found on-chain");
  }
  log("on-chain ballot nullifier matches ✔");

  // 7) Admin listing must surface the just-created election with status "ongoing".
  const list = await fetchAdminElections(program, admin.publicKey);
  const found = list.find((e) => e.electionId.eq(electionId));
  if (!found) throw new Error("election not found in admin listing");
  log(
    "admin listing:",
    "electionId",
    found.electionId.toString(),
    "state",
    found.state,
    "frozen",
    found.isFrozen,
    "voters",
    found.leafCount
  );
  if (found.state !== "ongoing") throw new Error(`expected ongoing, got ${found.state}`);
  if (!found.isFrozen) throw new Error("expected frozen voter list");

  // 8) Close the loop: tally the position and post the result.
  const tallyWitness = buildTallyWitness({
    sk: tallyKey.sk,
    pkX: tallyKey.pkX,
    pkY: tallyKey.pkY,
    maxCandidates,
    ballots: casts.map((c) => ({ nullifier: c.nullifier, xs: c.xs, parity: c.parityBits })),
  });

  const transcriptAccount = await program.account.ballotTranscript.fetch(transcript);
  if (
    hex(bytesToBigInt(transcriptAccount.transcript as number[])) !== hex(BigInt(tallyWitness.transcript))
  ) {
    throw new Error("transcript mismatch — ballots are out of order or missing");
  }

  const tallyProof = await prover.proveTally(tallyWitness);
  const totals = tallyWitness.totals.map((v) => parseInt(v, 10));

  // post_tally requires the voting window to have ended.
  log("waiting for the voting window to close…");
  let closeClock = (await connection.getBlockTime(await connection.getSlot())) ?? validatorNow;
  while (closeClock <= endTs) {
    await new Promise((r) => setTimeout(r, 500));
    closeClock = (await connection.getBlockTime(await connection.getSlot())) ?? closeClock;
  }

  const tallySig = await postTally(program, adminWallet, {
    electionId,
    positionId,
    totals,
    proof: tallyProof,
  });
  log("postTally:", tallySig, "totals:", totals);
  if (totals[1] !== 1) throw new Error(`unexpected totals (expected aspirant #2 = 1): ${totals}`);

  log("ALL CHECKS PASSED ✔");
}

main().catch((e) => {
  console.error("[e2e] FAILED:", e);
  process.exit(1);
});

