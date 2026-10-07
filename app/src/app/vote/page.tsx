"use client";

import { useState } from "react";
import Link from "next/link";
import BN from "bn.js";
import { PublicKey } from "@solana/web3.js";
import { useSolanaWallet } from "@/components/providers";
import { Stepper } from "@/components/stepper";
import { friendlyError } from "@/lib/errors";
import {
  buildBallotCiphertext,
  buildTree,
  bytesToBigInt,
  deriveSecret,
  fieldBytes,
  fieldFromHex,
  hex,
  leafOf,
  nullifierOf,
  randomField,
  rootFromPath,
} from "@/lib/crypto";
import { parseManifest, type ElectionManifest } from "@/lib/manifest";
import { getReadonlyProgram } from "@/lib/solana/program";
import { programId } from "@/lib/solana/connection";
import { electionPda, positionPda, transcriptPda } from "@/lib/solana/pda";
import { castVoteRelayed } from "@/lib/solana/relayVote";
import { prover, type VoteWitness } from "@/lib/proving";

const STEPS = ["Load & connect", "Identify", "Choose", "Review", "Done"];

interface Eligibility {
  index: number;
  bits: number[];
  sibs: bigint[];
}

interface CastResult {
  title: string;
  candidate: string;
  txSig: string;
  nullifier: bigint;
}

const toDec = (x: bigint) => x.toString();

export default function VotePage() {
  const { wallet, hasPhantom, connectPhantomWallet, connectKey, connecting, balance, error } =
    useSolanaWallet();

  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [txSig, setTxSig] = useState<string | null>(null);
  const [stage, setStage] = useState("");

  const [manifestText, setManifestText] = useState("");
  const [manifest, setManifest] = useState<ElectionManifest | null>(null);
  const [secretKeyText, setSecretKeyText] = useState("");

  const [name, setName] = useState("");
  const [voterId, setVoterId] = useState("");
  const [password, setPassword] = useState("");
  const [eligibility, setEligibility] = useState<Eligibility | null>(null);

  const [selections, setSelections] = useState<(number | null)[]>([]);
  const [results, setResults] = useState<CastResult[]>([]);

  const program = getReadonlyProgram();

  async function loadAndVerify() {
    setBusy(true);
    setActionError(null);
    try {
      const m = parseManifest(manifestText);

      // Cross-check the manifest root against the on-chain frozen root.
      const authority = new PublicKey(m.authority);
      const [election] = electionPda(authority, new BN(m.electionId), programId);
      const e = await program.account.electionConfig.fetch(election);
      if (!e.isFrozen) throw new Error("voting isn't open yet — the voter list hasn't been locked");
      if (hex(bytesToBigInt(e.frozenRoot as number[])) !== m.root) {
        throw new Error("the shared voter list doesn't match the locked list on-chain");
      }

      setManifest(m);
      setSelections(m.positions.map(() => null));
      setStep(1);
    } catch (e) {
      setActionError(friendlyError(e));
    } finally {
      setBusy(false);
    }
  }

  async function identify() {
    if (!manifest) return;
    setBusy(true);
    setActionError(null);
    try {
      const s = await deriveSecret(voterId, password);
      const leaf = leafOf(s);
      const index = manifest.leaves.findIndex((h) => h === hex(leaf));
      if (index < 0) throw new Error("not eligible — id/password does not match a registered voter");

      const leaves = manifest.leaves.map(fieldFromHex);
      const tree = buildTree(leaves);
      const path = tree.path(index);
      if (rootFromPath(leaf, path.bits, path.sibs) !== fieldFromHex(manifest.root)) {
        throw new Error("internal error: couldn't verify your spot on the voter list");
      }

      setEligibility({ index, bits: path.bits, sibs: path.sibs });
      setStep(2);
    } catch (e) {
      setActionError(friendlyError(e));
    } finally {
      setBusy(false);
    }
  }

  function allChosen(): boolean {
    if (!manifest) return false;
    return manifest.positions.every((pos, i) => {
      const s = selections[i];
      return s !== null && s !== undefined && s >= 0 && s < pos.candidates.length;
    });
  }

  async function castAll() {
    if (!manifest || !eligibility || !allChosen()) return;
    setBusy(true);
    setActionError(null);
    setTxSig(null);
    setResults([]);
    try {
      const s = await deriveSecret(voterId, password);
      const authority = new PublicKey(manifest.authority);
      const [election] = electionPda(authority, new BN(manifest.electionId), programId);
      const pk = { x: fieldFromHex(manifest.pkX), y: fieldFromHex(manifest.pkY) };
      const cast: CastResult[] = [];

      for (let i = 0; i < manifest.positions.length; i++) {
        const pos = manifest.positions[i];
        const choice = selections[i];
        if (choice === null || choice === undefined) continue;

        setStage(`Position ${i + 1}/${manifest.positions.length}: building ballot (${pos.title})`);
        const choiceArr = [false, false, false, false];
        choiceArr[choice] = true;
        const rSeed = randomField();
        const ct = buildBallotCiphertext(pk, rSeed, choiceArr);
        const nullifier = nullifierOf(s, BigInt(manifest.electionId), BigInt(pos.positionId));

        setStage(`Position ${i + 1}/${manifest.positions.length}: generating proof (${pos.title})`);
        const witness: VoteWitness = {
          merkle_root_pub: toDec(fieldFromHex(manifest.root)),
          nullifier: toDec(nullifier),
          election_id: manifest.electionId,
          position_id: pos.positionId,
          max_candidates: String(pos.maxCandidates),
          pk_hash: toDec(fieldFromHex(manifest.pkHash)),
          ballot_commitment: toDec(ct.commitment),
          s: toDec(s),
          bits: eligibility.bits.map(Boolean),
          sibs: eligibility.sibs.map(toDec),
          choice: choiceArr,
          r_seed: toDec(rSeed),
          pk_x: toDec(fieldFromHex(manifest.pkX)),
          pk_y: toDec(fieldFromHex(manifest.pkY)),
        };
        const proof = await prover.proveVote(witness);

        setStage(`Position ${i + 1}/${manifest.positions.length}: submitting (${pos.title})`);
        const [position] = positionPda(election, new BN(pos.positionId), programId);
        const [transcript] = transcriptPda(position, programId);

        const sig = await castVoteRelayed({
          election: election.toBase58(),
          position: position.toBase58(),
          transcript: transcript.toBase58(),
          proof,
          nullifier: Uint8Array.from(fieldBytes(nullifier)),
          xs: ct.xs.map((x) => Uint8Array.from(fieldBytes(x))),
          parityBits: ct.parityBits,
        });

        cast.push({ title: pos.title, candidate: pos.candidates[choice], txSig: sig, nullifier });
        setTxSig(sig);
      }

      setResults(cast);
      setStep(4);
    } catch (e) {
      setActionError(friendlyError(e));
    } finally {
      setBusy(false);
      setStage("");
    }
  }
  return (
    <div className="container">
      <Stepper steps={STEPS} current={step} />

      {step === 0 && (
        <div className="card">
          <h2>Load election</h2>
          <p className="hint">
            Paste the election manifest the admin shared with you. A shared relayer signs and pays
            for your vote, so you need no SOL — and your wallet address never appears on-chain.
            Connecting a wallet below is optional (display only).
          </p>
          <div className="row">
            <button
              className="btn btn-primary"
              disabled={connecting || !hasPhantom}
              onClick={connectPhantomWallet}
            >
              {connecting ? "Connecting…" : "Connect Phantom"}
            </button>
            <span className="muted">or paste a secret key:</span>
          </div>
          <div className="field" style={{ marginTop: 10 }}>
            <textarea
              className="textarea"
              value={secretKeyText}
              onChange={(e) => setSecretKeyText(e.target.value)}
              placeholder="[1,2,3, … 64 numbers]"
            />
          </div>
          <button className="btn" disabled={connecting || !secretKeyText.trim()} onClick={() => connectKey(secretKeyText)}>
            Use pasted key
          </button>

          <div className="spacer" />
          <div className="field">
            <label>Election manifest (JSON)</label>
            <textarea className="textarea" value={manifestText} onChange={(e) => setManifestText(e.target.value)} />
          </div>
          <button
            className="btn btn-primary btn-block"
            disabled={busy || !manifestText.trim()}
            onClick={loadAndVerify}
          >
            {busy ? "Verifying…" : "Load & verify"}
          </button>
          {error && <div className="alert alert-error">{error}</div>}
          {wallet && balance !== null && (
            <div className="alert alert-info">
              Connected wallet: <span className="mono">{wallet.publicKey.toBase58()}</span>{" "}
              ({balance.toFixed(3)} SOL) — cosmetic; the relayer will pay and your address stays off-chain.
            </div>
          )}
        </div>
      )}

      {step === 1 && (
        <div className="card">
          <h2>Identify yourself</h2>
          <p className="hint">
            Your secret is derived from your id + password <strong>on this device</strong> and never
            leaves it. We use it to privately check that you're on the registered voter list.
          </p>
          <div className="field">
            <label>Name (optional — display only)</label>
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="field">
            <label>ID number</label>
            <input className="input" value={voterId} onChange={(e) => setVoterId(e.target.value)} />
          </div>
          <div className="field">
            <label>Password</label>
            <input
              className="input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <button className="btn btn-primary" disabled={busy || !voterId || !password} onClick={identify}>
            {busy ? "Checking…" : "Check eligibility"}
          </button>
        </div>
      )}

      {step === 2 && (
        <div className="card">
          <h2>Make your selections</h2>
          <p className="hint">
            Choose one aspirant per position. Each choice is encrypted under the election public key
            (ElGamal over Grumpkin) and submitted with its own zero-knowledge proof.
          </p>
          {manifest?.positions.map((pos, pi) => (
            <div key={pos.positionId} className="card" style={{ marginBottom: 12 }}>
              <h3 style={{ margin: "0 0 8px", fontSize: 15 }}>{pos.title}</h3>
              {pos.candidates.map((c, i) => (
                <label key={c} className={`candidate${selections[pi] === i ? " selected" : ""}`}>
                  <input
                    type="radio"
                    name={`position-${pi}`}
                    checked={selections[pi] === i}
                    onChange={() => setSelections((prev) => prev.map((v, j) => (j === pi ? i : v)))}
                  />
                  {c}
                </label>
              ))}
            </div>
          ))}
          <button className="btn btn-primary btn-block" disabled={busy || !allChosen()} onClick={() => setStep(3)}>
            Review selections
          </button>
        </div>
      )}

      {step === 3 && (
        <div className="card">
          <h2>Review & confirm</h2>
          <p className="hint">
            Check your selections, then submit one encrypted ballot per position (one transaction
            each, in order). A relayer pays the fees; your wallet stays anonymous.
          </p>
          <table className="table">
            <tbody>
              {manifest?.positions.map((pos, pi) => (
                <tr key={pos.positionId}>
                  <th>{pos.title}</th>
                  <td>{selections[pi] === null || selections[pi] === undefined ? "—" : pos.candidates[selections[pi]!]}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {busy && stage && <div className="alert alert-info">{stage}…</div>}
          <button className="btn btn-primary btn-block" disabled={busy} onClick={castAll}>
            {busy ? "Casting…" : "Confirm & cast all votes"}
          </button>
          <button className="btn" disabled={busy} onClick={() => setStep(2)} style={{ marginTop: 8 }}>
            Back
          </button>
        </div>
      )}

      {step === 4 && (
        <div className="card">
          <h2>Votes recorded</h2>
          <div className="alert alert-success">
            Your encrypted ballots were cast. The chain stores only ciphertexts — your choices stay
            private, and a Groth16 proof attests your eligibility on-chain.
          </div>
          <table className="table">
            <tbody>
              {results.map((r) => (
                <tr key={r.title}>
                  <th>{r.title}</th>
                  <td>{r.candidate}</td>
                  <td className="mono">{r.txSig}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="row" style={{ gap: 8 }}>
            {results.map((r) => (
              <a
                key={r.title}
                className="btn"
                href={`https://explorer.solana.com/tx/${r.txSig}?cluster=custom`}
                target="_blank"
                rel="noreferrer"
              >
                {r.title} on explorer
              </a>
            ))}
          </div>

          <div className="spacer" />
          <Link href="/?done=voter" className="btn btn-primary btn-block">
            Done — back to home
          </Link>
        </div>
      )}

      {actionError && <div className="alert alert-error">{actionError}</div>}
    </div>
  );
}
