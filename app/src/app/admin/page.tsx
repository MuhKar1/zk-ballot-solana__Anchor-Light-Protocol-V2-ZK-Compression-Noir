"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import BN from "bn.js";
import { useSolanaWallet } from "@/components/providers";
import { Stepper } from "@/components/stepper";
import { friendlyError } from "@/lib/errors";
import { bytesToBigInt, buildTree, deriveSecret, hex, leafOf, poseidon2 } from "@/lib/crypto";
import type { ElectionManifest } from "@/lib/manifest";
import { getProgram } from "@/lib/solana/program";
import { getConnection, programId } from "@/lib/solana/connection";
import { electionPda, positionPda, tallyPda, transcriptPda } from "@/lib/solana/pda";
import { fetchBallotCasts } from "@/lib/solana/events";
import { buildTallyWitness } from "@/lib/tally";
import { prover } from "@/lib/proving";
import {
  fetchAdminElections,
  freezeVoterRoot,
  generateTallyKey,
  initializeElection,
  initializePosition,
  postTally,
  type AdminElection,
} from "@/lib/solana/admin";

const STEPS = ["Connect", "Election", "Positions", "Voters", "Status & tally"];

interface PositionDraft {
  key: number;
  title: string;
  candidatesText: string;
}

interface CommittedPosition {
  positionId: number;
  title: string;
  maxCandidates: number;
  candidates: string[];
}

interface ElectionStatus {
  isFrozen: boolean;
  frozenRoot: string;
  leafCount: number;
}

interface PositionStatus {
  title: string;
  ballotCount: number;
  tally?: number[];
}

export default function AdminPage() {
  const { wallet, hasPhantom, connectPhantomWallet, connectKey, connecting, balance, error } =
    useSolanaWallet();

  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [txSig, setTxSig] = useState<string | null>(null);

  const [electionName, setElectionName] = useState("Student Council 2026");
  const [delaySec, setDelaySec] = useState(300);
  const [durationSec, setDurationSec] = useState(3600);

  const [electionId, setElectionId] = useState<BN | null>(null);
  const [tallyKey, setTallyKey] = useState<{ sk: bigint; pkX: bigint; pkY: bigint } | null>(null);

  const [positionsDraft, setPositionsDraft] = useState<PositionDraft[]>([
    { key: 0, title: "President", candidatesText: "Alice, Bob" },
    { key: 1, title: "Secretary", candidatesText: "Carol, Dave" },
  ]);
  const [positionKey, setPositionKey] = useState(2);
  const [positions, setPositions] = useState<CommittedPosition[]>([]);

  const [votersText, setVotersText] = useState("Alice,1001,passA\nBob,1002,passB\nCarol,1003,passC");
  const [root, setRoot] = useState<bigint | null>(null);
  const [leafCount, setLeafCount] = useState<number>(0);
  const [manifest, setManifest] = useState<ElectionManifest | null>(null);

  const [secretKeyText, setSecretKeyText] = useState("");
  const [electionStatus, setElectionStatus] = useState<ElectionStatus | null>(null);
  const [statuses, setStatuses] = useState<PositionStatus[]>([]);
  const [elections, setElections] = useState<AdminElection[]>([]);
  const [electionsLoading, setElectionsLoading] = useState(false);

  const [tallyPositionId, setTallyPositionId] = useState<number>(1);
  const [tallyProofB64, setTallyProofB64] = useState("");
  const [tallyTotals, setTallyTotals] = useState("0,0,0,0");

  const parsedDrafts = useMemo(
    () =>
      positionsDraft.map((d) => ({
        ...d,
        title: d.title.trim() || `Position ${d.key + 1}`,
        candidates: d.candidatesText
          .split(",")
          .map((c) => c.trim())
          .filter(Boolean),
      })),
    [positionsDraft]
  );

  const draftsValid =
    parsedDrafts.length > 0 &&
    parsedDrafts.every((d) => d.candidates.length >= 1 && d.candidates.length <= 4);

  const program = wallet ? getProgram(wallet) : null;

  async function loadElections() {
    if (!program || !wallet) return;
    setElectionsLoading(true);
    try {
      setElections(await fetchAdminElections(program, wallet.publicKey));
    } catch (e) {
      setActionError(friendlyError(e));
    } finally {
      setElectionsLoading(false);
    }
  }

  useEffect(() => {
    if (wallet) {
      const p = getProgram(wallet);
      fetchAdminElections(p, wallet.publicKey)
        .then(setElections)
        .catch(() => setElections([]));
    } else {
      setElections([]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wallet]);

  function resetError() {
    setActionError(null);
    setTxSig(null);
  }

  function updateDraft(key: number, patch: Partial<PositionDraft>) {
    setPositionsDraft((prev) => prev.map((d) => (d.key === key ? { ...d, ...patch } : d)));
  }

  function addPosition() {
    setPositionsDraft((prev) => [
      ...prev,
      { key: positionKey, title: `Position ${positionKey + 1}`, candidatesText: "" },
    ]);
    setPositionKey((k) => k + 1);
  }

  function removePosition(key: number) {
    setPositionsDraft((prev) => prev.filter((d) => d.key !== key));
  }

  async function createElection() {
    if (!program || !wallet) return;
    setBusy(true);
    resetError();
    try {
      const key = generateTallyKey();
      const id = new BN(Date.now());
      const now = Math.floor(Date.now() / 1000);
      const start = new BN(now + delaySec);
      const end = new BN(now + delaySec + durationSec);
      const sig = await initializeElection(program, wallet, {
        electionId: id,
        pkX: key.pkX,
        pkY: key.pkY,
        voteStartTs: start,
        voteEndTs: end,
      });
      setElectionId(id);
      setTallyKey(key);
      setTxSig(sig);
      setStep(2);
    } catch (e) {
      setActionError(friendlyError(e));
    } finally {
      setBusy(false);
    }
  }

  async function createPositions() {
    if (!program || !wallet || !electionId) return;
    setBusy(true);
    resetError();
    try {
      const committed: CommittedPosition[] = parsedDrafts.map((d, i) => ({
        positionId: i + 1,
        title: d.title,
        maxCandidates: d.candidates.length,
        candidates: d.candidates,
      }));
      for (const p of committed) {
        const sig = await initializePosition(program, wallet, {
          electionId,
          positionId: new BN(p.positionId),
          maxCandidates: p.maxCandidates,
        });
        setTxSig(sig);
      }
      setPositions(committed);
      setStep(3);
    } catch (e) {
      setActionError(friendlyError(e));
    } finally {
      setBusy(false);
    }
  }

  async function enrollAndFreeze() {
    if (!program || !wallet || !electionId || !tallyKey) return;
    setBusy(true);
    resetError();
    try {
      const rows = votersText
        .split("\n")
        .map((line) => line.split(",").map((p) => p.trim()))
        .filter((parts) => parts.length >= 2);

      const leaves: bigint[] = [];
      for (const parts of rows) {
        const id = parts[1];
        const password = parts[2] ?? "";
        const s = await deriveSecret(id, password);
        leaves.push(leafOf(s));
      }
      const tree = buildTree(leaves);
      const sig = await freezeVoterRoot(program, wallet, {
        electionId,
        root: tree.root,
        leafCount: leaves.length,
      });

      const pkHash = poseidon2([tallyKey.pkX, tallyKey.pkY]);
      const m: ElectionManifest = {
        electionId: electionId.toString(),
        authority: wallet.publicKey.toBase58(),
        root: hex(tree.root),
        pkX: hex(tallyKey.pkX),
        pkY: hex(tallyKey.pkY),
        pkHash: hex(pkHash),
        leaves: leaves.map(hex),
        voteStartTs: Math.floor(Date.now() / 1000) + delaySec,
        voteEndTs: Math.floor(Date.now() / 1000) + delaySec + durationSec,
        positions: positions.map((p) => ({
          positionId: p.positionId.toString(),
          title: p.title,
          maxCandidates: p.maxCandidates,
          candidates: p.candidates,
        })),
      };

      setRoot(tree.root);
      setLeafCount(leaves.length);
      setManifest(m);
      setTxSig(sig);
      setStep(4);
    } catch (e) {
      setActionError(friendlyError(e));
    } finally {
      setBusy(false);
    }
  }

  async function refreshStatus() {
    if (!program || !wallet || !electionId) return;
    setBusy(true);
    resetError();
    try {
      const [election] = electionPda(wallet.publicKey, electionId, programId);
      const e = await program.account.electionConfig.fetch(election);
      setElectionStatus({
        isFrozen: e.isFrozen as boolean,
        frozenRoot: hex(bytesToBigInt(e.frozenRoot as number[])),
        leafCount: (e.leafCount as BN).toNumber(),
      });

      const next: PositionStatus[] = [];
      for (const p of positions) {
        const [position] = positionPda(election, new BN(p.positionId), programId);
        const [transcript] = transcriptPda(position, programId);
        const [tally] = tallyPda(position, programId);
        const t = await program.account.ballotTranscript.fetch(transcript).catch(() => null);
        const tal = await program.account.tallyResult.fetch(tally).catch(() => null);
        next.push({
          title: p.title,
          ballotCount: t ? (t.ballotCount as BN).toNumber() : 0,
          tally: tal ? (tal.totals as BN[]).map((v) => v.toNumber()) : undefined,
        });
      }
      setStatuses(next);
    } catch (e) {
      setActionError(friendlyError(e));
    } finally {
      setBusy(false);
    }
  }

  async function submitTally() {
    if (!program || !wallet || !electionId) return;
    setBusy(true);
    resetError();
    try {
      const totals = tallyTotals.split(",").map((t) => parseInt(t.trim(), 10) || 0);
      const proof = Uint8Array.from(atob(tallyProofB64.trim()), (c) => c.charCodeAt(0));
      const sig = await postTally(program, wallet, {
        electionId,
        positionId: new BN(tallyPositionId),
        totals,
        proof,
      });
      setTxSig(sig);
      await refreshStatus();
    } catch (e) {
      setActionError(friendlyError(e));
    } finally {
      setBusy(false);
    }
  }

  async function autoTally() {
    if (!program || !wallet || !electionId || !tallyKey) {
      setActionError("Missing election context — create the election first (or paste sk below).");
      return;
    }
    setBusy(true);
    resetError();
    try {
      const [election] = electionPda(wallet.publicKey, electionId, programId);
      const connection = getConnection();
      let posted = 0;

      for (const p of positions) {
        const [position] = positionPda(election, new BN(p.positionId), programId);
        const [transcript] = transcriptPda(position, programId);

        const events = await fetchBallotCasts(connection, position);
        if (events.length === 0) continue;

        const witness = buildTallyWitness({
          sk: tallyKey.sk,
          pkX: tallyKey.pkX,
          pkY: tallyKey.pkY,
          maxCandidates: p.maxCandidates,
          ballots: events.map((e) => ({ nullifier: e.nullifier, xs: e.xs, parity: e.parityBits })),
        });

        // Cross-check the locally-folded transcript against the chain before proving.
        const t = await program.account.ballotTranscript.fetch(transcript);
        if (hex(bytesToBigInt(t.transcript as number[])) !== hex(BigInt(witness.transcript))) {
          throw new Error(`transcript mismatch for ${p.title} — ballots are out of order or missing`);
        }

        const proof = await prover.proveTally(witness);
        const totals = witness.totals.map((v) => parseInt(v, 10));
        const sig = await postTally(program, wallet, {
          electionId,
          positionId: new BN(p.positionId),
          totals,
          proof,
        });
        setTxSig(sig);
        posted++;
      }

      if (posted === 0) throw new Error("no ballots found for any position");
      await refreshStatus();
    } catch (e) {
      setActionError(friendlyError(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="container">
      <Stepper steps={STEPS} current={step} />

      {step === 0 && (
        <div className="card">
          <h2>Connect your admin wallet</h2>
          <p className="hint">
            The admin wallet is the election authority and pays for every on-chain action. On the
            local validator, fund it with <code className="mono">solana airdrop</code>.
          </p>
          <div className="row">
            <button
              className="btn btn-primary"
              disabled={connecting || !hasPhantom}
              onClick={connectPhantomWallet}
            >
              {connecting ? "Connecting…" : "Connect Phantom"}
            </button>
            <span className="muted">or paste a base58 secret key (JSON array of 64 numbers):</span>
          </div>
          <div className="field" style={{ marginTop: 10 }}>
            <textarea
              className="textarea"
              value={secretKeyText}
              onChange={(e) => setSecretKeyText(e.target.value)}
              placeholder="[1,2,3, … 64 numbers]"
            />
          </div>
          <button
            className="btn"
            disabled={connecting || !secretKeyText.trim()}
            onClick={() => connectKey(secretKeyText)}
          >
            Use pasted key
          </button>
          {error && <div className="alert alert-error">{error}</div>}
          {wallet && balance !== null && (
            <div className="alert alert-success">
              Connected as <span className="mono">{wallet.publicKey.toBase58()}</span> —{" "}
              {balance.toFixed(3)} SOL.{" "}
              <button className="btn" onClick={() => setStep(1)}>
                Continue
              </button>
            </div>
          )}
        </div>
      )}

      {step === 1 && (
        <>
          <div className="card">
            <h2>Your elections</h2>
            <p className="hint">
              Every election created by this admin wallet, whether upcoming, ongoing, or ended.
            </p>
            <button className="btn" disabled={electionsLoading} onClick={loadElections}>
              {electionsLoading ? "Loading…" : "Refresh"}
            </button>
            {elections.length === 0 && !electionsLoading ? (
              <p className="muted">No elections found for this wallet yet.</p>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>Election id</th>
                    <th>Status</th>
                    <th>Voter list</th>
                    <th>Voters</th>
                  </tr>
                </thead>
                <tbody>
                  {elections.map((e) => (
                    <tr key={e.publicKey.toBase58()}>
                      <td className="mono">{e.electionId.toString()}</td>
                      <td>
                        <span
                          className={
                            e.state === "ongoing"
                              ? "badge ok"
                              : e.state === "ended"
                                ? "badge warn"
                                : "badge"
                          }
                        >
                          {e.state}
                        </span>
                      </td>
                      <td>{e.isFrozen ? "locked" : "open"}</td>
                      <td>{e.leafCount}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <div className="card">
          <h2>Election</h2>
          <p className="hint">
            Generates an ElGamal key pair (the tally secret <code className="mono">sk</code> is shown
            next — keep it to decrypt later) and opens the voting window.
          </p>
          <div className="field">
            <label>Name (label only)</label>
            <input className="input" value={electionName} onChange={(e) => setElectionName(e.target.value)} />
          </div>
          <div className="grid-2">
            <div className="field">
              <label>Voting starts in (seconds — leave time to finish setup)</label>
              <input
                className="input"
                type="number"
                value={delaySec}
                onChange={(e) => setDelaySec(parseInt(e.target.value, 10) || 0)}
              />
            </div>
            <div className="field">
              <label>Voting duration (seconds)</label>
              <input
                className="input"
                type="number"
                value={durationSec}
                onChange={(e) => setDurationSec(parseInt(e.target.value, 10) || 0)}
              />
            </div>
          </div>
          <button className="btn btn-primary" disabled={busy} onClick={createElection}>
            {busy ? "Creating…" : "Create election"}
          </button>
          </div>
        </>
      )}

      {step === 2 && (
        <div className="card">
          <h2>Positions / races</h2>
          <p className="hint">
            Add each position (race) and its aspirants (1–4, comma-separated). Each position becomes
            its own on-chain race and encrypted ballot.
          </p>
          {tallyKey && (
            <div className="alert alert-info" style={{ marginBottom: 12 }}>
              <div>
                Tally secret key <code className="mono">sk</code> (back this up):{" "}
                <code className="mono">{tallyKey.sk.toString()}</code>
              </div>
              <div>
                Public key: <code className="mono">({hex(tallyKey.pkX)}, {hex(tallyKey.pkY)})</code>
              </div>
            </div>
          )}
          {parsedDrafts.map((d, i) => (
            <div key={d.key} className="card" style={{ marginBottom: 12 }}>
              <div className="grid-2">
                <div className="field">
                  <label>Position title</label>
                  <input
                    className="input"
                    value={d.title}
                    onChange={(e) => updateDraft(d.key, { title: e.target.value })}
                  />
                </div>
                <div className="field">
                  <label>Aspirants ({d.candidates.length}/4)</label>
                  <input
                    className="input"
                    value={d.candidatesText}
                    onChange={(e) => updateDraft(d.key, { candidatesText: e.target.value })}
                  />
                </div>
              </div>
              <div className="muted" style={{ marginBottom: 8 }}>
                Position id {i + 1} — {d.candidates.length ? d.candidates.join(", ") : "no aspirants"}
              </div>
              <button
                className="btn btn-ghost"
                disabled={busy || positionsDraft.length <= 1}
                onClick={() => removePosition(d.key)}
              >
                Remove position
              </button>
            </div>
          ))}
          <button className="btn" disabled={busy} onClick={addPosition}>
            + Add position
          </button>
          <div className="spacer" />
          <button className="btn btn-primary btn-block" disabled={busy || !draftsValid} onClick={createPositions}>
            {busy ? "Creating…" : "Create positions"}
          </button>
        </div>
      )}

      {step === 3 && (
        <div className="card">
          <h2>Register eligible voters</h2>
          <p className="hint">
            Add every eligible voter — one per line as{" "}
            <code className="mono">name,id,password</code>. Locking the list records a tamper-proof
            fingerprint of it on-chain, so nobody can be added or removed once voting starts.
          </p>
          <div className="field">
            <label>Voters</label>
            <textarea className="textarea" value={votersText} onChange={(e) => setVotersText(e.target.value)} />
          </div>
          <button className="btn btn-primary" disabled={busy} onClick={enrollAndFreeze}>
            {busy ? "Locking…" : "Lock the voter list"}
          </button>
          {root !== null && (
            <div className="alert alert-success" style={{ marginTop: 12 }}>
              <div>
                Voter list fingerprint: <code className="mono">{hex(root)}</code>
              </div>
              <div>Eligible voters: {leafCount}</div>
            </div>
          )}
        </div>
      )}

      {step === 4 && (
        <>
          <div className="card">
            <h2>Status & tally</h2>
            <div className="row" style={{ marginBottom: 12 }}>
              <button className="btn" disabled={busy} onClick={refreshStatus}>
                Refresh status
              </button>
              {txSig && (
                <a
                  className="mono"
                  href={`https://explorer.solana.com/tx/${txSig}?cluster=custom`}
                  target="_blank"
                  rel="noreferrer"
                >
                  last tx
                </a>
              )}
            </div>
            {electionStatus && (
              <table className="table">
                <tbody>
                  <tr>
                    <th>Voter list locked</th>
                    <td>{electionStatus.isFrozen ? "yes" : "no"}</td>
                  </tr>
                  <tr>
                    <th>List fingerprint</th>
                    <td className="mono">{electionStatus.frozenRoot}</td>
                  </tr>
                  <tr>
                    <th>Voters</th>
                    <td>{electionStatus.leafCount}</td>
                  </tr>
                </tbody>
              </table>
            )}
            {statuses.map((s, i) => (
              <div key={i} className="card" style={{ marginBottom: 12 }}>
                <h3 style={{ margin: "0 0 8px", fontSize: 15 }}>{s.title}</h3>
                <table className="table">
                  <tbody>
                    <tr>
                      <th>Ballots cast</th>
                      <td>{s.ballotCount}</td>
                    </tr>
                    <tr>
                      <th>Tally</th>
                      <td>{s.tally ? `[${s.tally.join(", ")}]` : "not posted"}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            ))}
          </div>

          <div className="card">
            <h2>Election manifest (share with voters)</h2>
            <p className="hint">
              Share this JSON with voters. It contains the locked voter-list fingerprint and the
              election public key, so each voter's device can privately confirm they're on the list.
            </p>
            {manifest ? (
              <>
                <textarea className="textarea" readOnly value={JSON.stringify(manifest)} />
                <div className="row" style={{ marginTop: 10 }}>
                  <button
                    className="btn"
                    onClick={() => navigator.clipboard.writeText(JSON.stringify(manifest))}
                  >
                    Copy manifest
                  </button>
                  <button
                    className="btn"
                    onClick={() => {
                      const blob = new Blob([JSON.stringify(manifest, null, 2)], {
                        type: "application/json",
                      });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = `manifest-${manifest.electionId}.json`;
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                  >
                    Download
                  </button>
                </div>
              </>
            ) : (
              <p className="muted">Lock the voter list first to generate the shareable manifest.</p>
            )}
          </div>

          <div className="card">
            <h2>Post tally</h2>
            <p className="hint">
              Gathers the ballots from the chain (in cast order) for every position, decrypts them
              with the election secret key, proves each result with <code className="mono">tally_circuit</code>,
              and publishes it. Proving runs server-side via <code className="mono">sunspot</code>.
            </p>
            <button className="btn btn-primary" disabled={busy || !tallyKey} onClick={autoTally}>
              {busy ? "Working…" : "Auto tally all positions (gather → prove → post)"}
            </button>
            {!tallyKey && (
              <p className="muted">
                The election secret key is only held in this session — create the election (or redo
                the flow) to run auto tally.
              </p>
            )}

            <div className="spacer" />
            <h3 style={{ margin: "0 0 8px", fontSize: 15 }}>Manual (advanced)</h3>
            <div className="field">
              <label>Position</label>
              <select
                className="input"
                value={tallyPositionId}
                onChange={(e) => setTallyPositionId(parseInt(e.target.value, 10) || 1)}
              >
                {positions.map((p) => (
                  <option key={p.positionId} value={p.positionId}>
                    {p.positionId} — {p.title}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label>Totals (comma-separated, length 4)</label>
              <input className="input" value={tallyTotals} onChange={(e) => setTallyTotals(e.target.value)} />
            </div>
            <div className="field">
              <label>Proof (base64)</label>
              <textarea className="textarea" value={tallyProofB64} onChange={(e) => setTallyProofB64(e.target.value)} />
            </div>
            <button className="btn" disabled={busy || !tallyProofB64.trim()} onClick={submitTally}>
              {busy ? "Posting…" : "Post tally"}
            </button>
          </div>

          <div className="card">
            <h2>All set 🎉</h2>
            <p className="hint">
              Your election is configured and the voter list is locked. Share the manifest with your
              voters, then come back to post the tally once voting ends.
            </p>
            <Link href="/?done=admin" className="btn btn-primary btn-block">
              Done — back to home
            </Link>
          </div>
        </>
      )}

      {actionError && <div className="alert alert-error">{actionError}</div>}
      {txSig && (
        <div className="alert alert-success">
          Transaction confirmed: <span className="mono">{txSig}</span>
        </div>
      )}
    </div>
  );
}
