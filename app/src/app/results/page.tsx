"use client";

import { useState } from "react";
import BN from "bn.js";
import { PublicKey } from "@solana/web3.js";
import { friendlyError } from "@/lib/errors";
import { bytesToBigInt, hex } from "@/lib/crypto";
import { parseManifest, type ElectionManifest } from "@/lib/manifest";
import { getReadonlyProgram } from "@/lib/solana/program";
import { programId } from "@/lib/solana/connection";
import { electionPda, positionPda, tallyPda, transcriptPda } from "@/lib/solana/pda";

interface PositionResult {
  title: string;
  candidates: string[];
  ballotCount: number;
  tally?: number[];
}

export default function ResultsPage() {
  const [manifestText, setManifestText] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [frozenRoot, setFrozenRoot] = useState<string | null>(null);
  const [results, setResults] = useState<PositionResult[]>([]);

  async function load() {
    setBusy(true);
    setActionError(null);
    try {
      const m: ElectionManifest = parseManifest(manifestText);
      const program = getReadonlyProgram();
      const authority = new PublicKey(m.authority);
      const [election] = electionPda(authority, new BN(m.electionId), programId);

      const electionAccount = await program.account.electionConfig.fetch(election);
      setFrozenRoot(hex(bytesToBigInt(electionAccount.frozenRoot as number[])));

      const next: PositionResult[] = [];
      for (const p of m.positions) {
        const [position] = positionPda(election, new BN(p.positionId), programId);
        const [transcript] = transcriptPda(position, programId);
        const [tally] = tallyPda(position, programId);

        const t = await program.account.ballotTranscript.fetch(transcript).catch(() => null);
        const tal = await program.account.tallyResult.fetch(tally).catch(() => null);

        next.push({
          title: p.title,
          candidates: p.candidates,
          ballotCount: t ? (t.ballotCount as BN).toNumber() : 0,
          tally: tal ? (tal.totals as BN[]).map((v) => v.toNumber()) : undefined,
        });
      }
      setResults(next);
    } catch (e) {
      setActionError(friendlyError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="container">
      <div className="card">
        <h2>📊 Results</h2>
        <p className="hint">
          Paste the election manifest to inspect the live transcript and the on-chain verified
          tally (if the admin has posted it).
        </p>
        <div className="field">
          <textarea className="textarea" value={manifestText} onChange={(e) => setManifestText(e.target.value)} />
        </div>
        <button className="btn btn-primary" disabled={busy || !manifestText.trim()} onClick={load}>
          {busy ? "Loading…" : "Load results"}
        </button>
        {actionError && <div className="alert alert-error">{actionError}</div>}
      </div>

      {frozenRoot && (
        <div className="card">
          <div className="muted" style={{ marginBottom: 12 }}>
            Voter list fingerprint: <span className="mono">{frozenRoot}</span>
          </div>
          {results.length === 0 && <p className="muted">No positions loaded yet.</p>}
          {results.map((r) => (
            <div key={r.title} className="card" style={{ marginBottom: 12 }}>
              <h3 style={{ margin: "0 0 8px", fontSize: 15 }}>{r.title}</h3>
              <table className="table">
                <tbody>
                  <tr>
                    <th>Ballots cast</th>
                    <td>{r.ballotCount}</td>
                  </tr>
                  <tr>
                    <th>Tally</th>
                    <td>
                      {r.tally
                        ? r.candidates.map((c, i) => `${c}: ${r.tally?.[i] ?? 0}`).join(" · ")
                        : "not posted yet"}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
