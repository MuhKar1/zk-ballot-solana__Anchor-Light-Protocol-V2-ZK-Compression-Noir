import { base64ToBytes } from "@/lib/bytes";
import type { Prover, VoteWitness } from "./types";

/**
 * Dev/working prover: delegates to the Next.js `/api/prove` route, which runs
 * `nargo execute` + `sunspot prove` locally. This sends the witness to the server
 * (documented limitation) — the WASM prover replaces it later.
 */
export class NodeProver implements Prover {
  async proveVote(witness: VoteWitness): Promise<Uint8Array> {
    return prove("voting", witness);
  }

  async proveTally(inputs: object): Promise<Uint8Array> {
    return prove("tally", inputs);
  }
}

export async function prove(circuit: "voting" | "tally", inputs: object): Promise<Uint8Array> {
  const res = await fetch("/api/prove", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ circuit, inputs }),
  });
  const data = (await res.json().catch(() => ({}))) as { proof?: string; error?: string };
  if (!res.ok) throw new Error(data.error ?? `proving failed (HTTP ${res.status})`);
  if (!data.proof) throw new Error("prover returned no proof");
  return base64ToBytes(data.proof);
}

