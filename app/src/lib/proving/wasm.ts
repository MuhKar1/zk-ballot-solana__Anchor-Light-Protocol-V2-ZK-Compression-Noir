// On-device Groth16 prover backed by the Go-compiled prover.wasm, running in a
// Web Worker. Implements the same `Prover` interface as `NodeProver`.

import { prove } from "./node";
import type { Prover, VoteWitness } from "./types";

const ARTIFACT_URLS = {
  wasmExec: "/wasm_exec.js",
  wasm: "/prover.wasm",
  acir: "/proving/voting_circuit.json",
  ccs: "/proving/voting_circuit.ccs",
  pk: "/proving/voting_circuit.pk",
};

interface WorkerResponse {
  seq: number;
  type: "ready" | "proof" | "error";
  proof?: Uint8Array;
  error?: string;
}

export class WasmProver implements Prover {
  private worker: Worker | null = null;
  private seq = 0;
  private pending = new Map<number, { resolve: (v: WorkerResponse) => void; reject: (e: Error) => void }>();

  private ensureWorker(): Worker {
    if (this.worker) return this.worker;
    const worker = new Worker(new URL("../../workers/prover.worker.ts", import.meta.url));
    worker.onmessage = (e: MessageEvent) => {
      const msg = e.data as WorkerResponse;
      const entry = this.pending.get(msg.seq);
      if (!entry) return;
      this.pending.delete(msg.seq);
      if (msg.type === "error") entry.reject(new Error(msg.error));
      else entry.resolve(msg);
    };
    this.worker = worker;
    return worker;
  }

  private request(message: Record<string, unknown>): Promise<WorkerResponse> {
    const worker = this.ensureWorker();
    const seq = ++this.seq;
    return new Promise((resolve, reject) => {
      this.pending.set(seq, { resolve, reject });
      worker.postMessage({ ...message, seq });
    });
  }

  private async init(): Promise<void> {
    await this.request({ type: "init", urls: ARTIFACT_URLS });
  }

  /** Prove a pre-generated `nargo execute` witness stack (Problem A only). */
  async proveRaw(witnessGz: Uint8Array): Promise<Uint8Array> {
    await this.init();
    const msg = await this.request({ type: "prove", witness: witnessGz });
    if (!msg.proof) throw new Error("worker returned no proof");
    return msg.proof;
  }

  async proveVote(witness: VoteWitness): Promise<Uint8Array> {
    await this.init();
    const msg = await this.request({ type: "proveVote", inputs: witness });
    if (!msg.proof) throw new Error("worker returned no proof");
    return msg.proof;
  }

  async proveTally(inputs: object): Promise<Uint8Array> {
    // Tally proving runs server-side by design (nargo + sunspot). Delegate to the
    // same `/api/prove` route NodeProver uses so the WASM vote prover and the
    // server tally can coexist.
    return prove("tally", inputs);
  }
}
