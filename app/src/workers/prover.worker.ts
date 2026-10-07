// Web Worker hosting the Go-compiled prover.wasm. Keeps Groth16 proving off the
// main thread. See app/prisms/prover for the Go module + build.
//
// Witness generation ("Problem B") runs here too, via `@noir-lang/noir_js` +
// `@noir-lang/acvm_js` (pinned to 1.0.0-beta.22, matching the nargo toolchain
// that compiled the circuit). `Noir.execute()` returns `compressWitnessStack(...)`
// — the exact `nargo execute` `.gz` byte format the Go prover consumes — so the
// witness never needs a filesystem and never leaves the worker.

import { Noir } from "@noir-lang/noir_js";

interface WorkerScope {
  Go?: new () => { importObject: WebAssembly.Imports; run(instance: WebAssembly.Instance): Promise<void> };
  importScripts?: (...urls: string[]) => void;
  proverLoad?: (acir: string, ccs: string, pk: string) => { error?: string } | null;
  proverProve?: (witness: string) => string | { error?: string };
}

const scope = self as unknown as WorkerScope;

function bytesToB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64ToBytes(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

async function fetchBytes(url: string): Promise<Uint8Array> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`failed to fetch ${url}`);
  return new Uint8Array(await res.arrayBuffer());
}

let ready = false;
let circuitJson: object | null = null;

async function init(urls: { wasmExec: string; wasm: string; acir: string; ccs: string; pk: string }) {
  if (ready) return;

  if (typeof scope.importScripts === "function") scope.importScripts(urls.wasmExec);
  if (!scope.Go) throw new Error("wasm_exec.js did not define Go");

  const go = new scope.Go();
  const resp = await fetch(urls.wasm);
  const { instance } = await WebAssembly.instantiateStreaming(resp, go.importObject);
  go.run(instance); // do not await — the Go main() blocks forever

  const [acir, ccs, pk] = await Promise.all([urls.acir, urls.ccs, urls.pk].map(fetchBytes));
  circuitJson = JSON.parse(new TextDecoder().decode(acir)) as object;
  const loadFn = scope.proverLoad;
  if (typeof loadFn !== "function") throw new Error("Go wasm did not register proverLoad");

  const err = loadFn(bytesToB64(acir), bytesToB64(ccs), bytesToB64(pk));
  if (err && err.error) throw new Error(err.error);
  ready = true;
}

function proveFromWitness(witnessBytes: Uint8Array): Uint8Array {
  const proveFn = scope.proverProve;
  if (typeof proveFn !== "function") throw new Error("Go wasm did not register proverProve");
  const out = proveFn(bytesToB64(witnessBytes));
  if (out && (out as { error?: string }).error) throw new Error((out as { error?: string }).error as string);
  return b64ToBytes(out as string);
}

self.onmessage = async (e: MessageEvent) => {
  const msg = e.data as {
    type: string;
    seq?: number;
    urls?: { wasmExec: string; wasm: string; acir: string; ccs: string; pk: string };
    witness?: Uint8Array;
    inputs?: Record<string, unknown>;
  };
  const post = (m: Record<string, unknown>) =>
    (self as unknown as { postMessage(m: unknown): void }).postMessage({ seq: msg.seq, ...m });

  try {
    if (msg.type === "init") {
      await init(msg.urls as { wasmExec: string; wasm: string; acir: string; ccs: string; pk: string });
      post({ type: "ready" });
    } else if (msg.type === "prove") {
      if (!ready) throw new Error("worker not initialized");
      post({ type: "proof", proof: proveFromWitness(msg.witness as Uint8Array) });
    } else if (msg.type === "proveVote") {
      if (!ready) throw new Error("worker not initialized");
      if (!circuitJson) throw new Error("circuit JSON not loaded");
      if (!msg.inputs) throw new Error("proveVote requires inputs");

      // Solve the circuit on-device (noir_js → acvm_js). The returned witness is
      // the gzip + format-byte + msgpack stack — byte-identical to `nargo execute`.
      const noir = new Noir(circuitJson as never);
      const { witness } = await noir.execute(msg.inputs as never);

      post({ type: "proof", proof: proveFromWitness(witness) });
    }
  } catch (err) {
    post({ type: "error", error: err instanceof Error ? err.message : String(err) });
  }
};
