import { NodeProver } from "./node";
import { WasmProver } from "./wasm";
import type { Prover } from "./types";

export * from "./types";
export { NodeProver } from "./node";
export { WasmProver } from "./wasm";

/**
 * Active prover. `NEXT_PUBLIC_PROVER=wasm` selects the on-device WASM prover
 * (see app/prisms/prover); anything else falls back to the server-side NodeProver.
 *
 * NOTE: the WASM prover still needs on-device witness generation ("Problem B",
 * noir_js/acvm_js) before `proveVote` works end-to-end.
 */
export const prover: Prover =
  process.env.NEXT_PUBLIC_PROVER === "wasm" ? new WasmProver() : new NodeProver();

