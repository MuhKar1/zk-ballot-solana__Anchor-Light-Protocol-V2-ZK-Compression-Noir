// Dev proving service. Generates a Groth16 proof by running the local Noir +
// Sunspot toolchain (nargo execute + sunspot prove) on the pinned circuit
// artifacts. Requires `nargo` and `sunspot` on PATH and SUNSPOT_CIRCUITS_DIR set.
//
// IMPORTANT: this sends the witness to the server. Production should replace it
// with the on-device WASM prover (gnark compiled to wasm) so the voter secret
// never leaves the browser.

import { NextResponse } from "next/server";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function toToml(value: unknown): string {
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (typeof value === "bigint") return `"${value.toString()}"`;
  if (typeof value === "string") return `"${value}"`;
  if (Array.isArray(value)) return `[${value.map(toToml).join(", ")}]`;
  return `"${String(value)}"`;
}

export async function POST(req: Request) {
  let body: { circuit?: string; inputs?: Record<string, unknown> };
  try {
    body = (await req.json()) as { circuit?: string; inputs?: Record<string, unknown> };
  } catch {
    return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
  }

  const circuit = body.circuit;
  if (circuit !== "voting" && circuit !== "tally") {
    return NextResponse.json({ error: "circuit must be 'voting' or 'tally'" }, { status: 400 });
  }

  const circuitsDir = process.env.SUNSPOT_CIRCUITS_DIR;
  if (!circuitsDir) {
    return NextResponse.json({ error: "SUNSPOT_CIRCUITS_DIR is not set" }, { status: 500 });
  }

  const pkg = circuit === "voting" ? "voting_circuit" : "tally_circuit";
  const target = join(circuitsDir, "target");
  const tomlPath = join(circuitsDir, pkg, "Prover.toml");

  let original: string | null = null;
  try {
    original = readFileSync(tomlPath, "utf8");
  } catch {
    original = null;
  }

  try {
    const lines = Object.entries(body.inputs ?? {}).map(([key, value]) => `${key} = ${toToml(value)}`);
    writeFileSync(tomlPath, lines.join("\n") + "\n");

    execFileSync("nargo", ["execute", "--package", pkg], { cwd: circuitsDir, stdio: "pipe" });
    execFileSync(
      "sunspot",
      ["prove", join(target, `${pkg}.json`), join(target, `${pkg}.gz`), join(target, `${pkg}.ccs`), join(target, `${pkg}.pk`)],
      { stdio: "pipe" }
    );

    const proof = readFileSync(join(target, `${pkg}.proof`));
    return NextResponse.json({ proof: proof.toString("base64") });
  } catch (err) {
    const e = err as { stderr?: unknown; message?: string };
    const detail = typeof e?.stderr === "string" ? e.stderr : e?.message ?? String(err);
    return NextResponse.json({ error: detail }, { status: 500 });
  } finally {
    if (original !== null) writeFileSync(tomlPath, original);
  }
}
