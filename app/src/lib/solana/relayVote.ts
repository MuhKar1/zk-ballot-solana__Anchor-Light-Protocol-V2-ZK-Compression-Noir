// Client-side helper that submits a built ballot to the relayer endpoint. The
// browser generates the Groth16 proof + encrypted ballot, then sends only the
// *public* payload here; the relayer signs and pays the on-chain transaction so
// the voter's public key never appears on the explorer.

export interface RelayVoteInput {
  election: string;
  position: string;
  transcript: string;
  proof: Uint8Array;
  nullifier: Uint8Array;
  xs: Uint8Array[];
  parityBits: number;
}

export async function castVoteRelayed(input: RelayVoteInput): Promise<string> {
  const res = await fetch("/api/cast-vote", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      election: input.election,
      position: input.position,
      transcript: input.transcript,
      proof: Array.from(input.proof),
      nullifier: Array.from(input.nullifier),
      xs: input.xs.map((x) => Array.from(x)),
      parityBits: input.parityBits,
    }),
  });

  const data = (await res.json().catch(() => ({}))) as { sig?: string; error?: string };
  if (!res.ok) throw new Error(data.error ?? `relayer submit failed (HTTP ${res.status})`);
  if (!data.sig) throw new Error("relayer returned no signature");
  return data.sig;
}
