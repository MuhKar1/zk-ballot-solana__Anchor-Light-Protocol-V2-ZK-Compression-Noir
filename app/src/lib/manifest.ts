// The "election manifest" — everything a voter needs to cast a ballot, published
// by the admin after freezing the voter root. The voter re-checks `root` against
// the on-chain frozen root, so an untrusted manifest can't smuggle voters in.
//
// An election holds one or more positions (races). Each position has its own
// aspirant list (candidate names) whose slot order is the on-chain encryption
// slot index, capped at 4 by `K_MAX`.

export interface ManifestPosition {
  /** On-chain position id (decimal string). */
  positionId: string;
  /** Display name, e.g. "President". */
  title: string;
  /** Number of active encryption slots (must equal `candidates.length`, <= 4). */
  maxCandidates: number;
  /** Aspirant names in slot order. */
  candidates: string[];
}

export interface ElectionManifest {
  electionId: string;
  /** Admin authority pubkey (to derive the election PDA). */
  authority: string;
  /** Frozen Merkle root (0x-prefixed). */
  root: string;
  /** ElGamal public key, full point (x, y) as 0x-prefixed field hex. */
  pkX: string;
  pkY: string;
  /** H(pk_x, pk_y). */
  pkHash: string;
  /** Registered leaves (0x-prefixed), in fixed order. */
  leaves: string[];
  voteStartTs: number;
  voteEndTs: number;
  /** The races in this election. */
  positions: ManifestPosition[];
}

const REQUIRED = [
  "electionId",
  "authority",
  "root",
  "pkX",
  "pkY",
  "pkHash",
  "leaves",
  "voteStartTs",
  "voteEndTs",
] as const;

function asString(raw: Record<string, unknown>, key: string): string {
  const v = raw[key];
  if (v === undefined || v === null || v === "") {
    throw new Error(`manifest missing field: ${key}`);
  }
  return String(v);
}

function parsePositions(raw: Record<string, unknown>): ManifestPosition[] {
  // v2: explicit `positions` array.
  if (Array.isArray(raw.positions) && raw.positions.length > 0) {
    const seen = new Set<string>();
    return (raw.positions as unknown[]).map((p, i) => {
      const obj = (p ?? {}) as Record<string, unknown>;
      const positionId = String(obj.positionId ?? "");
      if (!positionId) throw new Error(`positions[${i}] missing positionId`);
      if (seen.has(positionId)) throw new Error(`duplicate positionId: ${positionId}`);
      seen.add(positionId);

      const title = String(obj.title ?? `Position ${i + 1}`);
      const candidates = Array.isArray(obj.candidates)
        ? obj.candidates.map((c) => String(c).trim()).filter(Boolean)
        : [];
      if (candidates.length < 1) throw new Error(`position "${title}" has no aspirants`);
      if (candidates.length > 4) throw new Error(`position "${title}" has more than 4 aspirants`);

      const maxCandidates =
        obj.maxCandidates === undefined ? candidates.length : Number(obj.maxCandidates);
      if (maxCandidates !== candidates.length) {
        throw new Error(`position "${title}": maxCandidates must equal the aspirant count`);
      }
      return { positionId, title, maxCandidates, candidates };
    });
  }

  // v1 fallback: a single legacy position.
  const positionId = asString(raw, "positionId");
  if (!Array.isArray(raw.candidates) || raw.candidates.length === 0) {
    throw new Error("manifest has no aspirants");
  }
  const candidates = raw.candidates.map((c) => String(c).trim()).filter(Boolean);
  if (candidates.length > 4) throw new Error("position has more than 4 aspirants");
  return [
    {
      positionId,
      title: "Position",
      maxCandidates: raw.maxCandidates === undefined ? candidates.length : Number(raw.maxCandidates),
      candidates,
    },
  ];
}

export function parseManifest(json: string): ElectionManifest {
  const raw = JSON.parse(json) as Record<string, unknown>;
  for (const key of REQUIRED) asString(raw, key);
  if (!Array.isArray(raw.leaves) || raw.leaves.length === 0) {
    throw new Error("manifest has no leaves");
  }
  return {
    electionId: asString(raw, "electionId"),
    authority: asString(raw, "authority"),
    root: asString(raw, "root"),
    pkX: asString(raw, "pkX"),
    pkY: asString(raw, "pkY"),
    pkHash: asString(raw, "pkHash"),
    leaves: raw.leaves as string[],
    voteStartTs: Number(raw.voteStartTs),
    voteEndTs: Number(raw.voteEndTs),
    positions: parsePositions(raw),
  };
}
