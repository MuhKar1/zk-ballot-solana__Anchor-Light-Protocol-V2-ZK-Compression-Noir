// Friendly mapping for the program's error codes (see the IDL `errors` array).
const BY_CODE: Record<number, string> = {
  6000: "Unauthorized administrative action",
  6001: "The voter list is already locked",
  6002: "The voter list hasn't been locked yet",
  6003: "Voting window is not open",
  6004: "Voting window has not ended",
  6005: "Invalid voting window",
  6006: "Number of voters is out of range",
  6007: "Voting has already started, so the voter list can't be locked. Start a new election with a longer “starts in” delay and lock the list before voting opens.",
  6008: "Position does not belong to this election",
  6009: "Candidate count out of bounds (1-4)",
  6010: "Value is not a canonical field element",
  6011: "A parity bit is not 0 or 1",
  6012: "Proof length out of range",
  6013: "Verifier program is not the pinned verifier",
  6014: "Address tree is not canonical",
  6015: "Not enough accounts for the Light CPI",
  6016: "Tally totals are invalid for this election",
  6017: "Tally proof length out of range",
  6018: "This position has reached its tally capacity (8 ballots)",
  6019: "Poseidon syscall failed",
};

export function errorCode(err: unknown): number | undefined {
  const e = err as {
    code?: number | string;
    message?: string;
    logs?: unknown;
    error?: { errorCode?: { code?: number | string }; code?: number | string };
  };

  // Anchor client errors expose the code in a structured way.
  const raw = e?.error?.errorCode?.code ?? e?.error?.code ?? e?.code;
  if (typeof raw === "number") return raw;
  if (typeof raw === "string" && /^\d+$/.test(raw)) return Number(raw);

  // Raw `SendTransactionError` (simulation) doesn't carry the structured code, so
  // recover it from the message / logs: "Error Number: 6007" or "custom program error: 0x1777".
  const lines = [
    e?.message ?? "",
    ...(Array.isArray(e?.logs) ? (e.logs as unknown[]).map((l) => String(l)) : []),
  ];
  const haystack = lines.join("\n");

  const errNumber = haystack.match(/Error Number:\s*(\d+)/i);
  if (errNumber) return Number(errNumber[1]);

  const hexCode = haystack.match(/custom program error:\s*0x([0-9a-fA-F]+)/i);
  if (hexCode) return parseInt(hexCode[1], 16);

  return undefined;
}

export function friendlyError(err: unknown): string {
  if (err instanceof Error && err.message) {
    const code = errorCode(err);
    if (code !== undefined && BY_CODE[code]) {
      return `${BY_CODE[code]} (${code})`;
    }
    return err.message;
  }
  return String(err);
}
