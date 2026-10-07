// Static, network-wide configuration. Values can be overridden via
// NEXT_PUBLIC_* env vars (see .env.local.example). These must match the
// deployed on-chain program and the pinned Sunspot verifier programs.

export const PROGRAM_ID =
  process.env.NEXT_PUBLIC_PROGRAM_ID ?? "4uiu9QzRVZYdLdxCmADj6cQwFCrNufDCgU7NtsvQJWYA";

export const VOTING_VERIFIER_ID =
  process.env.NEXT_PUBLIC_VOTING_VERIFIER_ID ?? "9jjgdh8kXLqZEkAGYjXTXsXGQeGALJ6YYKn5Gz3KXgYj";

export const TALLY_VERIFIER_ID =
  process.env.NEXT_PUBLIC_TALLY_VERIFIER_ID ?? "AuSPaahFzAViTokdyhc6fYNe1gELiHRksbExo2YNptav";

export const ADDRESS_TREE_V2 =
  process.env.NEXT_PUBLIC_ADDRESS_TREE_V2 ?? "amt2kaJA14v3urZbZvnc5v2np8jqvc4Z8zDep5wbtzx";

export const RPC_URL = process.env.NEXT_PUBLIC_RPC_URL ?? "http://127.0.0.1:8899";
export const LIGHT_INDEXER_URL =
  process.env.NEXT_PUBLIC_LIGHT_INDEXER_URL ?? "http://127.0.0.1:8784";
export const LIGHT_PROVER_URL =
  process.env.NEXT_PUBLIC_LIGHT_PROVER_URL ?? "http://127.0.0.1:3001";
