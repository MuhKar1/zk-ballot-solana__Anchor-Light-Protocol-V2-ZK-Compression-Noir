//! Ballot cryptography and the on-chain ↔ circuit ABI.
//!
//! This module is the Rust half of every value that must agree byte-for-byte with
//! the Noir circuits in `circuits/` (`voting_lib` in particular) and with Solana's
//! Poseidon syscall. Any change here must be mirrored in `circuits/voting_lib/src/lib.nr`.

use crate::{VotingError, K_MAX};
use anchor_lang::prelude::*;
use solana_poseidon::{hashv, Endianness, Parameters};

/// Flattened ballot length: K_MAX slots × 4 fields (C1.x, C1 parity, C2.x, C2 parity).
/// Mirrors `BALLOT_LEN` in `circuits/voting_lib`.
pub const BALLOT_LEN: usize = K_MAX * 4;
/// Compressed ciphertext length: K_MAX slots × 2 x-coordinates (C1.x, C2.x).
/// Mirrors `XS_LEN` in `circuits/voting_lib`.
pub const XS_LEN: usize = K_MAX * 2;
/// Domain separator for the ballot commitment fold. Mirrors `TAG_BALLOT`.
pub const TAG_BALLOT: u64 = 4;
/// Domain separator for the running tally transcript. Mirrors `TAG_TRANSCRIPT`.
pub const TAG_TRANSCRIPT: u64 = 5;
/// Number of public inputs to `voting_circuit` — must match its `main` signature order.
pub const N_PUBLIC: usize = 7;
/// Gnark public-witness size: 12-byte header + N_PUBLIC × 32-byte field values.
pub const WITNESS_LEN: usize = 12 + N_PUBLIC * 32;
/// Number of public inputs to `tally_circuit` — must match its `main` signature order.
pub const N_PUBLIC_TALLY: usize = 8;
/// Gnark public-witness size for the tally circuit.
pub const TALLY_WITNESS_LEN: usize = 12 + N_PUBLIC_TALLY * 32;
pub const BN254_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// True when `x` is a canonical BN254 field element (strictly less than the modulus).
/// Guards against modulus-aliased values that would otherwise hash to a different
/// element in the circuit than on-chain.
pub fn is_canonical(x: &[u8; 32]) -> bool {
    for i in 0..32 {
        if x[i] < BN254_MODULUS_BE[i] {
            return true;
        }
        if x[i] > BN254_MODULUS_BE[i] {
            return false;
        }
    }
    false
}

/// Encodes a `u64` as a 32-byte big-endian field element — the same encoding the
/// Noir circuits use for `pub u32`/`pub u64` inputs and the tally witness.
pub fn u64_to_field(v: u64) -> [u8; 32] {
    let mut out = [0; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// True when a 32-byte value encodes a single y-parity bit (0 or 1) in its LSB.
/// Parity is stored this way by `voting_lib::compress_point` / `expand_ballot`.
pub fn is_parity_bit(x: &[u8; 32]) -> bool {
    x[..31].iter().all(|b| *b == 0) && x[31] <= 1
}

/// Solana Poseidon(Bn254X5) two-input hash, big-endian.
/// Must equal Noir's `hash_2` (vendored `poseidon`) and `poseidon-lite`'s `poseidon2`.
fn poseidon2(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32]> {
    hashv(Parameters::Bn254X5, Endianness::BigEndian, &[a, b])
        .map(|h| h.to_bytes())
        .map_err(|_| error!(VotingError::PoseidonFailed))
}

/// H(pk_x, pk_y) — binds the election key. Matches `voting_lib::pk_hash_of`; the
/// circuit asserts this equals the voter's claimed key so ballots can't be
/// encrypted under a rogue key.
pub fn pk_hash(x: &[u8; 32], y: &[u8; 32]) -> Result<[u8; 32]> {
    poseidon2(x, y)
}

/// Rebuilds the 16-field flattened ballot from the 8 stored x-coordinates plus the
/// packed parity byte. This is the inverse of the circuit's `compress_point` layout
/// and equals `voting_lib::ballot_fields_from_xs`.
pub fn expand_ballot(xs: &[[u8; 32]; XS_LEN], parity_bits: u8) -> [[u8; 32]; BALLOT_LEN] {
    let mut out = [[0; 32]; BALLOT_LEN];
    for slot in 0..K_MAX {
        out[slot * 4] = xs[slot * 2];
        out[slot * 4 + 1][31] = (parity_bits >> (slot * 2)) & 1;
        out[slot * 4 + 2] = xs[slot * 2 + 1];
        out[slot * 4 + 3][31] = (parity_bits >> (slot * 2 + 1)) & 1;
    }
    out
}

/// Poseidon fold over all 16 ballot fields, seeded with `TAG_BALLOT`.
/// Must match `voting_lib::ballot_commitment_of`: `cast_vote` passes this value as a
/// public input to the vote proof, so any ciphertext tampering breaks verification.
pub fn ballot_commitment(ct: &[[u8; 32]; BALLOT_LEN]) -> Result<[u8; 32]> {
    let mut acc = u64_to_field(TAG_BALLOT);
    for (i, e) in ct.iter().enumerate() {
        require!(is_canonical(e), VotingError::NonCanonicalField);
        if i % 2 == 1 {
            require!(is_parity_bit(e), VotingError::BadParity);
        }
        acc = poseidon2(&acc, e)?;
    }
    Ok(acc)
}

/// Builds the voting-circuit public witness: a 12-byte header (two `u32` = N_PUBLIC)
/// followed by the 7 big-endian field values, in the **same order** as the `pub`
/// parameters of `voting_circuit::main` (root, nullifier, election_id, position_id,
/// max_candidates, pk_hash, commitment). `cast_vote` rebuilds this from its own state
/// and appends it to the proof before invoking the Sunspot verifier.
pub fn public_witness(
    root: &[u8; 32],
    nullifier: &[u8; 32],
    election_id: u64,
    position_id: u64,
    max_candidates: u8,
    key_hash: &[u8; 32],
    commitment: &[u8; 32],
) -> [u8; WITNESS_LEN] {
    let mut w = [0; WITNESS_LEN];
    w[0..4].copy_from_slice(&(N_PUBLIC as u32).to_be_bytes());
    w[8..12].copy_from_slice(&(N_PUBLIC as u32).to_be_bytes());
    let values = [
        *root,
        *nullifier,
        u64_to_field(election_id),
        u64_to_field(position_id),
        u64_to_field(max_candidates as u64),
        *key_hash,
        *commitment,
    ];
    for (i, value) in values.iter().enumerate() {
        w[12 + i * 32..12 + (i + 1) * 32].copy_from_slice(value);
    }
    w
}

/// Initial transcript value = field(`TAG_TRANSCRIPT`). Mirrors `voting_lib::transcript_init`.
/// Written into the `BallotTranscript` PDA when a position is created.
pub fn transcript_init() -> [u8; 32] {
    u64_to_field(TAG_TRANSCRIPT)
}

/// Per-ballot transcript leaf `H(nullifier, commitment)`. This is the per-vote value
/// that gets folded into the running transcript by `transcript_fold`.
pub fn transcript_leaf(nullifier: &[u8; 32], commitment: &[u8; 32]) -> Result<[u8; 32]> {
    poseidon2(nullifier, commitment)
}

/// Running transcript fold `H(acc, H(nullifier, commitment))`.
/// Must match `voting_lib::transcript_fold`: `cast_vote` folds this after every accepted
/// ballot, and `tally_circuit` re-derives the same chain to prove the tally.
pub fn transcript_fold(
    acc: &[u8; 32],
    nullifier: &[u8; 32],
    commitment: &[u8; 32],
) -> Result<[u8; 32]> {
    let leaf = transcript_leaf(nullifier, commitment)?;
    poseidon2(acc, &leaf)
}

/// Builds the tally-circuit public witness (12-byte header + 8 field values) in the
/// **same order** as the `pub` parameters of `tally_circuit::main`
/// (transcript, ballot_count, max_candidates, pk_hash, totals[0..3]). `post_tally`
/// rebuilds this from the on-chain transcript so the proof must decrypt exactly the
/// ballots the chain recorded.
pub fn tally_public_witness(
    transcript: &[u8; 32],
    ballot_count: u64,
    max_candidates: u8,
    pk_hash: &[u8; 32],
    totals: &[u64; K_MAX],
) -> [u8; TALLY_WITNESS_LEN] {
    let mut w = [0; TALLY_WITNESS_LEN];
    w[0..4].copy_from_slice(&(N_PUBLIC_TALLY as u32).to_be_bytes());
    w[8..12].copy_from_slice(&(N_PUBLIC_TALLY as u32).to_be_bytes());
    let values: [[u8; 32]; N_PUBLIC_TALLY] = [
        *transcript,
        u64_to_field(ballot_count),
        u64_to_field(max_candidates as u64),
        *pk_hash,
        u64_to_field(totals[0]),
        u64_to_field(totals[1]),
        u64_to_field(totals[2]),
        u64_to_field(totals[3]),
    ];
    for (i, value) in values.iter().enumerate() {
        w[12 + i * 32..12 + (i + 1) * 32].copy_from_slice(value);
    }
    w
}
