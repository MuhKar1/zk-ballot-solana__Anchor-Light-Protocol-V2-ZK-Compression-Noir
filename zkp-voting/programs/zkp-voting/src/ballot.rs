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

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a 64-char hex string into a 32-byte field element (no external crates).
    fn field(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64, "field hex must be 64 chars");
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex");
        }
        out
    }

    // Poseidon(Bn254X5) must match the Noir/circomlib reference vector.
    #[test]
    fn poseidon_matches_circomlib_vector() {
        let h = poseidon2(&u64_to_field(1), &u64_to_field(2)).unwrap();
        assert_eq!(
            h,
            field("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a")
        );
    }

    // pk_hash must match the deterministic fixture (pk = 1*G, sk = 1).
    #[test]
    fn pk_hash_matches_noir_vector() {
        let gy = field("0000000000000002cf135e7506a45d632d270d45f1181294833fc48d823f272c");
        let h = pk_hash(&u64_to_field(1), &gy).unwrap();
        assert_eq!(
            h,
            field("1b2231fbfcbdc8e78a98d738945989141683623400dafa121b10cd8e00b9b395")
        );
    }

    // ballot_commitment must match the deterministic ballot fixture
    // (pk = 1*G, r_seed = 55555, choice = [0,1,0,0], parity = 199).
    #[test]
    fn ballot_commitment_matches_noir_vector() {
        let xs = [
            field("10b75300c2fa898983b5dbc432f4dcb67ad1352c61464d83286eb07611bc2f4a"),
            field("10b75300c2fa898983b5dbc432f4dcb67ad1352c61464d83286eb07611bc2f4a"),
            field("1de875a73f5c453cebfef531032933621f90d81b8788db882042d983384669f9"),
            field("1eeac3200ad7a653e10dc6ac33efbde32b1188c25013f22ff2f2a032e95b4b2f"),
            field("25be218c110eb15d70f7165495d7c003ee3c6df9312423b0c26bd5289b55498c"),
            field("25be218c110eb15d70f7165495d7c003ee3c6df9312423b0c26bd5289b55498c"),
            field("0c25b8cecce4164af847a77d7b8c4dffcb074b934b813c8d071bb828f758d876"),
            field("0c25b8cecce4164af847a77d7b8c4dffcb074b934b813c8d071bb828f758d876"),
        ];
        let commitment = ballot_commitment(&expand_ballot(&xs, 199)).unwrap();
        assert_eq!(
            commitment,
            field("214c2146b7f84ae19622a3adf2e0c647bd41c241669013c8ae5305c087b23dc4")
        );
    }

    // expand_ballot must interleave x at even indices and parity bits at odd indices' LSB.
    #[test]
    fn expand_ballot_places_x_and_parity() {
        let mut xs = [[0u8; 32]; XS_LEN];
        for (i, x) in xs.iter_mut().enumerate() {
            x[31] = (i + 1) as u8;
        }
        let parity: u8 = 0b1010_0101;
        let ct = expand_ballot(&xs, parity);
        for slot in 0..K_MAX {
            assert_eq!(ct[slot * 4], xs[slot * 2]);
            assert_eq!(ct[slot * 4 + 2], xs[slot * 2 + 1]);
            assert_eq!(ct[slot * 4 + 1][31], (parity >> (slot * 2)) & 1);
            assert_eq!(ct[slot * 4 + 3][31], (parity >> (slot * 2 + 1)) & 1);
            assert!(ct[slot * 4 + 1][..31].iter().all(|b| *b == 0));
            assert!(ct[slot * 4 + 3][..31].iter().all(|b| *b == 0));
        }
    }

    #[test]
    fn ballot_commitment_rejects_non_canonical_field() {
        let mut ct = [[0u8; 32]; BALLOT_LEN];
        ct[0] = BN254_MODULUS_BE; // the modulus itself is non-canonical
        assert!(ballot_commitment(&ct).is_err());
    }

    #[test]
    fn ballot_commitment_rejects_bad_parity() {
        let mut ct = [[0u8; 32]; BALLOT_LEN];
        ct[1][31] = 2; // odd index (parity slot) must be 0 or 1
        assert!(ballot_commitment(&ct).is_err());
    }

    #[test]
    fn public_witness_header_and_order() {
        let root = u64_to_field(111);
        let nullifier = u64_to_field(222);
        let key_hash = u64_to_field(444);
        let commitment = u64_to_field(333);
        let w = public_witness(&root, &nullifier, 7, 1, 4, &key_hash, &commitment);
        assert!(w[0..4] == (N_PUBLIC as u32).to_be_bytes());
        assert!(w[8..12] == (N_PUBLIC as u32).to_be_bytes());
        assert_eq!(&w[12..44], &root[..]);
        assert_eq!(&w[44..76], &nullifier[..]);
        assert_eq!(&w[76..108], &u64_to_field(7)[..]);
        assert_eq!(&w[108..140], &u64_to_field(1)[..]);
        assert_eq!(&w[140..172], &u64_to_field(4)[..]);
        assert_eq!(&w[172..204], &key_hash[..]);
        assert_eq!(&w[204..236], &commitment[..]);
    }

    #[test]
    fn tally_public_witness_header_and_order() {
        let transcript = u64_to_field(999);
        let key_hash = u64_to_field(888);
        let totals = [1u64, 2, 3, 4];
        let w = tally_public_witness(&transcript, 8, 4, &key_hash, &totals);
        assert!(w[0..4] == (N_PUBLIC_TALLY as u32).to_be_bytes());
        assert!(w[8..12] == (N_PUBLIC_TALLY as u32).to_be_bytes());
        assert_eq!(&w[12..44], &transcript[..]);
        assert_eq!(&w[44..76], &u64_to_field(8)[..]);
        assert_eq!(&w[76..108], &u64_to_field(4)[..]);
        assert_eq!(&w[108..140], &key_hash[..]);
        assert_eq!(&w[140..172], &u64_to_field(1)[..]);
        assert_eq!(&w[172..204], &u64_to_field(2)[..]);
        assert_eq!(&w[204..236], &u64_to_field(3)[..]);
        assert_eq!(&w[236..268], &u64_to_field(4)[..]);
    }
}
