// =====================================================================================
// voting_lib  -  shared building blocks for the ZKP voting system
// =====================================================================================
//
// Every cryptographic primitive used by the voting circuits lives here, so ballot_encoder,
// voting_circuit (and any future circuit) all use byte-for-byte identical logic. If these
// were implemented twice they would become two incompatible "dialects" of the protocol.
//
// The scheme in one sentence: a voter proves they own a leaf in a Merkle tree of registered
// voters, publishes a one-time nullifier to stop double voting, and submits an
// ElGamal-encrypted ballot (one ciphertext per candidate slot) whose Poseidon commitment
// is recorded on-chain.

use dep::poseidon::poseidon::bn254::{hash_2, hash_3, hash_4};
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, embedded_curve_add, fixed_base_scalar_mul, multi_scalar_mul};

// ---------- system parameters ----------
pub global DEPTH: u32 = 24;      // Merkle tree depth: supports up to 2^24 registered voters
pub global K_MAX: u32 = 4;       // max candidates per race (also the number of encryption slots)
pub global BALLOT_LEN: u32 = 16; // K_MAX * 4 fields per ballot (x and y-parity for C1 and C2 per slot)
pub global XS_LEN: u32 = 8;      // K_MAX * 2 compressed points per ballot (C1.x and C2.x per slot)

// Domain-separation tags. Hashing one of these first means the same underlying value
// (e.g. the voter secret s) yields completely different hashes in each role, so a leaf
// can never be mistaken for a nullifier, slot randomness, or a ballot commitment.
pub global TAG_LEAF: Field = 1;
pub global TAG_NULL: Field = 2;
pub global TAG_RAND: Field = 3;
pub global TAG_BALLOT: Field = 4;
pub global TAG_TRANSCRIPT: Field = 5;

// A voter's leaf in the registration tree: H(TAG_LEAF, secret). The secret s is derived
// from the voter's passkey and is known only to the voter.
pub fn leaf_of(s: Field) -> Field { hash_2([TAG_LEAF, s]) }

// The one-time nullifier: H(TAG_NULL, secret, election, race). It is unique per
// (voter, election, race), so the chain rejects any second vote that reuses this value.
pub fn nullifier_of(s: Field, election_id: Field, position_id: Field) -> Field {
    hash_4([TAG_NULL, s, election_id, position_id])
}

// Commitment to the election public key: H(pk_x, pk_y). Stored on-chain so a voter is
// forced to encrypt under the official key (otherwise the trustees could not decrypt).
pub fn pk_hash_of(pk_x: Field, pk_y: Field) -> Field { hash_2([pk_x, pk_y]) }

// Recomputes a Merkle root from a leaf and an authentication path.
//   bits[i] == false -> the running value is the LEFT child at level i; true -> RIGHT child.
// At each level the sibling is hashed together with the running value, which is exactly
// the standard Merkle inclusion proof: a valid path lands back on the published root.
pub fn merkle_root(leaf: Field, bits: [bool; DEPTH], sibs: [Field; DEPTH]) -> Field {
    let mut cur = leaf; // start from the leaf and walk up toward the root
    for i in 0..DEPTH {
        // Order the pair as (left, right) according to this level's path bit.
        let (l, r) = if bits[i] { (sibs[i], cur) } else { (cur, sibs[i]) };
        cur = hash_2([l, r]); // hash this level's children into the parent value
    }
    cur // after DEPTH levels this is the root
}

// One-hot validation: exactly one candidate selected, and it must be a real one.
pub fn validate_choices(choice: [bool; K_MAX], max_candidates: u32) {
    assert(max_candidates > 0);      // the race must have at least one candidate
    assert(max_candidates <= K_MAX); // and no more than the circuit can encode
    let mut sum: Field = 0;
    for i in 0..K_MAX {
        sum += if choice[i] { 1 } else { 0 }; // count how many candidates were selected
        if i >= max_candidates { assert(!choice[i]); } // cannot pick a candidate that does not exist
    }
    assert(sum == 1); // exactly one selection
}

// Per-slot randomness: r_i = H(TAG_RAND, r_seed, i). Deriving a fresh r per slot from a
// single seed means the voter only remembers one secret, yet every slot gets independent
// randomness so ciphertexts do not leak which slots share a bit.
pub fn slot_randomness(r_seed: Field, i: u32) -> Field {
    let r = hash_3([TAG_RAND, r_seed, i as Field]);
    assert(r != 0); // r = 0 would make C1 the point at infinity and leak the encrypted bit
    r
}

// ElGamal (exponential variant) encryption of a single bit under public key pk:
//   C1 = r * G
//   C2 = r * PK + bit * G
// Decryption recovers bit*G by computing C2 - sk*C1, which equals G when bit == 1 and
// the point at infinity when bit == 0. The 0/1 message is hidden inside the group.
pub fn encrypt_slot(pk: EmbeddedCurvePoint, r: Field, bit: bool) -> (EmbeddedCurvePoint, EmbeddedCurvePoint) {
    let r_scalar = EmbeddedCurveScalar::from_field(r);              // interpret the field element as a scalar
    let g = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(1)); // the generator point G = 1 * G
    let c1 = fixed_base_scalar_mul(r_scalar);                       // C1 = r * G
    let shared = multi_scalar_mul([pk], [r_scalar]);                // shared secret point = r * PK
    let with_msg = embedded_curve_add(shared, g);                   // r * PK + G  (encodes bit = 1)
    let c2 = if bit { with_msg } else { shared };                   // C2 = r * PK + bit * G
    (c1, c2)
}

// Compresses a curve point to (x, parity of y). Storing two fields per point keeps the
// on-chain representation compact; the full y can be recovered from x and the parity bit.
pub fn compress_point(p: EmbeddedCurvePoint) -> (Field, Field) {
    let y_bits: [bool; 254] = p.y.to_le_bits(); // little-endian bits, so bit 0 is the parity
    (p.x, if y_bits[0] { 1 } else { 0 })        // (x, 1 if y is odd else 0)
}

// Encrypts every candidate slot and flattens the result into 4 fields per slot:
//   [C1.x, C1.y-parity, C2.x, C2.y-parity] for slot 0, then slot 1, and so on.
// A vote for candidate j encrypts bit 1 in slot j and bit 0 everywhere else, so the
// ballot is a vector of encryptions that reveals nothing about which slot holds the "1".
pub fn ballot_fields(pk: EmbeddedCurvePoint, r_seed: Field, choice: [bool; K_MAX]) -> [Field; BALLOT_LEN] {
    let mut out: [Field; BALLOT_LEN] = [0; BALLOT_LEN];
    for i in 0..K_MAX {
        let (c1, c2) = encrypt_slot(pk, slot_randomness(r_seed, i), choice[i]);
        let (c1x, c1p) = compress_point(c1);
        let (c2x, c2p) = compress_point(c2);
        out[i * 4] = c1x;     // slot i: C1.x
        out[i * 4 + 1] = c1p; // slot i: C1.y parity
        out[i * 4 + 2] = c2x; // slot i: C2.x
        out[i * 4 + 3] = c2p; // slot i: C2.y parity
    }
    out
}

// Commitment to the whole ballot: a single Poseidon hash folded over all 16 fields,
// seeded with TAG_BALLOT. Storing this one value on-chain binds the published ciphertext
// to the proven vote (changing any single field changes the commitment).
pub fn ballot_commitment_of(fields: [Field; BALLOT_LEN]) -> Field {
    let mut acc = TAG_BALLOT; // domain-separated starting value
    for j in 0..BALLOT_LEN { acc = hash_2([acc, fields[j]]); } // fold each field in
    acc
}

// Extracts bit k from a packed y-parity byte (the same u8 packing the Solana program stores).
pub fn parity_bit(parity_bits: Field, k: u32) -> Field {
    ((parity_bits as u32 >> k) & 1) as Field
}

// Rebuilds the 16-field flattened ballot (x and y-parity per ciphertext) from the compact
// on-chain representation (8 x-coordinates plus one packed parity byte).
pub fn ballot_fields_from_xs(xs: [Field; XS_LEN], parity_bits: Field) -> [Field; BALLOT_LEN] {
    let mut out = [0; BALLOT_LEN];
    for slot in 0..K_MAX {
        out[slot * 4] = xs[slot * 2];
        out[slot * 4 + 1] = parity_bit(parity_bits, slot * 2);
        out[slot * 4 + 2] = xs[slot * 2 + 1];
        out[slot * 4 + 3] = parity_bit(parity_bits, slot * 2 + 1);
    }
    out
}

// Recovers the full curve point from a compressed (x, y-parity) pair. Verifies the point is
// on the Grumpkin curve (y^2 = x^3 - 17) and has the advertised parity.
pub fn decompress(x: Field, y: Field, parity: Field) -> EmbeddedCurvePoint {
    assert(y * y == x * x * x - 17);
    let p = EmbeddedCurvePoint { x, y };
    let (_, p_parity) = compress_point(p);
    assert(p_parity == parity);
    p
}

// Validates that (x, y) is on the Grumpkin curve (y^2 = x^3 - 17) and returns it as a point.
// Used to reject an off-curve public key that would otherwise still hash to a valid pk_hash.
pub fn pk_point(x: Field, y: Field) -> EmbeddedCurvePoint {
    assert(y * y == x * x * x - 17);
    EmbeddedCurvePoint { x, y }
}

// Binds the tally secret key to the election public key: PK must equal sk * G. Without this
// a tally authority could decrypt with a mismatched key and the decrypted bits would be garbage.
pub fn assert_key_pair(sk: Field, pk_x: Field, pk_y: Field) {
    let pk = pk_point(pk_x, pk_y);
    let g = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(sk));
    assert((g.x == pk.x) & (g.y == pk.y));
}

// Decrypts an ElGamal ciphertext slot: C2 must equal sk*C1 (bit 0) or sk*C1 + G (bit 1).
pub fn decrypt_bit(sk: Field, c1: EmbeddedCurvePoint, c2: EmbeddedCurvePoint) -> bool {
    let sk_c1 = multi_scalar_mul([c1], [EmbeddedCurveScalar::from_field(sk)]);
    let g = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(1));
    let one = embedded_curve_add(sk_c1, g);
    let is_zero = (c2.x == sk_c1.x) & (c2.y == sk_c1.y);
    let is_one = (c2.x == one.x) & (c2.y == one.y);
    assert(is_zero | is_one);
    is_one
}

// The running transcript hash. It starts at TAG_TRANSCRIPT and folds every cast ballot in,
// in the order the votes arrived: acc = H(acc, H(nullifier, commitment)).
pub fn transcript_init() -> Field { TAG_TRANSCRIPT }

pub fn transcript_fold(acc: Field, nullifier: Field, commitment: Field) -> Field {
    hash_2([acc, hash_2([nullifier, commitment])])
}