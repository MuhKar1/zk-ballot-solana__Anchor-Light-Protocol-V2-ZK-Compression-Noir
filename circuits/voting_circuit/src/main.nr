// =====================================================================================
// voting_circuit  -  the circuit that is proved every time someone votes
// =====================================================================================
//
// PUBLIC vs PRIVATE INPUTS
//   PUBLIC inputs are known to everyone, including the blockchain. The Solana program does
//   not take them from the voter: it rebuilds them from its own stored data, so a proof made
//   for different values simply fails to verify.
//   PRIVATE inputs (the "witness") stay on the voter's phone. The proof reveals nothing
//   about them except that the rules below hold.
//
// ORDER MATTERS: the order of the public inputs below is the interface ("ABI") between this
// circuit and the on-chain program. If you reorder them, change both sides.
//
//   0 merkle_root       the frozen root of the voter tree (stored on-chain)
//   1 nullifier         this voter's fingerprint for this race (new on every vote)
//   2 election_id       which election
//   3 position_id       which race inside the election
//   4 max_candidates    how many candidates this race has (stored on-chain)
//   5 pk_hash           hash of the election's public encryption key (stored on-chain)
//   6 ballot_commitment hash of the encrypted ballot being submitted
// =====================================================================================

use dep::voting_lib::{
    ballot_commitment_of, ballot_fields, DEPTH, K_MAX, leaf_of, merkle_root, nullifier_of,
    pk_hash_of, validate_choices, encrypt_slot, slot_randomness,
};
use std::embedded_curve_ops::EmbeddedCurvePoint;

fn main(
    // ---------- PUBLIC INPUTS ----------
    merkle_root_pub: pub Field,
    nullifier: pub Field,
    election_id: pub Field,
    position_id: pub Field,
    max_candidates: pub u32,
    pk_hash: pub Field,
    ballot_commitment: pub Field,
    // ---------- PRIVATE WITNESS (never leaves the voter's device) ----------
    s: Field,                // the voter's secret, derived from their passkey
    bits: [bool; DEPTH],     // left/right choices along the Merkle path
    sibs: [Field; DEPTH],    // the neighbouring hashes along the Merkle path
    choice: [bool; K_MAX],   // the one-hot vote, e.g. [false, true, false, false] = second candidate
    r_seed: Field,           // fresh secret randomness for encryption
    pk_x: Field,             // election public key, x coordinate
    pk_y: Field,             // election public key, y coordinate
) {
    // RULE 1 - ELIGIBILITY
    // "My registration value H(TAG_LEAF, S) is one of the leaves under the published root."
    // The proof shows membership without saying WHICH leaf (the path stays private).
    assert(merkle_root(leaf_of(s), bits, sibs) == merkle_root_pub);

    // RULE 2 - ONE VOTE PER RACE
    // "The nullifier I publish really is H(TAG_NULL, S, election, race)." The chain refuses to
    // record the same nullifier twice, which is what stops double voting.
    assert(nullifier_of(s, election_id, position_id) == nullifier);

    // RULE 3 - THE RIGHT KEY
    // "The encryption key I use hashes to the value stored on-chain." Without this a voter
    // could encrypt under their own key and the trustees could never count the ballot.
    assert(pk_hash_of(pk_x, pk_y) == pk_hash);
    let pk = EmbeddedCurvePoint { x: pk_x, y: pk_y };

    // RULE 4 - A VALID CHOICE
    // "I selected exactly one candidate, and it is a real one (below max_candidates)."
    validate_choices(choice, max_candidates);

    // RULE 5 - THE BALLOT IS WHAT I SAID
    // The circuit itself encrypts the choice, then proves the result hashes to the public
    // ballot_commitment. A voter therefore cannot submit a ciphertext that differs from the
    // choice that was just checked.
    let fields = ballot_fields(pk, r_seed, choice);
    assert(ballot_commitment_of(fields) == ballot_commitment);
}

// =====================================================================================
// TESTS   (run with:  nargo test --package voting_circuit)
// =====================================================================================
// Every test below calls the REAL main() above, so it exercises all five rules together.
//   "vote_*"  tests must PASS  - honest ballots are accepted.
//   "fail_*"  tests must FAIL  - each one changes exactly ONE thing and must be rejected.
// If a fail_* test ever starts passing, the circuit has a hole.
// =====================================================================================
use dep::poseidon::poseidon::bn254::hash_2;
use std::embedded_curve_ops::{
    EmbeddedCurveScalar, embedded_curve_add, fixed_base_scalar_mul, multi_scalar_mul,
};

// A made-up election secret key, used ONLY in tests for decryption and checking results.
global TEST_SK: Field = 123456789;

// W bundles every input of main() so a test can build a valid set, change one field, and run.
struct W {
    root: Field,
    nullifier: Field,
    election_id: Field,
    position_id: Field,
    max_candidates: u32,
    pk_hash: Field,
    commitment: Field,
    s: Field,
    bits: [bool; DEPTH],
    sibs: [Field; DEPTH],
    choice: [bool; K_MAX],
    r_seed: Field,
    pk_x: Field,
    pk_y: Field,
}

// Public key for a secret key:  PK = sk * G.
fn pk_for(sk: Field) -> EmbeddedCurvePoint {
    fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(sk))
}

// Builds a completely VALID set of inputs for the given choice and candidate count.
fn good(choice: [bool; K_MAX], max_candidates: u32) -> W {
    let s = 987654321;
    let mut bits = [false; DEPTH];
    let mut sibs = [0; DEPTH];
    for i in 0..DEPTH {
        bits[i] = i % 3 == 0; // mixed left/right path
        sibs[i] = 1000 + i as Field;
    }
    let pk = pk_for(TEST_SK);
    let r_seed = 55555;
    let commitment = ballot_commitment_of(ballot_fields(pk, r_seed, choice));
    W {
        root: merkle_root(leaf_of(s), bits, sibs),
        nullifier: nullifier_of(s, 7, 1),
        election_id: 7,
        position_id: 1,
        max_candidates,
        pk_hash: pk_hash_of(pk.x, pk.y),
        commitment,
        s,
        bits,
        sibs,
        choice,
        r_seed,
        pk_x: pk.x,
        pk_y: pk.y,
    }
}

// Feeds a W into the real circuit.
fn run(w: W) {
    main(
        w.root, w.nullifier, w.election_id, w.position_id, w.max_candidates, w.pk_hash,
        w.commitment, w.s, w.bits, w.sibs, w.choice, w.r_seed, w.pk_x, w.pk_y,
    );
}

// ---------- honest votes: every candidate slot, several race sizes ----------
#[test]
fn vote_slot0_k4() { run(good([true, false, false, false], 4)); }
#[test]
fn vote_slot1_k4() { run(good([false, true, false, false], 4)); }
#[test]
fn vote_slot2_k4() { run(good([false, false, true, false], 4)); }
#[test]
fn vote_slot3_k4() { run(good([false, false, false, true], 4)); }
#[test]
fn vote_slot0_k3() { run(good([true, false, false, false], 3)); }
#[test]
fn vote_slot2_k3() { run(good([false, false, true, false], 3)); }
#[test]
fn vote_single_candidate_k1() { run(good([true, false, false, false], 1)); }

// ---------- bad choices: two picks, no pick, a pick for a candidate that does not exist ----------
#[test(should_fail)]
fn fail_two_ones() { run(good([true, true, false, false], 4)); }
#[test(should_fail)]
fn fail_zero_ones() { run(good([false, false, false, false], 4)); }
#[test(should_fail)]
fn fail_one_beyond_k() { run(good([false, false, false, true], 3)); }
#[test(should_fail)]
fn fail_k_zero() { run(good([true, false, false, false], 0)); }
#[test(should_fail)]
fn fail_k_above_kmax() { run(good([true, false, false, false], 5)); }

// ---------- bad bindings: any public value that does not match the private witness ----------
#[test(should_fail)]
fn fail_wrong_root() { let mut w = good([false, true, false, false], 4); w.root += 1; run(w); }
#[test(should_fail)]
fn fail_wrong_nullifier() { let mut w = good([false, true, false, false], 4); w.nullifier += 1; run(w); }
#[test(should_fail)]
fn fail_nullifier_for_other_position() {
    let mut w = good([false, true, false, false], 4);
    w.position_id = 2; // public position changed, nullifier still for position 1
    run(w);
}
#[test(should_fail)]
fn fail_wrong_secret() { let mut w = good([false, true, false, false], 4); w.s += 1; run(w); }
#[test(should_fail)]
fn fail_wrong_pk_hash() { let mut w = good([false, true, false, false], 4); w.pk_hash += 1; run(w); }
#[test(should_fail)]
fn fail_forged_commitment() { let mut w = good([false, true, false, false], 4); w.commitment += 1; run(w); }
#[test(should_fail)]
fn fail_flipped_path_bit() { let mut w = good([false, true, false, false], 4); w.bits[0] = !w.bits[0]; run(w); }

// The voter encrypts under some OTHER key but claims the official key's hash.
#[test(should_fail)]
fn fail_ballot_under_other_key() {
    let mut w = good([false, true, false, false], 4);
    let other = pk_for(TEST_SK + 1);
    w.commitment = ballot_commitment_of(ballot_fields(other, w.r_seed, w.choice));
    run(w);
}

// The commitment is for a ballot voting candidate 3, but the proof is for candidate 2.
#[test(should_fail)]
fn fail_commitment_for_other_choice() {
    let mut w = good([false, true, false, false], 4);
    let pk = pk_for(TEST_SK);
    w.commitment = ballot_commitment_of(ballot_fields(pk, w.r_seed, [false, false, true, false]));
    run(w);
}

// ---------- cryptographic sanity checks ----------
// Poseidon must give the same answer here, in TypeScript and on Solana. If this fails, STOP.
#[test]
fn poseidon_matches_circomlib_vector() {
    assert(hash_2([1, 2]) == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a);
}

// Decrypting with the secret key must give back exactly the bit that was encrypted:
// C2 == sk*C1 + bit*G.
#[test]
fn decrypt_matches_choice() {
    let pk = pk_for(TEST_SK);
    let g = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(1));
    let choice: [bool; K_MAX] = [false, false, true, false];
    for i in 0..K_MAX {
        let r = slot_randomness(55555, i);
        let (c1, c2) = encrypt_slot(pk, r, choice[i]);
        let sk_c1 = multi_scalar_mul([c1], [EmbeddedCurveScalar::from_field(TEST_SK)]);
        let expected = if choice[i] { embedded_curve_add(sk_c1, g) } else { sk_c1 };
        assert(c2.x == expected.x);
        assert(c2.y == expected.y);
    }
}

// Different slots must use different randomness (otherwise ciphertexts leak the bits).
#[test]
fn slot_randomness_is_distinct() {
    let pk = pk_for(TEST_SK);
    let f = ballot_fields(pk, 55555, [true, false, false, false]);
    assert(f[0] != f[4]); // C1.x of slot 0 vs slot 1
    assert(f[4] != f[8]);
}

// The left/right order along the path must change the resulting root.
#[test]
fn merkle_order_matters() {
    let leaf = leaf_of(5);
    let mut bits_a = [false; DEPTH];
    let mut bits_b = [false; DEPTH];
    let mut sibs = [0; DEPTH];
    for i in 0..DEPTH { sibs[i] = 3 + i as Field; }
    bits_b[0] = true;
    assert(merkle_root(leaf, bits_a, sibs) != merkle_root(leaf, bits_b, sibs));
}