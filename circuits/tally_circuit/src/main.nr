// =====================================================================================
// tally_circuit  -  Layer 2: proves the published totals decrypt the ballots the chain
// already folded into its running transcript.
// =====================================================================================
//
// Given the transcript the Solana program built while votes were cast, the circuit:
//   1. rebuilds every ballot's Poseidon commitment from its compressed ciphertext,
//   2. folds those commitments (with their nullifiers) back into a transcript and asserts
//      it equals the public transcript,
//   3. decompresses each ciphertext point and decrypts it with the election secret key,
//   4. asserts every ballot is one-hot and sums the bits into the totals.
//
// The prover (tally authority) needs the secret key sk to decrypt, but sk stays off-chain.
//
// PUBLIC INPUT ORDER (the ABI shared with the Solana program):
//   0 transcript       the on-chain running hash of all ballots
//   1 ballot_count     number of ballots actually folded
//   2 max_candidates   how many candidates this race has
//   3 pk_hash          hash of the election public encryption key
//   4..7 totals        votes per candidate slot
// =====================================================================================
use dep::voting_lib::{
    assert_key_pair, ballot_commitment_of, ballot_fields_from_xs, decompress, decrypt_bit,
    K_MAX, parity_bit, pk_hash_of, transcript_fold, transcript_init, validate_choices, XS_LEN,
};

global N_BALLOTS: u32 = 8; // fixed circuit capacity; a larger election needs a larger setup

fn main(
    // ---------- PUBLIC INPUTS ----------
    transcript: pub Field,
    ballot_count: pub u32,
    max_candidates: pub u32,
    pk_hash: pub Field,
    totals: pub [Field; K_MAX],
    // ---------- PRIVATE WITNESS ----------
    xs: [[Field; XS_LEN]; N_BALLOTS], // compressed x-coordinates, exactly as stored on-chain
    parities: [Field; N_BALLOTS],     // packed y-parity byte per ballot (same packing as on-chain)
    ys: [[Field; XS_LEN]; N_BALLOTS], // recovered y-coordinates for decompression
    nullifiers: [Field; N_BALLOTS],   // the nullifiers folded into the transcript
    pk_x: Field,                      // election public key x (bound by pk_hash)
    pk_y: Field,                      // election public key y
    sk: Field,                        // election secret key (never leaves the tally authority)
) {
    assert(max_candidates > 0);
    assert(max_candidates <= K_MAX);
    assert(ballot_count <= N_BALLOTS);
    assert(pk_hash_of(pk_x, pk_y) == pk_hash);
    assert_key_pair(sk, pk_x, pk_y); // bind the tally secret key to the election public key

    let mut acc = transcript_init();
    let mut count: [Field; K_MAX] = [0; K_MAX];

    for i in 0..N_BALLOTS {
        let active = i < ballot_count;

        // Rebuild the on-chain commitment from the compressed ciphertext, then fold it.
        let commitment = ballot_commitment_of(ballot_fields_from_xs(xs[i], parities[i]));
        acc = if active { transcript_fold(acc, nullifiers[i], commitment) } else { acc };

        // Decrypt each slot and validate the vote is one-hot and in range.
        let mut choice: [bool; K_MAX] = [false; K_MAX];
        for j in 0..K_MAX {
            let c1 = decompress(xs[i][2 * j], ys[i][2 * j], parity_bit(parities[i], 2 * j));
            let c2 = decompress(xs[i][2 * j + 1], ys[i][2 * j + 1], parity_bit(parities[i], 2 * j + 1));
            choice[j] = decrypt_bit(sk, c1, c2);
        }
        validate_choices(choice, max_candidates);
        for j in 0..K_MAX {
            if active & choice[j] { count[j] += 1; }
        }
    }

    assert(acc == transcript);
    for j in 0..K_MAX { assert(count[j] == totals[j]); }
}

// =====================================================================================
// TESTS   (run with:  nargo test --package tally_circuit)
// =====================================================================================
use dep::voting_lib::{compress_point, encrypt_slot, slot_randomness};
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul};

global TEST_SK: Field = 123456789;

struct W {
    transcript: Field,
    ballot_count: u32,
    max_candidates: u32,
    pk_hash: Field,
    totals: [Field; K_MAX],
    xs: [[Field; XS_LEN]; N_BALLOTS],
    parities: [Field; N_BALLOTS],
    ys: [[Field; XS_LEN]; N_BALLOTS],
    nullifiers: [Field; N_BALLOTS],
    pk_x: Field,
    pk_y: Field,
    sk: Field,
}

fn pk_for(sk: Field) -> EmbeddedCurvePoint {
    fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(sk))
}

// Encrypts one ballot and returns (xs, ys, packed parity) for the circuit.
fn make_ballot(pk: EmbeddedCurvePoint, r_seed: Field, choice: [bool; K_MAX]) -> ([Field; XS_LEN], [Field; XS_LEN], Field) {
    let mut xs = [0; XS_LEN];
    let mut ys = [0; XS_LEN];
    let mut parity: u32 = 0;
    for j in 0..K_MAX {
        let (c1, c2) = encrypt_slot(pk, slot_randomness(r_seed, j), choice[j]);
        xs[2 * j] = c1.x;
        xs[2 * j + 1] = c2.x;
        ys[2 * j] = c1.y;
        ys[2 * j + 1] = c2.y;
        let (_, p1) = compress_point(c1);
        let (_, p2) = compress_point(c2);
        parity += ((p1 as u32) << (2 * j)) + ((p2 as u32) << (2 * j + 1));
    }
    (xs, ys, parity as Field)
}

fn good(choices: [[bool; K_MAX]; N_BALLOTS], ballot_count: u32, max_candidates: u32) -> W {
    let pk = pk_for(TEST_SK);
    let mut xs = [[0; XS_LEN]; N_BALLOTS];
    let mut ys = [[0; XS_LEN]; N_BALLOTS];
    let mut parities = [0; N_BALLOTS];
    let mut nullifiers = [0; N_BALLOTS];
    let mut totals = [0; K_MAX];
    let mut acc = transcript_init();
    for i in 0..N_BALLOTS {
        let active = i < ballot_count;
        // Inactive slots are padding: they are decrypted and validated like real ballots but
        // are neither folded into the transcript nor counted. Give them a valid one-hot vote.
        let ballot_choice = if active { choices[i] } else { [true, false, false, false] };
        let (bx, by, bp) = make_ballot(pk, 70000 + (i as Field), ballot_choice);
        xs[i] = bx;
        ys[i] = by;
        parities[i] = bp;
        nullifiers[i] = 5000 + (i as Field);
        if active {
            acc = transcript_fold(acc, nullifiers[i], ballot_commitment_of(ballot_fields_from_xs(bx, bp)));
            for j in 0..K_MAX { if choices[i][j] { totals[j] += 1; } }
        }
    }
    W {
        transcript: acc,
        ballot_count,
        max_candidates,
        pk_hash: pk_hash_of(pk.x, pk.y),
        totals,
        xs, ys, parities, nullifiers,
        pk_x: pk.x, pk_y: pk.y, sk: TEST_SK,
    }
}

fn run(w: W) {
    main(w.transcript, w.ballot_count, w.max_candidates, w.pk_hash, w.totals,
         w.xs, w.parities, w.ys, w.nullifiers, w.pk_x, w.pk_y, w.sk);
}

// ---------- honest tallies ----------
#[test]
fn tallies_three_ballots() {
    let mut choices = [[false; K_MAX]; N_BALLOTS];
    choices[0][0] = true;
    choices[1][1] = true;
    choices[2][2] = true;
    run(good(choices, 3, 4));
}

#[test]
fn tallies_two_votes_for_one_candidate() {
    let mut choices = [[false; K_MAX]; N_BALLOTS];
    choices[0][0] = true;
    choices[1][0] = true;
    run(good(choices, 2, 1));
}

#[test]
fn tallies_full_capacity() {
    let mut choices = [[false; K_MAX]; N_BALLOTS];
    for i in 0..N_BALLOTS { choices[i][i % 2] = true; }
    run(good(choices, N_BALLOTS, 4));
}

// ---------- bad inputs ----------
#[test(should_fail)]
fn fail_wrong_totals() {
    let mut choices = [[false; K_MAX]; N_BALLOTS];
    choices[0][0] = true;
    let mut w = good(choices, 1, 4);
    w.totals[0] += 1;
    run(w);
}

#[test(should_fail)]
fn fail_wrong_transcript() {
    let mut choices = [[false; K_MAX]; N_BALLOTS];
    choices[0][0] = true;
    let mut w = good(choices, 1, 4);
    w.transcript += 1;
    run(w);
}

#[test(should_fail)]
fn fail_two_selections() {
    let mut choices = [[false; K_MAX]; N_BALLOTS];
    choices[0][0] = true;
    choices[0][1] = true;
    run(good(choices, 1, 4));
}

#[test(should_fail)]
fn fail_ballot_count_over_capacity() {
    let mut choices = [[false; K_MAX]; N_BALLOTS];
    choices[0][0] = true;
    run(good(choices, N_BALLOTS + 1, 4));
}

#[test(should_fail)]
fn fail_wrong_secret_key() {
    let mut choices = [[false; K_MAX]; N_BALLOTS];
    choices[0][0] = true;
    let mut w = good(choices, 1, 4);
    w.sk += 1;
    run(w);
}

// An off-curve (pk_x, pk_y) must be rejected even when its hash matches the election key.
#[test(should_fail)]
fn fail_off_curve_pk() {
    let mut choices = [[false; K_MAX]; N_BALLOTS];
    choices[0][0] = true;
    let mut w = good(choices, 1, 4);
    w.pk_x = 5;
    w.pk_y = 1; // (5, 1) is not on the Grumpkin curve
    w.pk_hash = pk_hash_of(5, 1);
    run(w);
}

// ---------- cryptographic sanity checks ----------
#[test]
fn grumpkin_generator_satisfies_curve() {
    let g = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(1));
    assert(g.x == 1);
    assert(g.y * g.y == g.x * g.x * g.x - 17);
}

#[test]
fn decompress_and_decrypt_roundtrip() {
    let pk = pk_for(TEST_SK);
    let choice: [bool; K_MAX] = [false, true, false, false];
    for j in 0..K_MAX {
        let (c1, c2) = encrypt_slot(pk, slot_randomness(55555, j), choice[j]);
        let (c1x, c1p) = compress_point(c1);
        let (c2x, c2p) = compress_point(c2);
        assert(decompress(c1x, c1.y, c1p).y == c1.y);
        assert(decompress(c2x, c2.y, c2p).x == c2.x);
        assert(decrypt_bit(TEST_SK, c1, c2) == choice[j]);
    }
}
