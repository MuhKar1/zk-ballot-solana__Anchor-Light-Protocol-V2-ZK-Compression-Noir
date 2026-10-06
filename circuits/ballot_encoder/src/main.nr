// =====================================================================================
// ballot_encoder  -  builds the encrypted ballot and its commitment for one race
// =====================================================================================
//
// This circuit is the "ballot maker". It does NOT check eligibility or prevent double
// voting; voting_circuit does that. Its narrower job is: given a voter's choice and
// fresh randomness, encrypt the choice under the election public key and return the
// serialized ciphertext plus a single commitment to it.
//
// PUBLIC OUTPUT - 17 fields, in this exact order (it is this circuit's ABI):
//   [0..15]  the 16-field serialized ciphertext produced by ballot_fields
//            (4 fields per candidate slot: C1.x, C1.y-parity, C2.x, C2.y-parity)
//   [16]     the Poseidon commitment to those 16 fields
//
// Why return both? The commitment is what gets anchored on-chain; the ciphertext itself
// is published alongside and must hash back to the commitment, which binds the encrypted
// vote to this proven choice.

use dep::voting_lib::{ballot_commitment_of, ballot_fields, BALLOT_LEN, K_MAX, validate_choices};
use std::embedded_curve_ops::EmbeddedCurvePoint;

fn main(
    pk_x: Field,           // election public key, x coordinate
    pk_y: Field,           // election public key, y coordinate
    choice: [bool; K_MAX], // one-hot vote: exactly one `true`, e.g. [false, true, false, false]
    r_seed: Field,         // fresh secret randomness seed for encryption
    max_candidates: u32,   // number of real candidates in this race (must be <= K_MAX)
) -> pub [Field; 17] {
    // Reject a malformed vote: not exactly one candidate, or one beyond max_candidates.
    validate_choices(choice, max_candidates);

    // Reassemble the election public key as a curve point so it can be used to encrypt.
    let pk = EmbeddedCurvePoint { x: pk_x, y: pk_y };

    // Encrypt every candidate slot and flatten it into the 16-field serialized layout.
    let fields = ballot_fields(pk, r_seed, choice);

    // Assemble the public output: the 16 ciphertext fields, then their commitment.
    let mut out: [Field; 17] = [0; 17];
    for i in 0..BALLOT_LEN { out[i] = fields[i]; }
    out[BALLOT_LEN] = ballot_commitment_of(fields);
    out
}