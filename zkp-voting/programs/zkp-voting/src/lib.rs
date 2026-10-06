#![allow(unexpected_cfgs)]
#![allow(deprecated)]

//! zkp_voting — the Layer-1 Anchor program.
//!
//! It stores election state, verifies the Groth16 **vote proof** (via the pinned Sunspot
//! verifier), records each accepted ballot in a **Light Protocol V2** compressed account,
//! folds a Poseidon "transcript" of accepted ballots, and finally verifies a **tally
//! proof** before publishing results. The Layer-2 logic lives in the Noir circuits
//! (`circuits/voting_circuit`, `circuits/tally_circuit`); this program only rebuilds
//! their public inputs from its own state and checks the proofs on-chain.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{instruction::Instruction, program::invoke};
use light_sdk::{
    account::LightAccount,
    address::v2::derive_address,
    constants::ADDRESS_TREE_V2,
    cpi::{v2::CpiAccounts, CpiSigner},
    derive_light_cpi_signer,
    instruction::{PackedAddressTreeInfo, ValidityProof},
    LightDiscriminator, PackedAddressTreeInfoExt,
};

pub mod ballot;
use ballot::{
    ballot_commitment, expand_ballot, is_canonical, pk_hash, public_witness, tally_public_witness,
    transcript_fold, transcript_init, XS_LEN,
};

// Keep the existing project address. Replace the verifier id after deploying the Sunspot circuit.
declare_id!("4uiu9QzRVZYdLdxCmADj6cQwFCrNufDCgU7NtsvQJWYA");

/// Program-derived signer used as the authority for the Light V2 CPI. Its seed is derived
/// from this program id, so only this program can authorize the compressed-account writes.
pub const LIGHT_CPI_SIGNER: CpiSigner = derive_light_cpi_signer!("4uiu9QzRVZYdLdxCmADj6cQwFCrNufDCgU7NtsvQJWYA");
/// Pinned voting verifier program — compiled from `circuits/target/voting_circuit.vk`.
pub const SUNSPOT_VERIFIER_ID: Pubkey = pubkey!("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
/// Pinned tally verifier program — compiled from `circuits/target/tally_circuit.vk`.
pub const SUNSPOT_TALLY_VERIFIER_ID: Pubkey = pubkey!("AjGDxunAeXevv7AWyhK4jKDsunjbAoZDxzNqGdM2iZWw");
/// Max candidates per race (and encryption slots). Mirrors `K_MAX` in `voting_lib`.
pub const K_MAX: usize = 4;
/// Merkle tree capacity 2^24 — mirrors `DEPTH = 24` in `voting_lib`.
pub const MERKLE_CAPACITY: u64 = 1 << 24;
/// Upper bound for the vote proof byte length.
pub const MAX_PROOF_LEN: usize = 512;
/// Upper bound for the tally proof byte length.
pub const MAX_TALLY_PROOF_LEN: usize = 512;

/// Rejects empty/oversized voter trees. `leaf_count` must be within the 2^24 capacity
/// implied by the circuit's `DEPTH = 24` Merkle tree.
fn validate_leaf_count(leaf_count: u64) -> Result<()> {

    require!(
        (1..=MERKLE_CAPACITY).contains(&leaf_count),
        VotingError::InvalidLeafCount
    );

    Ok(())
}

/// Structural sanity check on the posted totals **before** the tally proof is verified:
/// candidates beyond `max_candidates` must be 0, and the sum must not exceed the number
/// of eligible voters (`leaf_count`). The cryptographic binding to the actual ballots is
/// enforced afterwards by `tally_circuit` (and the `ballot_count` check in `post_tally`).
fn validate_tally_totals(totals: &[u64; K_MAX], max_candidates: u8, leaf_count: u64) -> Result<()> {
    let mut total_votes = 0u64;

    for (index, total) in totals.iter().enumerate() {
        if index >= max_candidates as usize {
            require!(*total == 0, VotingError::InvalidTally);
        }
        total_votes = total_votes
            .checked_add(*total)
            .ok_or(error!(VotingError::InvalidTally))?;
    }

    require!(total_votes <= leaf_count, VotingError::InvalidTally);

    Ok(())
}

#[program]
pub mod zkp_voting {
    use super::*;
    use light_sdk::cpi::{
        v2::LightSystemProgramCpi, InvokeLightSystemProgram, LightCpiInstruction,
    };

    /// Creates an election and stores its ElGamal public key (as `pk_hash = H(pk_x, pk_y)`)
    /// plus the voting window. No circuit is involved yet — this only sets the key the
    /// voter's `voting_circuit` proof must later commit to via `pk_hash`.
    pub fn initialize_election(
        ctx: Context<InitializeElection>,
        election_id: u64,
        pk_x: [u8; 32],
        pk_y: [u8; 32],
        vote_start_ts: i64,
        vote_end_ts: i64,
    ) -> Result<()> {
        require!(vote_start_ts < vote_end_ts, VotingError::BadWindow);
        require!(
            is_canonical(&pk_x) && is_canonical(&pk_y),
            VotingError::NonCanonicalField
        );

        let e = &mut ctx.accounts.election;
        e.authority = ctx.accounts.authority.key();
        e.election_id = election_id;
        e.is_frozen = false;
        e.frozen_root = [0; 32];
        e.leaf_count = 0;
        e.pk_x = pk_x;
        e.pk_y = pk_y;
        e.pk_hash = pk_hash(&pk_x, &pk_y)?;
        e.vote_start_ts = vote_start_ts;
        e.vote_end_ts = vote_end_ts;
        e.bump = ctx.bumps.election;

        Ok(())
    }

    /// Creates a race under an election and initializes its `BallotTranscript` PDA to the
    /// `TAG_TRANSCRIPT` domain separator. `max_candidates` must be in `1..=K_MAX`; this
    /// bound is mirrored by the circuit's `validate_choices`.
    pub fn initialize_position(
        ctx: Context<InitializePosition>,
        position_id: u64,
        max_candidates: u8,
    ) -> Result<()> {
        require!(!ctx.accounts.election.is_frozen, VotingError::AlreadyFrozen);
        require!(
            (1..=K_MAX as u8).contains(&max_candidates),
            VotingError::CandidateOutOfBounds
        );

        let p = &mut ctx.accounts.position;
        p.election = ctx.accounts.election.key();
        p.position_id = position_id;
        p.max_candidates = max_candidates;
        p.bump = ctx.bumps.position;

        let t = &mut ctx.accounts.transcript;
        t.position = ctx.accounts.position.key();
        t.transcript = transcript_init();
        t.ballot_count = 0;
        t.bump = ctx.bumps.transcript;

        Ok(())
    }

    /// Publishes the Merkle root of registered voters and freezes it before voting opens.
    /// This root becomes public input #0 of `voting_circuit`, so eligibility is fixed
    /// before any ballot is cast (no adding voters mid-election).
    pub fn freeze_voter_root(
        ctx: Context<FreezeVoterRoot>,
        root: [u8; 32],
        leaf_count: u64,
    ) -> Result<()> {
        require!(is_canonical(&root), VotingError::NonCanonicalField);
        let e = &mut ctx.accounts.election;
        require!(!e.is_frozen, VotingError::AlreadyFrozen);
        require!(
            Clock::get()?.unix_timestamp < e.vote_start_ts,
            VotingError::FreezeWindowClosed
        );

        validate_leaf_count(leaf_count)?;
        e.frozen_root = root;
        e.leaf_count = leaf_count;
        e.is_frozen = true;

        Ok(())
    }

    /// The vote entrypoint. It (1) checks the frozen/window state, (2) rebuilds the
    /// `voting_circuit` public witness from on-chain state and verifies the Groth16 proof
    /// via the pinned Sunspot verifier, (3) creates a Light V2 compressed `BallotAccount`
    /// whose address is seeded by the nullifier (so replay is structurally impossible), and
    /// (4) folds the ballot into the `BallotTranscript`. See `tests/compressed-ballot.ts`
    /// for the exact Light account/lookup-table layout and the `1_400_000` compute budget.
    pub fn cast_vote<'info>(
        ctx: Context<'_, '_, '_, 'info, CastVote<'info>>,
        proof: Vec<u8>,
        nullifier: [u8; 32],
        xs: [[u8; 32]; XS_LEN],
        parity_bits: u8,
        validity_proof: ValidityProof,
        address_tree_info: PackedAddressTreeInfo,
        output_state_tree_index: u8,
    ) -> Result<()> {
        let election = &ctx.accounts.election;
        let position = &ctx.accounts.position;
        let now = Clock::get()?.unix_timestamp;

        require!(election.is_frozen, VotingError::NotFrozen);
        require!(
            now >= election.vote_start_ts && now < election.vote_end_ts,
            VotingError::VotingClosed
        );
        require!(is_canonical(&nullifier), VotingError::NonCanonicalField);
        require!(
            !proof.is_empty() && proof.len() <= MAX_PROOF_LEN,
            VotingError::BadProofLength
        );

        let commitment = ballot_commitment(&expand_ballot(&xs, parity_bits))?;
        let witness = public_witness(
            &election.frozen_root,
            &nullifier,
            election.election_id,
            position.position_id,
            position.max_candidates,
            &election.pk_hash,
            &commitment,
        );

        let mut data = Vec::with_capacity(proof.len() + witness.len());
        data.extend_from_slice(&proof);
        data.extend_from_slice(&witness);

        let ix = Instruction {
            program_id: SUNSPOT_VERIFIER_ID,
            accounts: vec![],
            data,
        };
        invoke(&ix, &[ctx.accounts.verifier.to_account_info()])?;

        let light_accounts = CpiAccounts::new(
            ctx.accounts.payer.as_ref(),
            ctx.remaining_accounts,
            LIGHT_CPI_SIGNER,
        );

        let tree = address_tree_info
            .get_tree_pubkey(&light_accounts)
            .map_err(|_| error!(VotingError::NotEnoughAccountKeys))?;
        require!(
            tree.to_bytes() == ADDRESS_TREE_V2,
            VotingError::InvalidAddressTree
        );

        let (address, seed) = derive_address(
            &[b"nullifier", position.key().as_ref(), &nullifier],
            &tree,
            &crate::ID,
        );

        let mut account = LightAccount::<BallotAccount>::new_init(
            &crate::ID,
            Some(address),
            output_state_tree_index,
        );
        account.position = position.key().to_bytes();
        account.commitment = commitment;
        account.xs = xs;
        account.parity_bits = parity_bits;

        LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, validity_proof)
            .with_light_account(account)?
            .with_new_addresses(&[
                address_tree_info.into_new_address_params_assigned_packed(seed, Some(0))
            ])
            .invoke(light_accounts)?;

        let t = &mut ctx.accounts.transcript;
        t.transcript = transcript_fold(&t.transcript, &nullifier, &commitment)?;
        t.ballot_count = t
            .ballot_count
            .checked_add(1)
            .ok_or(error!(VotingError::InvalidTally))?;

        emit!(BallotCast {
            election: election.key(),
            position: position.key(),
            nullifier,
            xs,
            parity_bits
        });
        Ok(())
    }

    /// Publishes the final totals **only if** a `tally_circuit` proof shows they are the
    /// decryption of the ballots the chain folded into `BallotTranscript`. It rebuilds the
    /// tally witness from the on-chain transcript (not from admin-supplied data), enforces
    /// `Σtotals ≤ ballot_count`, and verifies the proof via the pinned tally verifier.
    pub fn post_tally(
        ctx: Context<PostTally>,
        totals: [u64; K_MAX],
        proof: Vec<u8>,
    ) -> Result<()> {
        require!(ctx.accounts.election.is_frozen, VotingError::NotFrozen);
        require!(
            Clock::get()?.unix_timestamp >= ctx.accounts.election.vote_end_ts,
            VotingError::VotingStillOpen
        );

        validate_tally_totals(
            &totals,
            ctx.accounts.position.max_candidates,
            ctx.accounts.election.leaf_count,
        )?;

        let transcript = &ctx.accounts.transcript;
        let total_votes = totals
            .iter()
            .try_fold(0u64, |acc, total| acc.checked_add(*total))
            .ok_or(error!(VotingError::InvalidTally))?;
        require!(
            total_votes <= transcript.ballot_count,
            VotingError::InvalidTally
        );

        require!(
            !proof.is_empty() && proof.len() <= MAX_TALLY_PROOF_LEN,
            VotingError::BadTallyProofLength
        );

        let witness = tally_public_witness(
            &transcript.transcript,
            transcript.ballot_count,
            ctx.accounts.position.max_candidates,
            &ctx.accounts.election.pk_hash,
            &totals,
        );

        let mut data = Vec::with_capacity(proof.len() + witness.len());
        data.extend_from_slice(&proof);
        data.extend_from_slice(&witness);

        let ix = Instruction {
            program_id: SUNSPOT_TALLY_VERIFIER_ID,
            accounts: vec![],
            data,
        };
        invoke(&ix, &[ctx.accounts.verifier.to_account_info()])?;

        let t = &mut ctx.accounts.tally;
        t.position = ctx.accounts.position.key();
        t.totals = totals;
        t.transcript_hash = transcript.transcript;
        t.bump = ctx.bumps.tally;

        Ok(())
    }
}

/// Election state — the ElGamal public key (stored as `pk_hash`), the voting window, and
/// the frozen voter root. `frozen_root` becomes public input #0 of `voting_circuit`.
#[account]
#[derive(InitSpace)]
pub struct ElectionConfig {
    pub authority: Pubkey,
    pub election_id: u64,
    pub is_frozen: bool,
    pub frozen_root: [u8; 32],
    pub leaf_count: u64,
    pub pk_x: [u8; 32],
    pub pk_y: [u8; 32],
    pub pk_hash: [u8; 32],
    pub vote_start_ts: i64,
    pub vote_end_ts: i64,
    pub bump: u8,
}

/// A race within an election. `max_candidates` bounds the one-hot choice the circuit's
/// `validate_choices` checks, and drives the tally witness layout.
#[account]
#[derive(InitSpace)]
pub struct PositionConfig {
    pub election: Pubkey,
    pub position_id: u64,
    pub max_candidates: u8,
    pub bump: u8,
}

/// The running tally transcript. `cast_vote` folds `H(acc, H(nullifier, commitment))` after
/// every accepted ballot; `tally_circuit` re-derives this chain and must land on `transcript`
/// with exactly `ballot_count` real ballots. This is the Layer-1 anchor for tally correctness.
#[account]
#[derive(InitSpace)]
pub struct BallotTranscript {
    pub position: Pubkey,
    pub transcript: [u8; 32],
    pub ballot_count: u64,
    pub bump: u8,
}

/// Published results. `totals` are only written after `post_tally` verifies a `tally_circuit`
/// proof, and `transcript_hash` records exactly which transcript they were proven against.
#[account]
#[derive(InitSpace)]
pub struct TallyResult {
    pub position: Pubkey,
    pub totals: [u64; K_MAX],
    pub transcript_hash: [u8; 32],
    pub bump: u8,
}

/// The data payload written into each Light V2 compressed account. `xs` + `parity_bits` are
/// the compressed ciphertext (same layout as `voting_lib::ballot_fields`), and `commitment`
/// is the Poseidon commitment the vote proof binds to.
#[event]
#[derive(Clone, Debug, Default, LightDiscriminator)]
pub struct BallotAccount {
    pub position: [u8; 32],
    pub commitment: [u8; 32],
    pub xs: [[u8; 32]; XS_LEN],
    pub parity_bits: u8,
}

/// Emitted on every accepted vote. The tally authority collects these (or the indexed
/// compressed accounts) to build the `tally_circuit` witness.
#[event]
pub struct BallotCast {
    pub election: Pubkey,
    pub position: Pubkey,
    pub nullifier: [u8; 32],
    pub xs: [[u8; 32]; XS_LEN],
    pub parity_bits: u8,
}

/// Accounts for `initialize_election` — creates the `ElectionConfig` PDA.
#[derive(Accounts)]
#[instruction(election_id: u64)]
pub struct InitializeElection<'info> {
    #[account(init, payer = authority, space = 8 + ElectionConfig::INIT_SPACE,
    seeds = [b"election", authority.key().as_ref(), &election_id.to_le_bytes()], bump)]
    pub election: Account<'info, ElectionConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Accounts for `initialize_position` — creates both the `PositionConfig` and the
/// `BallotTranscript` PDAs (the transcript is seeded from the position).
#[derive(Accounts)]
#[instruction(position_id: u64)]
pub struct InitializePosition<'info> {
    #[account(has_one = authority @ VotingError::Unauthorized)]
    pub election: Account<'info, ElectionConfig>,

    #[account(init, payer = authority, space = 8 + PositionConfig::INIT_SPACE,
    seeds = [b"position", election.key().as_ref(), &position_id.to_le_bytes()], bump)]
    pub position: Account<'info, PositionConfig>,

    #[account(init, payer = authority, space = 8 + BallotTranscript::INIT_SPACE,
    seeds = [b"transcript", position.key().as_ref()], bump)]
    pub transcript: Account<'info, BallotTranscript>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Accounts for `freeze_voter_root` — the election must be owned by the signing authority.
#[derive(Accounts)]
pub struct FreezeVoterRoot<'info> {
    #[account(mut, has_one = authority @ VotingError::Unauthorized)]
    pub election: Account<'info, ElectionConfig>,

    pub authority: Signer<'info>,
}

/// Accounts for `cast_vote`. `payer` and `remaining_accounts` feed the Light V2 CPI
/// (`CpiAccounts::new`); the `verifier` is the pinned voting verifier program.
#[derive(Accounts)]
pub struct CastVote<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(seeds = [b"election", election.authority.as_ref(), &election.election_id.to_le_bytes()], bump = election.bump)]
    pub election: Account<'info, ElectionConfig>,

    #[account(seeds = [b"position", election.key().as_ref(), &position.position_id.to_le_bytes()], bump = position.bump,
    constraint = position.election == election.key() @ VotingError::PositionMismatch)]
    pub position: Account<'info, PositionConfig>,

    #[account(mut, seeds = [b"transcript", position.key().as_ref()], bump = transcript.bump)]
    pub transcript: Account<'info, BallotTranscript>,

    /// CHECK: The address is pinned to the configured verifier and must be executable.
    #[account(address = SUNSPOT_VERIFIER_ID @ VotingError::InvalidVerifier, executable)]
    pub verifier: UncheckedAccount<'info>,
}

/// Accounts for `post_tally`. `transcript` is the Layer-1 anchor the tally must decrypt,
/// and the `verifier` is the pinned tally verifier program.
#[derive(Accounts)]
pub struct PostTally<'info> {
    #[account(has_one = authority @ VotingError::Unauthorized)]
    pub election: Account<'info, ElectionConfig>,

    #[account(constraint = position.election == election.key() @ VotingError::PositionMismatch)]
    pub position: Account<'info, PositionConfig>,

    #[account(seeds = [b"transcript", position.key().as_ref()], bump = transcript.bump)]
    pub transcript: Account<'info, BallotTranscript>,

    #[account(init, payer = authority, space = 8 + TallyResult::INIT_SPACE, seeds = [b"tally", position.key().as_ref()], bump)]
    pub tally: Account<'info, TallyResult>,

    #[account(mut)]
    pub authority: Signer<'info>,

    /// CHECK: The address is pinned to the configured tally verifier and must be executable.
    #[account(address = SUNSPOT_TALLY_VERIFIER_ID @ VotingError::InvalidVerifier, executable)]
    pub verifier: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// Program error codes. The msg strings are surfaced in Anchor logs/tests; the codes are
/// the stable identifiers used by `tests/instructions.ts` and the client suites.
#[error_code]
pub enum VotingError {
    #[msg("Unauthorized administrative action.")]
    Unauthorized,
    #[msg("Election root already frozen.")]
    AlreadyFrozen,
    #[msg("Election root has not been frozen.")]
    NotFrozen,
    #[msg("Voting window is not open.")]
    VotingClosed,
    #[msg("Voting window has not ended.")]
    VotingStillOpen,
    #[msg("Invalid voting window.")]
    BadWindow,
    #[msg("Leaf count must be between 1 and the Merkle tree capacity.")]
    InvalidLeafCount,
    #[msg("The voter root cannot be frozen after voting starts.")]
    FreezeWindowClosed,
    #[msg("Position does not belong to this election.")]
    PositionMismatch,
    #[msg("Candidate count out of bounds.")]
    CandidateOutOfBounds,
    #[msg("Value is not a canonical BN254 field element.")]
    NonCanonicalField,
    #[msg("A y-parity slot is not 0 or 1.")]
    BadParity,
    #[msg("Proof length out of range.")]
    BadProofLength,
    #[msg("Verifier program is not the pinned verifier.")]
    InvalidVerifier,
    #[msg("Address tree is not canonical.")]
    InvalidAddressTree,
    #[msg("Not enough account keys for the Light CPI.")]
    NotEnoughAccountKeys,
    #[msg("Tally totals are invalid for this election.")]
    InvalidTally,
    #[msg("Tally proof length out of range.")]
    BadTallyProofLength,
    #[msg("Poseidon syscall failed.")]
    PoseidonFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_leaf_counts_within_depth_24_capacity() {
        assert!(validate_leaf_count(1).is_ok());
        assert!(validate_leaf_count(MERKLE_CAPACITY).is_ok());
    }

    #[test]
    fn rejects_invalid_leaf_counts() {
        assert!(validate_leaf_count(0).is_err());
        assert!(validate_leaf_count(MERKLE_CAPACITY + 1).is_err());
    }

    #[test]
    fn accepts_tallies_with_abstentions() {
        assert!(validate_tally_totals(&[2, 1, 0, 0], 4, 4).is_ok());
        assert!(validate_tally_totals(&[2, 0, 0, 0], 1, 4).is_ok());
    }

    #[test]
    fn rejects_tallies_for_inactive_candidates() {
        assert!(validate_tally_totals(&[1, 0, 1, 0], 2, 4).is_err());
    }

    #[test]
    fn rejects_tallies_above_leaf_count_or_u64_capacity() {
        assert!(validate_tally_totals(&[3, 2, 0, 0], 4, 4).is_err());
        assert!(validate_tally_totals(&[u64::MAX, 1, 0, 0], 4, u64::MAX).is_err());
    }
}
