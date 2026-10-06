# ZKP Voting System

A trustless, zero-knowledge voting system on Solana. Ballots are **ElGamal-encrypted**
and stored as **ZK-compressed accounts**, so a vote is private and cheap. A
**Groth16 circuit** proves each ballot is cast by an eligible voter exactly once,
and a second circuit proves that the published **tally is the correct decryption**
of the ballots the chain actually recorded — so the election administrator cannot
stuff, flip, or forge votes without being detected.

---

## Table of contents

1. [Overview](#overview)
2. [Trust model at a glance](#trust-model-at-a-glance)
3. [Architecture](#architecture)
4. [Repository layout](#repository-layout)
5. [The protocol in detail](#the-protocol-in-detail)
6. [Layer 1 — the Solana program](#layer-1--the-solana-program)
7. [Layer 2 — the circuits](#layer-2--the-circuits)
8. [Tally correctness (the trustless part)](#tally-correctness-the-trustless-part)
9. [Design decisions](#design-decisions)
10. [Security model & threat analysis](#security-model--threat-analysis)
11. [Prerequisites](#prerequisites)
12. [Build & test runbook](#build--test-runbook)
13. [Developer workflow](#developer-workflow)
14. [Configuration reference](#configuration-reference)
15. [Frontend integration (planned)](#frontend-integration-planned)
16. [Known limitations](#known-limitations)
17. [Troubleshooting](#troubleshooting)
18. [Disclaimer](#disclaimer)

---

## Overview

The system is split into two layers that reinforce each other:

- **Layer 1 (on-chain)** — an Anchor Solana program (`zkp_voting`) that manages
  elections, freezes the registered-voter Merkle root, accepts ballots via the
  Light Protocol V2 ZK-compression stack, and — after the last change — also
  **re-derives a transcript** of every ballot so a tally can be checked.
- **Layer 2 (off-chain circuits)** — Noir circuits compiled to Groth16 and
  verified on-chain through **Sunspot** verifier programs:
  - `voting_circuit` — proves a ballot is valid (eligibility, one-vote,
    right key, one-hot choice, committed ciphertext).
  - `tally_circuit` — proves the published `totals` are the decryption of the
    exact set of ballots the chain folded into its transcript.

A voter's **secret (`s`) never leaves their device**; the ballot is only ever
published in encrypted form. The election secret key (`sk`) stays **off-chain**
with the tally authority, but because the tally is re-derived by a verified
circuit, a dishonest (or compromised) administrator cannot publish fake totals.

> **Status:** the protocol and test suite are complete and green. A frontend is
> planned but not yet present — see [Frontend integration](#frontend-integration-planned).

## Trust model at a glance

| Component | Who trusts what | Mitigation |
|---|---|---|
| Voter eligibility | The frozen Merkle root (published by the admin before voting) | `voting_circuit` proves membership without revealing the leaf |
| One vote per voter | The nullifier is unique per `(secret, election, position)` | On-chain replay is impossible: the nullifier is part of the compressed-account seed |
| Ballot integrity | The ciphertext a voter publishes matches their proven choice | `voting_circuit` re-encrypts the choice and binds its commitment |
| Ballot privacy | Ciphertexts are ElGamal; only `sk` decrypts them | `sk` is never on-chain; ballots are ZK-compressed |
| Tally correctness | The admin posts `totals` | Layer-1 transcript + `tally_circuit` re-derive the tally on-chain |
| Verifier programs | Groth16 verifying keys are correct | Pinned program IDs; keys are compiled into the verifier `.so` |

**What remains trusted:** the **unsafe trusted setup** used to generate proving
keys (fine for local testing, not for production), and the **Light Protocol
validators/prover** for ZK compression (standard infrastructure trust).

---

## Architecture

```
                 Voter (browser/CLI, future frontend)
      passkey → secret s → leaf, nullifier, ElGamal ballot
      proves voting_circuit (Noir → Groth16, via Sunspot)
                              │  proof + ciphertext (xs + parity) + nullifier
                              ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                    Solana program: zkp_voting  (Layer 1)                    │
│                                                                            │
│  initialize_election   create election (pk, window)                        │
│  initialize_position   create position + transcript PDA                    │
│  freeze_voter_root     publish Merkle root + leaf count (before voting)    │
│  cast_vote             verify voting proof → fold transcript → Light CPI   │
│  post_tally            verify tally proof → store totals                   │
└───────────────┬───────────────────────────────────┬────────────────────────┘
                │ CPI (Light V2)                    │ invoke (Sunspot)
                ▼                                   ▼
   Light Protocol V2                      Sunspot Groth16 verifiers
   (one compressed BallotAccount        voting verifier  3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3
    per ballot, indexed off-chain)      tally  verifier  AjGDxunAeXevv7AWyhK4jKDsunjbAoZDxzNqGdM2iZWw

        Off-chain (Noir workspace, circuits/)
        voting_lib  →  voting_circuit, ballot_encoder, tally_circuit
```

Two proofs are generated off-chain and verified on-chain:

1. **Vote proof** — per ballot, generated on the voter's device.
2. **Tally proof** — once per position, generated by the tally authority (who
   holds `sk`) from the ballots the chain already recorded.

---

## Repository layout

```
ZKP-Voting-System/
├── circuits/                        # Noir workspace (Layer 2)
│   ├── Nargo.toml                   # workspace members
│   ├── voting_lib/                  # shared primitives (hash, EC, transcript)
│   │   └── src/lib.nr
│   ├── voting_circuit/              # the per-vote proof (5 rules)
│   │   ├── Nargo.toml
│   │   ├── Prover.toml              # empty input template (kept)
│   │   └── src/main.nr              # + 25 nargo tests
│   ├── ballot_encoder/              # computes a ciphertext from (pk, choice, r)
│   │   ├── Nargo.toml
│   │   ├── Prover.toml              # empty input template (kept)
│   │   └── src/main.nr
│   ├── tally_circuit/               # the tally-correctness proof (Layer 2)
│   │   ├── Nargo.toml
│   │   └── src/main.nr              # + 10 nargo tests
│   ├── target/                      # build artifacts (gitignored, regenerated)
│   └── vendor/poseidon/             # vendored Noir Poseidon (circomlib-compatible)
│
└── zkp-voting/                      # Anchor project (Layer 1 + tests)
    ├── Anchor.toml
    ├── Cargo.toml / Cargo.lock
    ├── package.json                 # npm scripts
    ├── programs/zkp-voting/
    │   └── src/{lib.rs, ballot.rs}
    ├── client/                      # off-chain JS helpers
    │   ├── tree.mjs                 # Merkle tree + Poseidon (poseidon-lite)
    │   ├── make_inputs.mjs          # build voting fixture + Prover.toml
    │   ├── make_tally_inputs.mjs    # build tally witness (Tonelli-Shanks + fold)
    │   ├── adversarial.mjs          # PDA/crypto property tests (no validator)
    │   └── check.mjs                # TS ↔ Noir Poseidon/Merkle vector parity
    ├── migrations/deploy.ts
    └── tests/
        ├── zkp-voting.ts            # validator-backed smoke/integration
        ├── compressed-ballot.ts     # full Light V2 cast_vote flow + replay
        ├── instructions.ts          # 20-case on-chain instruction matrix
        ├── tally.ts                 # trustless post_tally end-to-end
        ├── sunspot.ts               # raw Groth16 verifier accept/reject
        ├── adversarial.ts           # PDA seed-boundary tests (no validator)
        └── README.md                # test-suite docs + runbook
```

---

## Prerequisites

| Tool | Version / notes |
|---|---|
| Noir (`nargo`) | `1.0.0-beta.22` (required by Sunspot v1) |
| Sunspot | v1 CLI (`compile`, `setup`, `prove`, `deploy`, `verify`) |
| Solana / Anchor | Anchor CLI + SBF toolchain (`cargo build-sbf`) |
| Light Protocol | `@lightprotocol/zk-compression-cli` (`light test-validator`) |
| Node | ≥ 20 (tests use node 22) |
| Rust | stable (for `cargo test --lib`) |
| gnark verifier crate | path set via `GNARK_VERIFIER_BIN` for `sunspot deploy` |

All circuits pin `compiler_version = "1.0.0"` in their `Nargo.toml`, which
resolves to the required `1.0.0-beta.22` toolchain.

## The protocol in detail

### Cryptographic building blocks

- **Field / curve.** Everything lives in the BN254 scalar field
  `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.
  The embedded curve used for ElGamal is **Grumpkin** over that field:
  `y² = x³ − 17`, with generator `G = (1, 17631683881184975370165255887551781615748388533673675138860)`.
- **Hash.** Poseidon (`Bn254X5`, big-endian), chosen because it is SNARK-friendly
  **and** matches the Solana `alt_bn128`/`solana_poseidon` syscall. The same
  hash is used in three places that must agree byte-for-byte:
  Noir (vendored `poseidon`), the Rust program (`solana_poseidon::hashv`), and
  the TS helpers (`poseidon-lite`). `client/check.mjs` and the
  `poseidon_matches_circomlib_vector` nargo test guard this parity.
- **ElGamal (exponential variant).** A bit `b` is encrypted under public key
  `PK = sk·G` with randomness `r` as `(C1, C2) = (r·G, r·PK + b·G)`.
  Decryption computes `C2 − sk·C1 = b·G`, which is `G` for `1` and the point at
  infinity for `0`. Each candidate slot gets its own ciphertext.

### Domain separation tags

The same value in different roles must hash differently, so every role is
seeded with a distinct tag (kept in sync between `voting_lib` and the Rust code):

| Tag | Value | Used for |
|---|---|---|
| `TAG_LEAF` | 1 | `H(1, s)` — registration leaf |
| `TAG_NULL` | 2 | `H(2, s, election, position)` — one-time nullifier |
| `TAG_RAND` | 3 | `H(3, r_seed, slot)` — per-slot randomness |
| `TAG_BALLOT` | 4 | fold seed for the ballot commitment |
| `TAG_TRANSCRIPT` | 5 | fold seed for the running tally transcript |

### The five rules a vote must satisfy (`voting_circuit`)

1. **Eligibility** — `H(TAG_LEAF, s)` is a leaf of the frozen Merkle tree
   (`merkle_root(leaf, path) == frozen_root`). The 24-level path stays private.
2. **One vote per race** — the published nullifier is
   `H(TAG_NULL, s, election_id, position_id)`. Its uniqueness is enforced
   on-chain by using it in the compressed-account address seed.
3. **Right key** — the encryption key hashes to the on-chain `pk_hash`.
4. **Valid choice** — exactly one candidate selected, below `max_candidates`.
5. **Committed ballot** — the circuit itself encrypts the choice and proves the
   resulting ciphertext hashes to the published `ballot_commitment`.

### Ballot encoding

A ballot is `K_MAX = 4` slots × (C1.x, C1.y-parity, C2.x, C2.y-parity) = 16
fields. Only the compressed form is stored on-chain: 8 x-coordinates plus one
packed parity byte (`xs[8]` + `parity_bits: u8`). `ballot_commitment` folds
Poseidon over all 16 fields seeded with `TAG_BALLOT`.

### The tally transcript (the hardening)

When `cast_vote` accepts a ballot it folds
`transcript' = H(transcript, H(nullifier, commitment))`, starting from
`TAG_TRANSCRIPT`, and increments `ballot_count`. This produces a single running
hash that **binds the exact ordered set of accepted ballots**. `post_tally` is
then only allowed to store `totals` when a `tally_circuit` proof shows those
totals decrypt that transcript (see
[Tally correctness](#tally-correctness-the-trustless-part)).

## Layer 1 — the Solana program

Program ID: **`4uiu9QzRVZYdLdxCmADj6cQwFCrNufDCgU7NtsvQJWYA`** (Anchor, in
`programs/zkp-voting/src/{lib.rs, ballot.rs}`).

### Accounts

| Account | Seeds | Purpose |
|---|---|---|
| `ElectionConfig` | `["election", authority, election_id(le u64)]` | public key, voting window, frozen Merkle root + leaf count |
| `PositionConfig` | `["position", election, position_id(le u64)]` | race `max_candidates` |
| `BallotTranscript` | `["transcript", position]` | running Poseidon transcript + `ballot_count` |
| `TallyResult` | `["tally", position]` | published `totals[4]` + bound transcript |
| `BallotAccount` | Light V2 compressed, seed `["nullifier", position, nullifier]` | one compressed account per accepted ballot |
| `BallotCast` | event | `election`, `position`, `nullifier`, `xs`, `parity_bits` |

### Instructions

| Instruction | Signer | Behaviour |
|---|---|---|
| `initialize_election(election_id, pk_x, pk_y, vote_start_ts, vote_end_ts)` | authority | store key + window; require `start < end` and canonical key |
| `initialize_position(position_id, max_candidates)` | authority | require `1 ≤ max_candidates ≤ 4`; also init the transcript PDA |
| `freeze_voter_root(root, leaf_count)` | authority | require `now < vote_start`; publish root + `1 ≤ leaf_count ≤ 2²⁴` |
| `cast_vote(proof, nullifier, xs, parity_bits, validity_proof, address_tree_info, output_tree_index)` | payer | verify vote proof → fold transcript → Light V2 CPI → emit event |
| `post_tally(totals, proof)` | authority | require window ended + `Σtotals ≤ ballot_count` → verify tally proof → store totals |

`post_tally` was hardened from its original "trust the admin's numbers" form:
it no longer accepts a free-form transcript hash, and it cannot store `totals`
unless a `tally_circuit` proof decrypts the on-chain transcript.

### Public-witness ABIs (order matters)

The Sunspot/gnark verifier expects `proof ‖ witness`, where `witness` is a
12-byte header (two `u32` public-input counts) followed by 32-byte big-endian
field values.

- **voting_circuit** (7 inputs):
  `root, nullifier, election_id, position_id, max_candidates, pk_hash, commitment`
- **tally_circuit** (8 inputs):
  `transcript, ballot_count, max_candidates, pk_hash, totals[0..3]`

These layouts are defined in `ballot.rs` (`public_witness`,
`tally_public_witness`) and must mirror the `pub` parameter order in each
circuit's `main`.

### Error codes

`Unauthorized`, `AlreadyFrozen`, `NotFrozen`, `VotingClosed`,
`VotingStillOpen`, `BadWindow`, `InvalidLeafCount`, `FreezeWindowClosed`,
`PositionMismatch`, `CandidateOutOfBounds`, `NonCanonicalField`, `BadParity`,
`BadProofLength`, `InvalidVerifier`, `InvalidAddressTree`,
`NotEnoughAccountKeys`, `InvalidTally`, `BadTallyProofLength`, `PoseidonFailed`.

### Canonicality rules

Every field element stored or hashed on-chain is checked to be a **canonical**
BN254 field element (`< p`), and every parity slot must be `0` or `1`, so no
modulus-aliased or malformed value can sneak into a commitment.

---

## Layer 2 — the circuits

Noir workspace (`circuits/`), compiled to Groth16 and verified by pinned Sunspot
programs. `voting_lib` is the single source of truth so every circuit uses
byte-for-byte identical primitives.

- **`voting_circuit`** — the five rules above. Public witness = 7 fields.
  25 `nargo` tests (`vote_*` must pass, `fail_*` must fail).
- **`ballot_encoder`** — helper that turns `(pk, choice, r_seed)` into the
  compressed `xs` + parity used to feed the on-chain `cast_vote` and the tests.
- **`tally_circuit`** — decrypts each ballot in the transcript and sums the bits
  (10 `nargo` tests). See the next section.
- **`voting_lib`** — `leaf_of`, `nullifier_of`, `merkle_root`, `encrypt_slot`,
  `compress_point`, `ballot_commitment_of`, `validate_choices`,
  `ballot_fields_from_xs`, `decompress`, `decrypt_bit`, `transcript_*`.

### Verifier programs

`sunspot deploy <vk>` compiles the Groth16 verifying key into a Solana program.
Two verifiers are deployed and pinned:

| Circuit | Verifier program ID |
|---|---|
| `voting_circuit.vk` | `3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3` |
| `tally_circuit.vk` | `AjGDxunAeXevv7AWyhK4jKDsunjbAoZDxzNqGdM2iZWw` |

Both must be preloaded into the test validator at these addresses (see the
runbook), and the program checks them with an `executable` + pinned-address
account constraint (`InvalidVerifier` otherwise).

## Tally correctness (the trustless part)

The original `post_tally` trusted the admin: it accepted any `totals[4]` plus a
self-reported `transcript_hash`. Two changes make the tally verifiable:

1. **Layer 1 — the transcript.** `cast_vote` folds every accepted ballot into a
   `BallotTranscript` PDA, so the chain itself records *which ballots* (and how
   many) were counted.
2. **Layer 2 — the tally circuit.** `tally_circuit` takes the transcript as a
   public input and, for each ballot, **re-derives the commitment, decompresses
   each ciphertext point, decrypts it with `sk`, and asserts the vote is
   one-hot**, then sums the bits and asserts the sum equals the public `totals`.

`post_tally` therefore stores `totals` only when the proof verifies against the
**on-chain** transcript. An admin who fabricates totals has no valid proof; an
admin who omits or reorders ballots breaks the transcript fold.

The circuit has a **fixed capacity `N_BALLOTS = 8`**. Ballots beyond the
on-chain `ballot_count` are padding slots (still valid one-hot encryptions, but
excluded from both the fold and the sum), so one circuit serves any election of
≤ 8 ballots; larger elections need a larger setup. Decrypting needs `sk`, which
stays off-chain with the tally authority.

### Why not homomorphic on-chain aggregation?

ElGamal is additively homomorphic, so in principle the chain could sum
ciphertexts and decrypt `Σbits·G` once. That would scale better — but it needs
**Grumpkin** point arithmetic on-chain, and Solana's `alt_bn128` precompiles are
BN254-**G1**, not Grumpkin. So the per-ballot `tally_circuit` (whose verification
cost is independent of constraint count) is the pragmatic trustless design today.

---

## Design decisions

| Decision | Why |
|---|---|
| ElGamal over Grumpkin | Additive homomorphism + fits the BN254 scalar field used by Noir's embedded curve |
| Exponential ElGamal (`b·G` in the exponent) | Decryption = a point compare (`C2 − sk·C1` is `G` or `∞`); no discrete-log per ballot |
| `sk` stays off-chain | Decryption is the only operation needing it; keeping it off-chain avoids exposing it to the world |
| Per-slot randomness from `TAG_RAND` | One remembered secret, independent ciphertexts per slot (no bit leakage between slots) |
| Poseidon everywhere | SNARK-friendly **and** available as a Solana syscall, so Noir ↔ Rust ↔ TS can agree exactly |
| Domain tags | Same value can never be mistaken across leaf/nullifier/randomness/commitment/transcript roles |
| Frozen root **before** voting starts | Prevents an admin from adding voters mid-election (`FreezeWindowClosed`) |
| Compressed ballots (Light V2) | One cheap on-chain slot per vote; the nullifier seed makes replay structurally impossible |
| Layer-1 transcript | Turns "the chain accepted some ballots" into a single hash the tally proof can bind to |
| Separate tally verifier program | Each Groth16 verifying key is compiled into its own program, so two circuits = two pinned IDs |
| `N_BALLOTS = 8` fixed capacity | Verification cost is independent of constraints, so a modest fixed capacity keeps setup/proving practical |
| Unsafe `sunspot setup` | Documented as local-only; production needs a real trusted setup (MPC) |

---

## Security model & threat analysis

### What is *proven*

- A ballot can only be cast by a registered voter (Merkle membership proof).
- The same voter cannot vote twice in a position (nullifier in the account seed).
- The published ciphertext is the encryption of the proven one-hot choice.
- The published tally equals the decryption of the exact ballots the chain folded.

### What is *enforced on-chain*

- Voting window, frozen root, canonical fields, pinned verifier programs.
- `Σtotals ≤ ballot_count` and inactive candidates must be `0`.

### Adversary model / what a malicious actor can *not* do

- **Forge a ballot** without a valid Merkle path (proof fails).
- **Double-vote** — the nullifier address already exists (Light CPI rejects).
- **Replay** a valid ballot elsewhere — nullifier binds `(election, position)`.
- **Tamper with a ciphertext** — it would no longer match the proven commitment.
- **Post fake totals** — no `tally_circuit` proof exists for a transcript it
  doesn't decrypt to.
- **Use a wrong verifier/key** — verifier IDs are pinned; `pk_hash` binds the key.

### Residual trust & known gaps

- **Trusted setup is unsafe** (local testing only).
- **Light Protocol prover/validators** are trusted for compression correctness.
- **Ballot secrecy vs. a corrupt tally authority** — the authority can decrypt
  individual ballots (`sk`); the transcript/tally design guarantees *correctness*,
  not *authority-blindness*. Mixnets/resharing would be needed for stronger
  privacy from the tallier.
- **Receipt-freeness/coercion-resistance** are not implemented.
- **`N_BALLOTS` capacity** is fixed per setup.

### The security test suites

| Suite | What it attacks |
|---|---|
| `nargo test` (`voting_circuit`) | each of the 5 rules individually (wrong root/nullifier/key/choice/commitment) |
| `nargo test` (`tally_circuit`) | wrong totals/transcript/sk, two-selection, over-capacity |
| `client/adversarial.mjs` | Merkle path, nullifier/leaf domains, canonicality, order-sensitivity |
| `client/check.mjs` | TS ↔ Noir Poseidon/Merkle vector parity |
| `tests/instructions.ts` | full on-chain success/rejection matrix for all 5 instructions |
| `tests/compressed-ballot.ts` | real Light V2 cast, corrupted-proof rejection, nullifier replay rejection, transcript advance |
| `tests/tally.ts` | end-to-end trustless `post_tally` (cast + circuit-verified totals) |
| `tests/sunspot.ts` | raw Groth16 verifier accepts valid proof, rejects mutated witness |
| `tests/adversarial.ts` | PDA seed-boundary invariants |

---

## Build & test runbook

The full pipeline (one-time + per-run). Commands assume `noirup` has
`1.0.0-beta.22` active and `sunspot`, `light`, and `anchor` are on `PATH`.

### 0. Install dependencies (once)

```bash
cd zkp-voting && npm install   # or yarn; Anchor + test dependencies
cd client   && npm install     # poseidon-lite etc. for the input generators
```

### 1. Circuits (Noir → Sunspot artifacts)

```bash
cd circuits
nargo test --workspace                                # 35 tests (voting 25 + tally 10)
nargo compile --package voting_circuit
nargo compile --package tally_circuit
cd ../zkp-voting
node client/make_inputs.mjs                           # writes voting fixture + witness

sunspot compile ../circuits/target/voting_circuit.json
sunspot setup   ../circuits/target/voting_circuit.ccs
sunspot prove   ../circuits/target/voting_circuit.json ../circuits/target/voting_circuit.gz \
                ../circuits/target/voting_circuit.ccs ../circuits/target/voting_circuit.pk
GNARK_VERIFIER_BIN=/path/to/sunspot/gnark-solana/crates/verifier-bin \
  sunspot deploy ../circuits/target/voting_circuit.vk

sunspot compile ../circuits/target/tally_circuit.json
sunspot setup   ../circuits/target/tally_circuit.ccs
GNARK_VERIFIER_BIN=/path/to/sunspot/gnark-solana/crates/verifier-bin \
  sunspot deploy ../circuits/target/tally_circuit.vk
```

`sunspot deploy` writes `<name>.so` + `<name>-keypair.json` **next to the `.vk`**
and prints the verifier program id. The tally verifier id must match
`SUNSPOT_TALLY_VERIFIER_ID` in `lib.rs`; the voting verifier matches
`SUNSPOT_VERIFIER_ID`.

### 2. Build the app program

```bash
cd zkp-voting
cargo test --lib        # Rust unit tests (6)
anchor build            # regenerates target/idl + target/types + deploy .so
```

### 3. Start the Light validator with both verifiers + the app

```bash
light test-validator \
  --sbf-program 3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3 ../circuits/target/voting_circuit.so \
  --sbf-program AjGDxunAeXevv7AWyhK4jKDsunjbAoZDxzNqGdM2iZWw ../circuits/target/tally_circuit.so \
  --sbf-program 4uiu9QzRVZYdLdxCmADj6cQwFCrNufDCgU7NtsvQJWYA target/deploy/zkp_voting.so
```

Keep it running, then in another terminal:

```bash
npm run test:light       # integration + compressed + instructions + pda
npm run test:tally       # trustless post_tally (re-prepares + proves + runs)
```

---

## Developer workflow

```bash
# unit / circuit tests (no validator needed)
cargo test --lib
nargo test --workspace
cd client && npm test        # check.mjs + adversarial.mjs (Poseidon/Merkle parity)

# on-chain suites (require the Light validator above)
npm run test:integration    # zkp-voting.ts
npm run test:compressed     # regenerate voting proof + compressed-ballot.ts
npm run test:instructions   # 20-case instruction matrix
npm run test:pda            # adversarial.ts (no validator)
npm run test:sunspot        # raw verifier accept/reject
npm run test:tally          # prepare proofs + tally.ts end-to-end
npm run test:light          # integration + compressed + instructions + pda
npm test                    # anchor test (zkp-voting.ts + adversarial.ts)

# regenerate proof artifacts
npm run prepare:test-proof   # voting fixture + Groth16 vote proof
npm run prepare:tally-proof  # tally witness + Groth16 tally proof
```

Environment variables used by the suites:

| Var | Default | Purpose |
|---|---|---|
| `ANCHOR_PROVIDER_URL` | `http://127.0.0.1:8899` | validator RPC |
| `ANCHOR_WALLET` | `~/.config/solana/id.json` | payer |
| `LIGHT_INDEXER_URL` | `http://127.0.0.1:8784` | compressed-account indexer |
| `LIGHT_PROVER_URL` | `http://127.0.0.1:3001` | Light ZK prover |
| `ZKP_TEST_ELECTION_ID` | `Date.now()` | override the fixture election id |

---

## Configuration reference

| Constant | Value | Where |
|---|---|---|
| Program ID | `4uiu9QzRVZYdLdxCmADj6cQwFCrNufDCgU7NtsvQJWYA` | `lib.rs` / `Anchor.toml` |
| Voting verifier | `3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3` | `lib.rs` |
| Tally verifier | `AjGDxunAeXevv7AWyhK4jKDsunjbAoZDxzNqGdM2iZWw` | `lib.rs` |
| `K_MAX` | 4 | `lib.rs`, `voting_lib` |
| `DEPTH` | 24 (⇒ `2²⁴` voters) | `voting_lib` |
| `XS_LEN` / `BALLOT_LEN` | 8 / 16 | `ballot.rs`, `voting_lib` |
| `N_BALLOTS` | 8 | `tally_circuit` |
| `MAX_PROOF_LEN` / `MAX_TALLY_PROOF_LEN` | 512 / 512 | `lib.rs` |
| Domain tags | 1…5 | `ballot.rs`, `voting_lib` |
| Address tree (test) | `amt2kaJA14v3urZbZvnc5v2np8jqvc4Z8zDep5wbtzx` | `compressed-ballot.ts` |

---

## Frontend integration (planned)

A frontend is the next phase and is not yet present. The integration surface it
will consume is already defined:

- **Vote flow** — per ballot the client must:
  1. derive `s` from the user's passkey,
  2. fetch the frozen root / `pk` / window from the program,
  3. build the Merkle path (registration service),
  4. run `voting_circuit` + `sunspot prove` to get `proof`,
  5. call `cast_vote(proof, nullifier, xs, parity_bits, validity_proof, …)` via
     a Light-aware transaction (see `tests/compressed-ballot.ts` for the exact
     account + LUT layout, including the `1_400_000` compute budget).
- **Tally flow** — an admin client fetches the `BallotCast` events / compressed
  ballots for a position, decrypts with `sk`, builds the `tally_circuit`
  witness (see `client/make_tally_inputs.mjs`), proves, and calls
  `post_tally(totals, proof)` (also with a `1_400_000` compute budget).
- **Indexer** — read compressed ballots from the Light indexer
  (`LIGHT_INDEXER_URL`), keyed by owner `programId` and the nullifier-derived
  address.

The on-chain ABI, PDA seeds, witness layouts, and compute-budget requirements in
this README are the contract the frontend must satisfy.

---

## Known limitations

- **Trusted setup is unsafe** — regenerate via a real MPC for production.
- **Fixed `N_BALLOTS = 8`** tally capacity; larger elections need a new circuit + setup.
- **No receipt-freeness / coercion resistance / verifiable decryption shares** — `sk`
  is held by a single tallier.
- **No voter-facing key management** — `s` derivation from a passkey is assumed, not implemented.
- **Local/dev verifier programs** are compiled from the current `.vk`; redeploy
  regenerates the program id, which must then be re-pinned in `lib.rs`.
- **Light Protocol V2** specifics (address tree id, CPI account layout) are pinned
  to the test environment used here.

---

## Troubleshooting

- **`TransactionExpiredTimeoutError` on success sends** — the surfpool validator
  does not confirm the same way `provider.sendAndConfirm` polls. Use the explicit
  `sendRawTransaction` + `confirmTransaction({blockhash, lastValidBlockHeight})`
  pattern (as in `tests/compressed-ballot.ts`).
- **`FreezeWindowClosed` / flaky time-sensitive tests** — the Light validator's
  `Clock.unix_timestamp` drifts ahead of wall clock. Read the on-chain clock
  (`SysvarC1ock…`, `unix_timestamp` at byte offset 32) for tight windows, or
  restart the validator before running.
- **`exceeded CUs meter` on `post_tally`** — the tally verifier consumes ~186k
  CUs; the transaction must set `ComputeBudgetProgram.setComputeUnitLimit(1_400_000)`.
- **`Account "transcript" not provided`** — `initialize_position` and `cast_vote`
  require the `BallotTranscript` PDA; derive it with seeds `["transcript", position]`.
- **`InvalidVerifier`** — the verifier `.so` isn't preloaded at the pinned address,
  or the pinned ID drifted after `sunspot deploy`.
- **Verifier id changed after redeploy** — update the matching `SUNSPOT_*_VERIFIER_ID`
  in `lib.rs`, re-`anchor build`, and reload the `.so`.

---

## Disclaimer

This is a reference implementation for demonstration and testing. It uses an
**unsafe trusted setup** and is not audited. Do not use it for real elections
without a production trusted setup, an independent audit, and a threat model
that covers the residual-trust items above.






