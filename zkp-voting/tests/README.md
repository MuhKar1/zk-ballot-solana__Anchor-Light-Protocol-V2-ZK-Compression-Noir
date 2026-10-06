# Anchor tests

The TypeScript tests are split by whether they need a validator.

## `zkp-voting.ts`

This is the validator-backed Anchor suite. It submits real transactions for
election and position initialization, voter-root freezing, stored account
state, and invalid transition rejection.

Successful `cast_vote` tests additionally require the deployed Sunspot
verifier and the Light Protocol ZK Compression environment.

## `adversarial.ts`

This is a fast, provider-independent suite for PDA and account-seed invariants.
It does not call the Solana program and cannot prove instruction rejection.

## `compressed-ballot.ts`

This Light-backed integration test verifies a ballot with the pinned Sunspot
program, submits the Light V2 CPI, checks the indexed compressed ballot, and
rejects an unfrozen election, a corrupted proof, and a replayed nullifier. It
generates a fresh circuit fixture and proof for each run.

## `sunspot.ts`

This suite submits a generated Groth16 proof to the Sunspot verifier and checks
that a modified public witness is rejected. It requires the generated local
Sunspot artifacts and a validator with the verifier preloaded at its pinned
address; run it separately with `npm run test:sunspot`.

## `instructions.ts`

A table-driven on-chain matrix for every instruction. It covers the success and
rejection paths of `initialize_election`, `initialize_position`,
`freeze_voter_root`, `cast_vote`, and `post_tally`. It is deliberately
Light-free: every `cast_vote`/`post_tally` case fails before the Sunspot
verifier or the Light CPI, so no proof or compressed-account artifacts are
needed. It still requires a validator preloaded with both verifier programs.

## `tally.ts`

The Layer-2 end-to-end test. It casts a real compressed ballot, asserts the
on-chain transcript was re-derived (Layer 1), then posts a tally and asserts it
is accepted only when accompanied by a `tally_circuit` proof that decrypts the
ballot the chain folded. Requires the tally proof from `prepare:tally-proof`.


## Commands

```bash
npm run test:pda          # PDA model tests; no validator
npm run test:integration  # Anchor smoke/integration tests; local validator
npm run test:compressed   # Full Light V2 compressed ballot flow
npm run test:instructions # Instruction success/rejection matrix
npm run test:tally        # Layer-2 trustless tally flow (casts + posts)
npm run test:light        # Integration, compressed ballot, instructions, and PDA suites
npm run test:ts           # Alias for all TypeScript suites; requires Light
npm run test:sunspot      # Sunspot verifier proof acceptance/rejection
npm test                  # Full Anchor workflow
```

## Local Sunspot Setup

Sunspot v1 requires Noir `1.0.0-beta.22`; this circuit workspace pins its
`1.0.0` compatibility version. The following setup is for local testing only:
`sunspot setup` performs an unsafe trusted setup, so the generated keys must
not be used for a production election.

```bash
noirup --version 1.0.0-beta.22
cd circuits
nargo test --workspace
nargo compile --package voting_circuit
nargo compile --package tally_circuit
cd ../zkp-voting
node client/make_inputs.mjs
sunspot compile ../circuits/target/voting_circuit.json
sunspot setup ../circuits/target/voting_circuit.ccs
sunspot prove ../circuits/target/voting_circuit.json ../circuits/target/voting_circuit.gz ../circuits/target/voting_circuit.ccs ../circuits/target/voting_circuit.pk
GNARK_VERIFIER_BIN=/path/to/sunspot/gnark-solana/crates/verifier-bin sunspot deploy ../circuits/target/voting_circuit.vk
sunspot compile ../circuits/target/tally_circuit.json
sunspot setup ../circuits/target/tally_circuit.ccs
GNARK_VERIFIER_BIN=/path/to/sunspot/gnark-solana/crates/verifier-bin sunspot deploy ../circuits/target/tally_circuit.vk
anchor build
```

Build the application program, then start a fresh Light test environment with
the verifier and application program loaded at their configured addresses.
Keep this running while executing `npm run test:light` in another terminal.

```bash
light test-validator \
	--sbf-program 3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3 ../circuits/target/voting_circuit.so \
	--sbf-program AjGDxunAeXevv7AWyhK4jKDsunjbAoZDxzNqGdM2iZWw ../circuits/target/tally_circuit.so \
	--sbf-program 4uiu9QzRVZYdLdxCmADj6cQwFCrNufDCgU7NtsvQJWYA target/deploy/zkp_voting.so
npm run test:light
npm run test:tally
```