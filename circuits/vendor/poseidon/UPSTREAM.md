# Poseidon provenance

This directory is based on Noir Poseidon `v0.4.0` at commit
`e105cdd5c79c222860d53c5dfdb8fa8012b291c0`.

The source contains two compatibility adjustments for the current Noir toolchain
(`1.0.0-beta.22`):

- Empty slice markers use `[]` instead of the removed `@[]` syntax.
- `poseidon2_permutation` receives the state width argument `4`.

The cryptographic hash functions and constants are otherwise unchanged from the
upstream release, and the vectors are verified on Noir `1.0.0-beta.22` via
`nargo test --workspace` and against Rust/TypeScript in `zkp-voting/client/check.mjs`
and `zkp-voting/programs/zkp-voting/src/ballot.rs`. Re-run those when upgrading.

