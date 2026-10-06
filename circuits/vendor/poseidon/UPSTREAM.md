# Poseidon provenance

This directory is based on Noir Poseidon `v0.4.0` at commit
`e105cdd5c79c222860d53c5dfdb8fa8012b291c0`.

The source contains two compatibility adjustments for Noir `0.39.0`:

- Empty slice markers use `[]` instead of the removed `@[]` syntax.
- `poseidon2_permutation` receives the state width argument `4`.

The cryptographic hash functions and constants are otherwise unchanged from the upstream release. Re-run the Noir, Rust, and TypeScript vector tests when upgrading this dependency.
