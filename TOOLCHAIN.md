# Toolchain

Exact pinned versions for reproducing this project. Use these versions.

| Tool | Version / commit |
|---|---|
| Noir (`nargo`) | `1.0.0-beta.22` (noirc `c57152f91260ecdb9faad4efc20abb14b6d2ece7`) |
| Sunspot | commit `43891c5` (v1 CLI, `go/sunspot`) |
| gnark verifier crate | commit `43891c5` (`sunspot/gnark-solana/crates/verifier-bin`) |
| Anchor CLI | `0.31.1` |
| Solana CLI | `3.1.5` (Agave) |
| Rust | `1.89.0` |
| Node | `22.23.1` |
| Light Protocol CLI | `@lightprotocol/zk-compression-cli 0.28.4` |
| Vendored Noir Poseidon | `v0.4.0` @ `e105cdd5c79c222860d53c5dfdb8fa8012b291c0` |

## Notes

- Noir `1.0.0-beta.22` is required by Sunspot v1. The circuits pin
  `compiler_version = "1.0.0"` in their `Nargo.toml`, which resolves to this toolchain.
- Install Noir with `noirup --version 1.0.0-beta.22`.
- `sunspot setup` performs an **unsafe** trusted setup — for local testing only.
  Production requires a real trusted setup (e.g. an MPC ceremony).
- `sunspot deploy` compiles the Groth16 verifying key into a Solana program via
  `cargo build-sbf`; it needs `GNARK_VERIFIER_BIN` pointing at the
  `gnark-solana/crates/verifier-bin` crate.
- `sunspot prove` needs the circuit `.json`, `.gz` (witness), `.ccs`, and `.pk` files.
