# ZKP Voting — frontend (`app/`)

A Next.js (App Router) UI for the ZKP voting system. It talks to both layers:

- **Layer 1** — the Anchor program `zkp_voting` + Light Protocol V2 compressed accounts
  (`lib/solana`, `lib/light`).
- **Layer 2** — the Noir circuits + Sunspot Groth16 proofs (`lib/crypto`, `lib/proving`).

## Layout

```
app/
├── public/idl/zkp_voting.json   # copied from zkp-voting/target/idl (drift guard: keep in sync)
├── src/
│   ├── app/
│   │   ├── admin/               # admin wizard (create election → position → enroll → freeze → tally)
│   │   ├── vote/                # voter wizard (load manifest → identify → choose → cast)
│   │   ├── results/             # read-only transcript + tally view
│   │   └── api/prove/route.ts   # DEV proving service (nargo + sunspot)
│   ├── lib/
│   │   ├── crypto/              # TS mirror of voting_lib + tree.mjs (Poseidon, Grumpkin, Merkle, ballot)
│   │   ├── solana/              # connection, program, PDAs, admin actions, castVote (Light CPI)
│   │   ├── light/               # Light V2 helpers
│   │   ├── proving/             # Prover interface (NodeProver now, WasmProver later)
│   │   ├── manifest.ts          # the election manifest shared between admin and voter
│   │   └── config.ts            # program id, verifier ids, RPC/light URLs
│   └── components/              # providers (wallet), topbar, stepper
└── scripts/crypto-check.ts      # parity test vs. the Noir fixtures (run with `npm run check`)
```

## Run

```bash
cd app
cp .env.local.example .env.local   # set SUNSPOT_CIRCUITS_DIR to the repo's circuits/ dir
npm install
npm run check                      # crypto parity (must pass 11/11)
npm run dev                        # http://localhost:3000
```

The voter's **proof generation** uses the `/api/prove` route, which shells out to
`nargo execute` + `sunspot prove` on the machine running the app. This requires
`nargo` (1.0.0-beta.22) and `sunspot` on `PATH`, and `SUNSPOT_CIRCUITS_DIR` set to
the absolute path of `../circuits`. This is the **dev-only** path — it sends the
witness to the server.

## Proving strategy

The Groth16 proving key + circuit must match the **already deployed** Sunspot
verifiers (pinned IDs). Two backends, one interface (`lib/proving/types.ts`):

1. **NodeProver (default)** — delegates to `/api/prove`. Fastest to a working demo,
   but the witness (voter secret) leaves the browser. Dev-only.
2. **WasmProver** — the gnark prover compiled to WASM (`app/prisms/prover/`), run in
   a Web Worker so the secret never leaves the device. Set `NEXT_PUBLIC_PROVER=wasm`.
   It needs two halves:
   - **Problem A (done):** the Go prover → `prover.wasm` + the `acir` byte-loaders +
     the worker bridge (`lib/proving/wasm.ts`, `workers/prover.worker.ts`).
   - **Problem B (pending):** producing the `nargo execute` witness stack in-browser
     (Noir ACIR VM via `@noir-lang/noir_js`/`acvm_js` pinned to `1.0.0-beta.22`).

The tally proof is intentionally **server-side** (the admin already holds the tally
secret, so there is no privacy gain from proving it in the browser, only a large cost).
The admin's **Auto tally** button gathers the `BallotCast` events in cast order
(`lib/solana/events.ts`), decrypts with the secret key and builds the `tally_circuit`
witness (`lib/tally.ts`), then proves + posts via the same `/api/prove` route.

## Known limitations

- **Password-derived secret:** the admin supplies `(name, id, password)`, so the
  admin can re-derive any voter's secret. Acceptable for the demo; production needs
  voter self-enrollment (share only the leaf) or a passkey.
- **8-ballot cap:** the tally circuit has a fixed `N_BALLOTS = 8`; the program
  rejects the 9th ballot (`TallyCapacityReached`).
- **Local toolchain:** the vote proof requires `nargo` + `sunspot` on the server
  (or the WASM prover once built).
