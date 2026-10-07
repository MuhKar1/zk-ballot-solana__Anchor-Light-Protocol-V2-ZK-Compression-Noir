module zkpvoting/prover

go 1.24.2

require (
	github.com/consensys/gnark v0.14.0
	github.com/consensys/gnark-crypto v0.19.0
	github.com/reilabs/sunspot/go v0.0.0-00010101000000-000000000000
)

require (
	github.com/bits-and-blooms/bitset v1.24.0 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/google/btree v1.0.0 // indirect
	github.com/google/pprof v0.0.0-20250820193118-f64d9cf942d6 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ronanh/intcomp v1.1.1 // indirect
	github.com/rs/zerolog v1.34.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/exp v0.0.0-20250819193227-8b4c13bb791b // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
)

// Point this at a local checkout of https://github.com/reilabs/sunspot pinned to
// commit 43891c5 (the version that produced the deployed verifiers). See README.
replace github.com/reilabs/sunspot/go => ../sunspot/go
