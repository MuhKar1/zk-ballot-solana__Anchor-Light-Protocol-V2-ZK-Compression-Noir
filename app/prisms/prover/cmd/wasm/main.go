//go:build js && wasm

// Package main is the on-device Groth16 prover compiled to WebAssembly.
//
// It exposes two JS globals (after `go.run`):
//
//	proverLoad(acirB64, ccsB64, pkB64) -> { error? }   load the circuit + keys (once)
//	proverProve(witnessGzB64)          -> proofB64 | { error }
//
// The inputs are base64-encoded byte blobs so they can cross the JS<->Go boundary
// without a filesystem. `witnessGz` is the `nargo execute` witness stack
// (gzip -> format byte -> msgpack), exactly what `sunspot prove` consumes.
package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"syscall/js"

	"github.com/consensys/gnark-crypto/ecc"
	ecc_bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/reilabs/sunspot/go/acir"
	"github.com/reilabs/sunspot/go/bn254"
)

type E = constraint.U64
type T = *bn254.BN254Field

var (
	loaded  bool
	ccs     constraint.ConstraintSystem
	pk      groth16.ProvingKey
	circuit acir.ACIR[T, E]
)

func fail(err error) map[string]any {
	return map[string]any{"error": err.Error()}
}

func decode(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(value)
}

func load(_ js.Value, args []js.Value) any {
	if len(args) != 3 {
		return fail(errors.New("proverLoad expects (acirB64, ccsB64, pkB64)"))
	}

	acirBytes, err := decode(args[0].String())
	if err != nil {
		return fail(err)
	}
	if err := circuit.UnmarshalJSON(acirBytes); err != nil {
		return fail(err)
	}

	ccsBytes, err := decode(args[1].String())
	if err != nil {
		return fail(err)
	}
	ccs = groth16.NewCS(ecc.BN254)
	if _, err := ccs.ReadFrom(bytes.NewReader(ccsBytes)); err != nil {
		return fail(err)
	}

	pkBytes, err := decode(args[2].String())
	if err != nil {
		return fail(err)
	}
	pk = groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(bytes.NewReader(pkBytes)); err != nil {
		return fail(err)
	}

	loaded = true
	return nil
}

func prove(_ js.Value, args []js.Value) any {
	if !loaded {
		return fail(errors.New("prover not loaded"))
	}
	if len(args) != 1 {
		return fail(errors.New("proverProve expects (witnessGzB64)"))
	}

	witnessBytes, err := decode(args[0].String())
	if err != nil {
		return fail(err)
	}

	witness, err := circuit.GetWitnessFromBytes(witnessBytes, ecc_bn254.ID.ScalarField())
	if err != nil {
		return fail(err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return fail(err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteRawTo(&buf); err != nil {
		return fail(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func main() {
	js.Global().Set("proverLoad", js.FuncOf(load))
	js.Global().Set("proverProve", js.FuncOf(prove))
	select {}
}
