// Byte-loaders for the sunspot `acir` package (WASM has no filesystem).
//
// Copy this file into your sunspot checkout at `go/acir/acir-bytes.go` (same
// package) before building prover.wasm. It adds memory-based equivalents of
// LoadWitnessStackFromFile / GetWitness, reusing the package's existing
// `readStackItem` / `readWitnessMap` / `msgpackutil` helpers.
package acir

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend/witness"
	"github.com/reilabs/sunspot/go/acir/msgpackutil"
	shr "github.com/reilabs/sunspot/go/acir/shared"
)

// LoadWitnessStackFromBytes reads a `nargo execute` witness stack from memory.
func LoadWitnessStackFromBytes[T shr.ACIRField](data []byte, modulus *big.Int) (WitnessStack[T], error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return WitnessStack[T]{}, fmt.Errorf("witness: %w", err)
	}
	defer gz.Close()

	if err := msgpackutil.ConsumeFormatByte(gz); err != nil {
		return WitnessStack[T]{}, fmt.Errorf("witness: %w", err)
	}
	r := msgpackutil.NewReader(gz)

	var witnesses WitnessStack[T]
	err = msgpackutil.ReadStruct(r, "WitnessStack", []msgpackutil.Field{
		{Name: "stack", Decode: func(r *msgpackutil.Reader) error {
			n, err := r.ReadArrayLen()
			if err != nil {
				return err
			}
			witnesses = make(WitnessStack[T], 0, n)
			for i := 0; i < n; i++ {
				item, err := readStackItem[T](r)
				if err != nil {
					return fmt.Errorf("stack item %d: %w", i, err)
				}
				witnesses = append(witnesses, item)
			}
			return nil
		}},
	})
	if err != nil {
		return WitnessStack[T]{}, err
	}
	return witnesses, nil
}

// GetWitnessFromBytes builds the gnark witness (public-first) from an in-memory
// witness stack. Identical mapping to GetWitness, but no file path.
func (acir *ACIR[T, E]) GetWitnessFromBytes(data []byte, field *big.Int) (witness.Witness, error) {
	witnessStack, err := LoadWitnessStackFromBytes[T](data, field)
	if err != nil {
		return nil, err
	}

	w, err := witness.New(field)
	if err != nil {
		return nil, fmt.Errorf("failed to create new witness: %w", err)
	}
	if len(witnessStack) == 0 {
		return nil, fmt.Errorf("witness stack is empty")
	}

	publicWitnesses := acir.PublicWitnesses()
	publicSlots := make(map[shr.Witness]struct{}, len(publicWitnesses))
	for _, pub := range publicWitnesses {
		publicSlots[pub.MainIndex] = struct{}{}
	}

	countPublic := len(publicWitnesses)
	countPrivate := 0
	for _, stackItem := range witnessStack {
		c := &acir.Program.Functions[stackItem.CircuitIndex]
		countPrivate += int(c.CurrentWitnessIndex) + 1
	}
	countPrivate -= countPublic

	values := make(chan any)
	go func() {
		outer := witnessStack[len(witnessStack)-1]
		for _, pub := range publicWitnesses {
			value, ok := outer.WitnessMap[pub.MainIndex]
			if !ok {
				values <- 0
				continue
			}
			values <- value.ToFrontendVariable()
		}
		for i := 0; i < len(witnessStack); i++ {
			stackItem := witnessStack[i]
			c := &acir.Program.Functions[stackItem.CircuitIndex]
			for j := uint32(0); j <= c.CurrentWitnessIndex; j++ {
				witnessKey := shr.Witness(j)
				if i == len(witnessStack)-1 {
					if _, isPublic := publicSlots[witnessKey]; isPublic {
						continue
					}
				}
				witnessValue, ok := stackItem.WitnessMap[witnessKey]
				if !ok {
					values <- 0
					continue
				}
				values <- witnessValue.ToFrontendVariable()
			}
		}
		close(values)
	}()

	if err := w.Fill(countPublic, countPrivate, values); err != nil {
		return nil, fmt.Errorf("failed to fill witness: %w", err)
	}
	return w, nil
}
