// Copyright (c) Faye Amacker. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

package cose_test

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2/cose"
)

// This is the wrapper-level usage for the explicit COSE_Sign1 reader:
// ReadSign1 parses and validates structure (never touching keys), and Verify
// delegates cryptography to an injected Verifier.
func ExampleReadSign1() {
	pub, priv := exampleKey()

	// Protected header {1: -8} (alg = EdDSA). In real messages this bstr
	// arrives off the wire; here we construct one for the example.
	protected := []byte{0xa1, 0x01, 0x27}
	payload := []byte("example payload")
	aad := []byte("external aad")

	sig := ed25519.Sign(priv, exampleSigStructure(protected, aad, payload))
	msg := exampleSign1(protected, nil, payload, sig)

	msg2, err := cose.ReadSign1(msg)
	if err != nil {
		panic(err)
	}

	verifier := cose.NewMemoryVerifier(pub)
	if err := msg2.Verify(verifier, nil, aad); err != nil {
		panic(err)
	}
	fmt.Println("verified")

	// A detached message carries a null payload; content is supplied to Verify.
	detachedSig := ed25519.Sign(priv, exampleSigStructure(protected, nil, payload))
	detached := exampleSign1(protected, nil, nil, detachedSig) // null payload
	dm, err := cose.ReadSign1(detached)
	if err != nil {
		panic(err)
	}
	if err := dm.Verify(verifier, payload, nil); err != nil { // content here
		panic(err)
	}
	if err := dm.Verify(verifier, nil, nil); !errors.Is(err, cose.ErrDetachedPayload) {
		panic("expected ErrDetachedPayload")
	}
	fmt.Println("detached verified")
	// Output:
	// verified
	// detached verified
}

func exampleKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func exampleSign1(protected, unprotected, payload, sig []byte) []byte {
	e := cbTag(cose.Sign1TagNumber)
	e = append(e, cbArray(4)...)
	e = append(e, cbBstr(protected)...)
	e = append(e, cbMap(0)...) // empty unprotected map
	if payload == nil {
		e = append(e, cbNull...) // null: detached
	} else {
		e = append(e, cbBstr(payload)...)
	}
	e = append(e, cbBstr(sig)...)
	return e
}

func exampleSigStructure(protected, aad, payload []byte) []byte {
	if aad == nil {
		aad = []byte{}
	}
	e := cbArray(4)
	e = append(e, cbText("Signature1")...)
	e = append(e, cbBstr(protected)...)
	e = append(e, cbBstr(aad)...)
	e = append(e, cbBstr(payload)...)
	return e
}
