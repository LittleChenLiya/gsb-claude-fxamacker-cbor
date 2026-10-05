// Copyright (c) Faye Amacker. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

package cose

import (
	"crypto/ed25519"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// COSE header labels and algorithm identifiers used by the built-in verifier.
const (
	labelAlg uint64 = 1 // RFC 9052 table 2
	labelKid uint64 = 4 // RFC 9052 table 2

	// AlgEdDSA is the COSE algorithm identifier for pure EdDSA over Edwards
	// curves (RFC 9053), i.e. Ed25519 in this implementation.
	AlgEdDSA int64 = -8
)

// MemoryVerifier is an in-memory, dependency-injected COSE_Sign1 [Verifier].
//
// It performs no I/O and never reads key files: public keys are supplied by
// the application. Key selection uses the unprotected "kid" header (a bstr):
//
//   - when the message has no kid, Default is used (and must be set);
//   - when the message has a kid, the matching entry in Keys is used (and
//     must be set).
//
// Only COSE algorithm EdDSA (label -8) over Ed25519 is implemented. The
// algorithm is taken from the PROTECTED header, as required by RFC 9052.
type MemoryVerifier struct {
	// Default is the key used for messages without a kid.
	Default ed25519.PublicKey
	// Keys maps kid byte strings to public keys.
	Keys map[string]ed25519.PublicKey
}

// NewMemoryVerifier returns a [MemoryVerifier] using key for messages without
// a kid header.
func NewMemoryVerifier(key ed25519.PublicKey) *MemoryVerifier {
	return &MemoryVerifier{
		Default: key,
		Keys:    make(map[string]ed25519.PublicKey),
	}
}

// AddKey registers a public key under a kid for keyed verification.
func (mv *MemoryVerifier) AddKey(kid []byte, key ed25519.PublicKey) {
	if mv.Keys == nil {
		mv.Keys = make(map[string]ed25519.PublicKey)
	}
	mv.Keys[string(kid)] = key
}

// VerifyCOSESign1 implements [Verifier]. It validates the protected "alg"
// header, selects the key, and checks the Ed25519 signature over the
// precomputed Sig_structure.
func (mv *MemoryVerifier) VerifyCOSESign1(req *VerifyRequest) error {
	if req == nil {
		return fmt.Errorf("%w: nil request", ErrVerificationFailed)
	}

	// The algorithm MUST live in the protected header. Decode it from the
	// ORIGINAL protected bytes without re-encoding them.
	alg, err := protectedAlg(req.Protected)
	if err != nil {
		return err
	}
	if alg != AlgEdDSA {
		return fmt.Errorf("%w: algorithm %d: %w",
			ErrVerificationFailed, alg, ErrUnsupportedAlgorithm)
	}

	key, err := mv.selectKey(req.Unprotected)
	if err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid Ed25519 key size %d",
			ErrVerificationFailed, len(key))
	}

	if !ed25519.Verify(key, req.SigStructure, req.Signature) {
		return fmt.Errorf("%w", ErrVerificationFailed)
	}
	return nil
}

// selectKey resolves the verification key from the unprotected kid header.
func (mv *MemoryVerifier) selectKey(unprotected map[any]cbor.RawMessage) (ed25519.PublicKey, error) {
	rawKid, hasKid := unprotected[labelKid]
	if !hasKid {
		if mv.Default == nil {
			return nil, fmt.Errorf("%w: no default key and message has no kid",
				ErrVerificationFailed)
		}
		return mv.Default, nil
	}
	var kid []byte
	if err := cbor.Unmarshal(rawKid, &kid); err != nil {
		return nil, fmt.Errorf("%w: kid must be a bstr: %v",
			ErrVerificationFailed, err)
	}
	key, ok := mv.Keys[string(kid)]
	if !ok {
		return nil, fmt.Errorf("%w: no key registered for kid %x",
			ErrVerificationFailed, kid)
	}
	return key, nil
}

// protectedAlg decodes the integer "alg" label from a protected header byte
// string. It decodes the original bytes; it does not re-encode them.
func protectedAlg(protected []byte) (int64, error) {
	if len(protected) == 0 {
		return 0, fmt.Errorf("%w: missing alg: %w",
			ErrVerificationFailed, ErrUnsupportedAlgorithm)
	}
	var hdr map[any]cbor.RawMessage
	if err := decMode.Unmarshal(protected, &hdr); err != nil {
		return 0, fmt.Errorf("%w: cannot decode protected header: %v",
			ErrVerificationFailed, err)
	}
	rawAlg, ok := hdr[labelAlg]
	if !ok {
		return 0, fmt.Errorf("%w: missing alg: %w",
			ErrVerificationFailed, ErrUnsupportedAlgorithm)
	}
	var alg int64
	if err := cbor.Unmarshal(rawAlg, &alg); err != nil {
		return 0, fmt.Errorf("%w: alg must be an integer: %v",
			ErrVerificationFailed, err)
	}
	return alg, nil
}

var _ Verifier = (*MemoryVerifier)(nil)
