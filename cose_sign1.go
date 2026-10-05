// Copyright (c) Faye Amacker. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

package cbor

import (
	"errors"
	"fmt"
)

// Sign1Verifier is the backend that verifies a COSE_Sign1 signature.
//
// It is injected into Sign1Reader so that the reader never reads key material
// itself. A verifier may be implemented by an in-memory key, a hardware
// security module, a cloud KMS, or any other signing backend.
type Sign1Verifier interface {
	// Verify verifies signature over sigStructure.
	//
	// sigStructure is the CBOR-encoded Sig_structure for COSE_Sign1 as
	// defined in RFC 9052 Section 4.4:
	//
	//   Sig_structure = [
	//     context : "Signature1",
	//     body_protected : bstr,
	//     external_aad : bstr,
	//     payload : bstr
	//   ]
	//
	// The reader assembles sigStructure (including the external AAD) and
	// passes it to the verifier; the verifier only performs the cryptographic
	// verification.
	Verify(sigStructure, signature []byte) error
}

// Sign1VerifierFunc is an adapter that allows an ordinary function to be used
// as a Sign1Verifier.
type Sign1VerifierFunc func(sigStructure, signature []byte) error

// Verify calls f(sigStructure, signature).
func (f Sign1VerifierFunc) Verify(sigStructure, signature []byte) error {
	return f(sigStructure, signature)
}

// Sign1Message is a parsed COSE_Sign1 message.
type Sign1Message struct {
	// Protected is the raw protected header bstr as encoded on the wire.
	// It is kept verbatim so the exact bytes enter the Sig_structure; the
	// reader never decodes and re-encodes it.
	Protected []byte

	// ProtectedHeader is the decoded protected header map. It is decoded
	// only for inspection; duplicate labels are rejected before verification.
	ProtectedHeader map[any]any

	// Unprotected is the unprotected header map. Duplicate labels are
	// rejected before verification.
	Unprotected map[any]any

	// Payload is the payload. It is the embedded payload, or the detached
	// content supplied to the reader.
	Payload []byte

	// Signature is the signature bytes.
	Signature []byte
}

// Sign1Reader reads and verifies COSE_Sign1 messages.
//
// The reader parses a COSE_Sign1 structure, validates its shape and headers,
// assembles the Sig_structure per RFC 9052, and delegates signature
// verification to the injected Sign1Verifier.
type Sign1Reader struct {
	verifier Sign1Verifier
	decMode  DecMode
	encMode  EncMode
}

// Sign1ReadOptions contains options for reading a COSE_Sign1 message.
type Sign1ReadOptions struct {
	// DetachedContent is the detached payload. It is required when the
	// message payload is nil (detached). It must not be set when the
	// message payload is present.
	DetachedContent []byte

	// ExternalAAD is the external additional authenticated data. It is
	// assembled into the Sig_structure per RFC 9052. If nil, an empty
	// byte string is used.
	ExternalAAD []byte
}

// NewSign1Reader creates a Sign1Reader with the given verifier.
//
// The verifier must be non-nil; the reader never reads key material itself.
func NewSign1Reader(verifier Sign1Verifier) (*Sign1Reader, error) {
	if verifier == nil {
		return nil, errors.New("cbor: Sign1Reader requires a non-nil verifier")
	}
	decMode, err := DecOptions{DupMapKey: DupMapKeyEnforcedAPF}.DecMode()
	if err != nil {
		return nil, fmt.Errorf("cbor: failed to create decoder for Sign1Reader: %w", err)
	}
	encMode, err := CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("cbor: failed to create encoder for Sign1Reader: %w", err)
	}
	return &Sign1Reader{verifier: verifier, decMode: decMode, encMode: encMode}, nil
}

// Read parses and verifies a COSE_Sign1 message.
//
// The validation order is:
//
//  1. The outer structure must be a 4-element array.
//  2. The four element types are checked first: protected must be a bstr,
//     unprotected must be a map, payload must be a bstr or nil, and
//     signature must be a bstr.
//  3. The protected header is decoded; duplicate labels are rejected.
//  4. The unprotected header is decoded; duplicate labels are rejected.
//  5. A nil payload requires detached content.
//  6. The Sig_structure is assembled with the raw protected bstr and the
//     external AAD.
//  7. The injected verifier verifies the signature.
//
// Duplicate labels and missing detached content are rejected before the
// verifier is called.
func (r *Sign1Reader) Read(data []byte, opts Sign1ReadOptions) (*Sign1Message, error) {
	// 1. Parse the outer array.
	var elements []any
	if err := r.decMode.Unmarshal(data, &elements); err != nil {
		return nil, fmt.Errorf("cbor: invalid COSE_Sign1: %w", err)
	}
	if len(elements) != 4 {
		return nil, fmt.Errorf("cbor: COSE_Sign1 must be a 4-element array, got %d elements", len(elements))
	}

	// 2. Verify the four element types first.
	protected, ok := elements[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("cbor: COSE_Sign1 protected header must be a byte string, got %T", elements[0])
	}
	unprotected, ok := elements[1].(map[any]any)
	if !ok {
		return nil, fmt.Errorf("cbor: COSE_Sign1 unprotected header must be a map, got %T", elements[1])
	}
	signature, ok := elements[3].([]byte)
	if !ok {
		return nil, fmt.Errorf("cbor: COSE_Sign1 signature must be a byte string, got %T", elements[3])
	}

	// 3. Decode the protected header map; reject duplicate labels.
	var protectedMap map[any]any
	if len(protected) > 0 {
		if err := r.decMode.Unmarshal(protected, &protectedMap); err != nil {
			return nil, fmt.Errorf("cbor: COSE_Sign1 protected header is not a valid CBOR map: %w", err)
		}
	} else {
		protectedMap = map[any]any{}
	}

	// 4. Resolve the payload; a nil payload requires detached content.
	var payload []byte
	switch p := elements[2].(type) {
	case []byte:
		payload = p
	case nil:
		if opts.DetachedContent == nil {
			return nil, errors.New("cbor: COSE_Sign1 payload is detached but no detached content was provided")
		}
		payload = opts.DetachedContent
	default:
		return nil, fmt.Errorf("cbor: COSE_Sign1 payload must be a byte string or nil, got %T", elements[2])
	}

	// 5. Assemble the Sig_structure per RFC 9052. The raw protected bstr
	// is used verbatim; it is never decoded and re-encoded.
	externalAAD := opts.ExternalAAD
	if externalAAD == nil {
		externalAAD = []byte{}
	}
	sigStructure, err := r.encMode.Marshal(sigStructure{
		Context:       "Signature1",
		BodyProtected: protected,
		ExternalAAD:   externalAAD,
		Payload:       payload,
	})
	if err != nil {
		return nil, fmt.Errorf("cbor: failed to encode Sig_structure: %w", err)
	}

	// 6. Verify via the injected backend.
	if err := r.verifier.Verify(sigStructure, signature); err != nil {
		return nil, fmt.Errorf("cbor: COSE_Sign1 signature verification failed: %w", err)
	}

	return &Sign1Message{
		Protected:       protected,
		ProtectedHeader: protectedMap,
		Unprotected:     unprotected,
		Payload:         payload,
		Signature:       signature,
	}, nil
}

// sigStructure is the COSE Sig_structure for COSE_Sign1.
//
// It is encoded as a 4-element array in field declaration order:
//
//	["Signature1", body_protected, external_aad, payload]
type sigStructure struct {
	_             struct{} `cbor:",toarray"`
	Context       string
	BodyProtected []byte
	ExternalAAD   []byte
	Payload       []byte
}
