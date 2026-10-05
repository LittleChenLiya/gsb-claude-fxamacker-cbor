// Copyright (c) Faye Amacker. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

// Package cose provides an explicit, low-level reader for COSE_Sign1
// single-signature messages (RFC 9052, section 4.4) layered on top of the
// CBOR codec.
//
// # Security properties
//
// The COSE Sig_structure (RFC 9052, section 4.4) that is signed is built
// from the EXACT byte string carried by the protected header element of the
// message:
//
//	Sig_structure = [
//	  context        : "Signature1",
//	  body_protected : empty_or_serialized_map,
//	  external_aad   : bstr,
//	  payload        : bstr,
//	]
//
// The protected header is decoded only so that its labels can be inspected
// (for example, looking up "alg" inside an injected Verifier). The decoded
// map is never re-encoded to build the signature input. A message whose
// protected header is semantically valid but serialized in a non-canonical
// byte form is therefore verified against the bytes that were actually
// transmitted, defeating canonicalization/normalization attacks that would
// arise from decode-then-reencode verification.
//
// The ordinary CBOR entry points in package cbor are unaffected by this
// package.
package cose

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// COSE_Sign1 tag number, as assigned by RFC 9299 / RFC 9052.
const Sign1TagNumber uint64 = 18

// Sentinel errors returned by this package. Verifier implementations SHOULD
// return errors wrapping ErrVerificationFailed so callers can use errors.Is.
var (
	// ErrMalformed is returned when a COSE_Sign1 message is not structurally
	// valid: bad CBOR, wrong tag/array shape, wrong element types, labels of
	// unsupported types, etc.
	ErrMalformed = errors.New("cose: malformed COSE_Sign1 message")

	// ErrDuplicateLabel is returned before any verification is attempted
	// when the same label appears in both the protected and unprotected
	// header buckets, or when a single header bucket itself contains a
	// duplicate label. RFC 9052 forbids duplicate labels.
	ErrDuplicateLabel = errors.New("cose: duplicate header label")

	// ErrDetachedPayload is returned when Verify is called on a message whose
	// payload is null (detached) without supplying detached content.
	ErrDetachedPayload = errors.New("cose: detached payload requires detached content")

	// ErrVerificationFailed is the canonical error wrapped by verifier
	// implementations for cryptographic failures.
	ErrVerificationFailed = errors.New("cose: signature verification failed")

	// ErrUnsupportedAlgorithm is returned by the built-in verifiers when the
	// "alg" header does not select an algorithm the verifier implements.
	ErrUnsupportedAlgorithm = errors.New("cose: unsupported or missing signature algorithm")
)

// decMode rejects duplicate map keys. It is used for both header buckets so
// that malformed input is rejected structurally (before verification)
// regardless of which bucket carries the duplicate.
var decMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}()

// Sign1 is the parsed, explicit view of a COSE_Sign1 message.
//
// The fields describe the four COSE array elements:
//
//   - ProtectedRaw is the EXACT serialized byte string from the message
//     ("body_protected"). It is copied, not reconstructed, and is the value
//     placed into the Sig_structure for verification.
//   - Protected holds the labels decoded from ProtectedRaw (when non-empty),
//     keyed by int64 (integer labels) or string (text labels), with raw CBOR
//     values. It is exposed for inspection only.
//   - Unprotected holds the decoded unprotected header bucket.
//   - Payload is the inline payload, or nil when the payload element is the
//     CBOR null placeholder (detached payload). An empty bstr is a non-nil,
//     zero-length slice and is NOT detached.
//   - Signature is the signature byte string.
type Sign1 struct {
	ProtectedRaw []byte
	Protected    map[any]cbor.RawMessage
	Unprotected  map[any]cbor.RawMessage
	Payload      []byte
	Signature    []byte

	// payloadDetached records whether element 3 of the message was null.
	payloadDetached bool
}

// Detached reports whether the message carried the CBOR null payload
// placeholder, i.e. the payload must be supplied out of band.
func (m *Sign1) Detached() bool { return m.payloadDetached }

// ReadSign1 parses a COSE_Sign1 message. The message may be the bare
// 4-element array or the same array wrapped in CBOR tag 18; a message wrapped
// in any other tag is rejected.
//
// Structural validation (array shape, element bstr/map types, four-element
// length, duplicate labels) is completed before the returned value may be
// passed to Verify; no cryptographic material is accessed here.
func ReadSign1(data []byte) (*Sign1, error) {
	// Peel off the optional COSE_Sign1 tag (18). The tag content is the array.
	content := data
	var tag cbor.RawTag
	if err := cbor.Unmarshal(data, &tag); err == nil {
		if tag.Number != Sign1TagNumber {
			return nil, fmt.Errorf("%w: unexpected CBOR tag %d (want %d)",
				ErrMalformed, tag.Number, Sign1TagNumber)
		}
		content = tag.Content
	}
	// If data was not tagged, decoding into RawTag yields an
	// UnmarshalTypeError and we fall through to decoding the raw array.

	// Decode the four array elements as raw CBOR items so each element's
	// major type can be checked explicitly. First require exactly four
	// elements (cbor.Unmarshal into a fixed array otherwise truncates), and
	// reject trailing bytes in the same step.
	var anyElems []cbor.RawMessage
	if err := cbor.Unmarshal(content, &anyElems); err != nil {
		return nil, fmt.Errorf("%w: COSE_Sign1 must be a 4-element array: %v",
			ErrMalformed, err)
	}
	if len(anyElems) != 4 {
		return nil, fmt.Errorf("%w: COSE_Sign1 array has %d elements, want 4",
			ErrMalformed, len(anyElems))
	}
	var elems [4]cbor.RawMessage
	copy(elems[:], anyElems)

	// Element 1: protected header, MUST be a bstr (empty or a serialized map).
	protectedRaw, err := decodeBstr(elems[0])
	if err != nil {
		return nil, fmt.Errorf("%w: protected header: %v", ErrMalformed, err)
	}
	protected, err := decodeHeaderMap(protectedRaw)
	if err != nil {
		return nil, wrapHeaderErr("protected header", err)
	}

	// Element 2: unprotected header, MUST be a map.
	unprotected, err := decodeHeaderMap(elems[1])
	if err != nil {
		return nil, wrapHeaderErr("unprotected header", err)
	}

	// RFC 9052: a label MUST NOT be present in both header buckets.
	// Enforced before payload/signature checks and before verification.
	if err := checkOverlap(protected, unprotected); err != nil {
		return nil, err
	}

	// Element 3: payload, bstr or null (detached).
	var payload []byte
	var detached bool
	if isNull(elems[2]) {
		detached = true
	} else {
		payload, err = decodeBstr(elems[2])
		if err != nil {
			return nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
		}
	}

	// Element 4: signature, MUST be a bstr.
	signature, err := decodeBstr(elems[3])
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrMalformed, err)
	}

	return &Sign1{
		ProtectedRaw:    protectedRaw,
		Protected:       protected,
		Unprotected:     unprotected,
		Payload:         payload,
		Signature:       signature,
		payloadDetached: detached,
	}, nil
}

// VerifyRequest is the exact input a Verifier needs to check a signature.
//
// SigStructure is the RFC 9052 Sig_structure to be signed/verified, already
// encoded and ready for the verifier's crypto primitive. Protected is the
// original body_protected byte string from the wire message, copied verbatim;
// it is also the exact bytes embedded in SigStructure. Payload is the
// effective payload (inline content or detached content supplied to Verify).
// AAD is the external Additional Authenticated Data (an empty bstr when none
// was given). Unprotected exposes the unprotected header for key lookup.
type VerifyRequest struct {
	SigStructure []byte
	Protected    []byte
	Payload      []byte
	AAD          []byte
	Signature    []byte
	Unprotected  map[any]cbor.RawMessage
}

// Verifier checks a COSE_Sign1 signature. Cryptography and key selection are
// fully delegated to implementations; this package never reads key files and
// performs no crypto itself.
//
// A failure to verify MUST return an error wrapping ErrVerificationFailed
// (for example fmt.Errorf("...: %w", cose.ErrVerificationFailed)).
type Verifier interface {
	VerifyCOSESign1(*VerifyRequest) error
}

// Verify verifies the message signature using the injected verifier.
//
// detachedPayload is used only when the message carries the null payload
// placeholder; in that case it MUST be non-nil, otherwise ErrDetachedPayload
// is returned without calling the verifier. An empty detached payload is
// valid: pass a non-nil zero-length slice. For an inline-payload message the
// detachedPayload argument is ignored.
//
// externalAAD is spliced into the Sig_structure exactly as supplied; a nil
// value is encoded as the zero-length bstr per RFC 9052.
func (m *Sign1) Verify(v Verifier, detachedPayload, externalAAD []byte) error {
	if v == nil {
		return errors.New("cose: nil verifier")
	}
	payload := m.Payload
	if m.payloadDetached {
		if detachedPayload == nil {
			return ErrDetachedPayload
		}
		payload = detachedPayload
	}
	aad := externalAAD
	if aad == nil {
		aad = []byte{}
	}

	// Build the Sig_structure. The body_protected item is the original
	// byte string wrapped as a CBOR bstr; it is never reconstructed from the
	// decoded protected map. RawMessage items are spliced as pre-encoded
	// CBOR; the []byte items are encoded as CBOR bstr by the codec.
	sigStructure, err := cbor.Marshal([]any{
		"Signature1",
		cbor.RawMessage(wrapBstr(m.ProtectedRaw)),
		aad,
		payload,
	})
	if err != nil {
		return fmt.Errorf("%w: encoding Sig_structure: %v", ErrMalformed, err)
	}

	return v.VerifyCOSESign1(&VerifyRequest{
		SigStructure: sigStructure,
		Protected:    m.ProtectedRaw,
		Payload:      payload,
		AAD:          aad,
		Signature:    m.Signature,
		Unprotected:  m.Unprotected,
	})
}

// wrapHeaderErr preserves the sentinel class of a header-decoding error
// (duplicate labels stay ErrDuplicateLabel) while adding context.
func wrapHeaderErr(bucket string, err error) error {
	if errors.Is(err, ErrDuplicateLabel) {
		return fmt.Errorf("%w: %s: %v", ErrDuplicateLabel, bucket, err)
	}
	return fmt.Errorf("%w: %s: %v", ErrMalformed, bucket, err)
}

// decodeBstr decodes a raw CBOR item that MUST be a byte string and returns a
// copy of its bytes. Empty bstrs return a non-nil zero-length slice so callers
// can distinguish them from a null payload.
func decodeBstr(raw cbor.RawMessage) ([]byte, error) {
	var b []byte
	if err := decMode.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	// Copy defensively so the result never aliases the caller's wire buffer.
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

// decodeHeaderMap decodes a header bucket. data is either empty (empty
// protected header -> empty map) or a serialized CBOR map. Map keys are
// constrained to COSE label types (integer or text string) and duplicate keys
// are rejected. Values remain raw CBOR.
func decodeHeaderMap(data []byte) (map[any]cbor.RawMessage, error) {
	out := make(map[any]cbor.RawMessage)
	if len(data) == 0 {
		return out, nil
	}
	var raw map[any]cbor.RawMessage
	if err := decMode.Unmarshal(data, &raw); err != nil {
		var dup *cbor.DupMapKeyError
		if errors.As(err, &dup) {
			return nil, fmt.Errorf("%w: %v", ErrDuplicateLabel, err)
		}
		return nil, err
	}
	for k, v := range raw {
		label, err := normalizeLabel(k)
		if err != nil {
			return nil, err
		}
		out[label] = v
	}
	return out, nil
}

// normalizeLabel validates a decoded map key and returns a comparable COSE
// label (int64/uint64 for integer labels, string for text labels). Other key
// types are rejected because RFC 9052 labels are limited to integers and text
// strings. Returning a consistent set of types also makes cross-bucket
// duplicate detection reliable.
func normalizeLabel(k any) (any, error) {
	switch v := k.(type) {
	case int64:
		return v, nil
	case uint64:
		return v, nil
	case string:
		return v, nil
	default:
		return nil, fmt.Errorf("header label must be an integer or text string, got %T", k)
	}
}

// checkOverlap rejects labels present in both header buckets (RFC 9052).
func checkOverlap(protected, unprotected map[any]cbor.RawMessage) error {
	for k := range protected {
		if _, ok := unprotected[k]; ok {
			return fmt.Errorf("%w: label %s", ErrDuplicateLabel, labelName(k))
		}
	}
	return nil
}

// labelName renders a label for error messages.
func labelName(k any) string {
	switch v := k.(type) {
	case string:
		return v
	case int64:
		return fmt.Sprintf("%d", v)
	case uint64:
		return fmt.Sprintf("%d", v)
	default:
		return "?"
	}
}

// isNull reports whether a raw CBOR item is the single null byte (0xf6).
func isNull(raw cbor.RawMessage) bool {
	return len(raw) == 1 && raw[0] == 0xf6
}

// wrapBstr encodes a Go byte slice as a standalone CBOR byte string.
func wrapBstr(b []byte) []byte {
	enc, err := cbor.Marshal(b)
	if err != nil {
		// Encoding a []byte cannot fail with the default enc mode.
		panic(err)
	}
	return enc
}
