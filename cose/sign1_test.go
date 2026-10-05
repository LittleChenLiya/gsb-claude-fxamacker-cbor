// Copyright (c) Faye Amacker. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

package cose_test

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/fxamacker/cbor/v2/cose"
)

// ---- hand-rolled CBOR (keeps the test independent of how production builds
// bytes, and gives exact control over non-canonical encodings) ----

func head(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 0xff:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 0xffff:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	case n <= 0xffffffff:
		return []byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		return []byte{major<<5 | 27,
			byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func cbUint(n uint64) []byte { return head(0, n) }
func cbNint(n uint64) []byte { return head(1, n) } // -1-n
func cbBstr(b []byte) []byte { return append(head(2, uint64(len(b))), b...) }
func cbText(s string) []byte { return append(head(3, uint64(len(s))), s...) }
func cbArray(n int) []byte   { return head(4, uint64(n)) }
func cbMap(n int) []byte     { return head(5, uint64(n)) }
func cbTag(n uint64) []byte  { return head(6, n) }

var cbNull = []byte{0xf6}

// encodeSign1 builds a COSE_Sign1 message (tag 18 wrapping the 4-array).
// payload == nil encodes the null placeholder (detached); an empty (non-nil)
// slice encodes an empty bstr.
func encodeSign1(protectedMap, unprotectedMap, payload, sig []byte, tagged bool) []byte {
	var e []byte
	e = append(e, cbBstr(protectedMap)...)
	e = append(e, unprotectedMap...)
	if payload == nil {
		e = append(e, cbNull...)
	} else {
		e = append(e, cbBstr(payload)...)
	}
	e = append(e, cbBstr(sig)...)
	arr := append(cbArray(4), e...)
	if tagged {
		return append(cbTag(cose.Sign1TagNumber), arr...)
	}
	return arr
}

// sigStructure independently builds the RFC 9052 Sig_structure bytes.
func sigStructure(protectedMap, aad, payload []byte) []byte {
	var e []byte
	e = append(e, cbText("Signature1")...)
	e = append(e, cbBstr(protectedMap)...) // original bytes, not re-encoded
	if aad == nil {
		aad = []byte{}
	}
	e = append(e, cbBstr(aad)...)
	e = append(e, cbBstr(payload)...)
	return append(cbArray(4), e...)
}

// ---- fixtures ----

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

// protected header {1: -8} in canonical (minimal) bytes.
func protectedCanonical() []byte {
	e := append(cbMap(1), cbUint(1)...)
	return append(e, cbNint(7)...) // -8
}

// protected header {1: -8} in NON-canonical but semantically identical bytes:
// key 1 encoded as an 0x18-prefixed one-byte uint. Decodes to the same map but
// has different bytes.
func protectedNonCanonical() []byte {
	e := append(cbMap(1), 0x18, 0x01) // uint 1 in non-minimal form
	return append(e, cbNint(7)...)
}

func unprotectedWithKid(kid []byte) []byte {
	e := append(cbMap(1), cbUint(4)...) // kid label
	return append(e, cbBstr(kid)...)
}

var someKid = []byte("key-0")

// verifierFor returns a MemoryVerifier that resolves both the default key and
// the someKid key to pub (fixtures tag messages with someKid).
func verifierFor(pub ed25519.PublicKey) *cose.MemoryVerifier {
	mv := cose.NewMemoryVerifier(pub)
	mv.AddKey(someKid, pub)
	return mv
}

// recordingVerifier records the request and returns cannedErr (nil = pass).
type recordingVerifier struct {
	calls     int
	got       *cose.VerifyRequest
	cannedErr error
}

func (r *recordingVerifier) VerifyCOSESign1(req *cose.VerifyRequest) error {
	r.calls++
	r.got = req
	return r.cannedErr
}

// ---- acceptance tests ----

func TestProtectedRawBytesVerbatim(t *testing.T) {
	pub, priv := testKey(t)
	unprot := unprotectedWithKid(someKid)
	payload := []byte("hello cose")

	canonical := protectedCanonical()
	nonCanonical := protectedNonCanonical()
	if equalBytes(canonical, nonCanonical) {
		t.Fatal("fixture error: protected variants must differ in bytes")
	}
	// Sanity: both decode to the same map.
	var m1, m2 map[any]any
	if err := cbor.Unmarshal(canonical, &m1); err != nil {
		t.Fatal(err)
	}
	if err := cbor.Unmarshal(nonCanonical, &m2); err != nil {
		t.Fatal(err)
	}

	for name, prot := range map[string][]byte{"canonical": canonical, "noncanonical": nonCanonical} {
		t.Run(name, func(t *testing.T) {
			sig := ed25519.Sign(priv, sigStructure(prot, nil, payload))
			msg := encodeSign1(prot, unprot, payload, sig, true)

			m, err := cose.ReadSign1(msg)
			if err != nil {
				t.Fatalf("ReadSign1: %v", err)
			}
			if !equalBytes(m.ProtectedRaw, prot) {
				t.Fatalf("ProtectedRaw = %x, want original bytes %x", m.ProtectedRaw, prot)
			}

			rec := &recordingVerifier{}
			if err := m.Verify(rec, nil, nil); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if rec.calls != 1 {
				t.Fatalf("verifier called %d times", rec.calls)
			}
			if !equalBytes(rec.got.Protected, prot) {
				t.Fatalf("verifier saw protected %x, want %x", rec.got.Protected, prot)
			}
			wantStruct := sigStructure(prot, nil, payload)
			if !equalBytes(rec.got.SigStructure, wantStruct) {
				t.Fatalf("SigStructure mismatch:\n got %x\nwant %x", rec.got.SigStructure, wantStruct)
			}

			// The injected crypto backend must verify using original bytes.
			mv := verifierFor(pub)
			if err := m.Verify(mv, nil, nil); err != nil {
				t.Fatalf("MemoryVerifier: %v", err)
			}
		})
	}

	// A signature produced over the canonical form must NOT validate a message
	// carrying the non-canonical protected bytes (proves the reader does not
	// re-encode before verify).
	sigCanonical := ed25519.Sign(priv, sigStructure(canonical, nil, payload))
	msgSwapped := encodeSign1(nonCanonical, unprot, payload, sigCanonical, true)
	m, err := cose.ReadSign1(msgSwapped)
	if err != nil {
		t.Fatal(err)
	}
	mv := verifierFor(pub)
	if err := m.Verify(mv, nil, nil); !errors.Is(err, cose.ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed for canonicalized signature, got %v", err)
	}
}

func TestDuplicateLabelRejectedBeforeVerify(t *testing.T) {
	_, _ = testKey(t)
	prot := protectedCanonical() // {1: -8}

	// Same label (1) in both protected and unprotected buckets.
	overlap := append(cbMap(1), cbUint(1)...)
	overlap = append(overlap, cbNint(6)...) // value -7, content irrelevant

	msg := encodeSign1(prot, overlap, []byte("p"), []byte("s"), true)
	m, err := cose.ReadSign1(msg)
	if !errors.Is(err, cose.ErrDuplicateLabel) {
		t.Fatalf("overlap: want ErrDuplicateLabel, got %v (msg=%v)", err, m)
	}
	if m != nil {
		rec := &recordingVerifier{}
		if err := m.Verify(rec, nil, nil); err == nil {
			t.Fatal("verify on rejected message unexpectedly succeeded")
		}
	}

	// Duplicate key inside the protected bucket itself.
	dupProt := append(cbMap(2), cbUint(1)...)
	dupProt = append(dupProt, cbNint(7)...)
	dupProt = append(dupProt, cbUint(1)...)
	dupProt = append(dupProt, cbNint(6)...)
	msg = encodeSign1(dupProt, cbMap(0), []byte("p"), []byte("s"), false)
	if _, err := cose.ReadSign1(msg); !errors.Is(err, cose.ErrDuplicateLabel) {
		t.Fatalf("dup in protected: want ErrDuplicateLabel, got %v", err)
	}

	// Duplicate key inside the unprotected bucket itself.
	dupUnprot := append(cbMap(2), cbUint(4)...)
	dupUnprot = append(dupUnprot, cbBstr([]byte("a"))...)
	dupUnprot = append(dupUnprot, cbUint(4)...)
	dupUnprot = append(dupUnprot, cbBstr([]byte("b"))...)
	msg = encodeSign1(prot, dupUnprot, []byte("p"), []byte("s"), false)
	if _, err := cose.ReadSign1(msg); !errors.Is(err, cose.ErrDuplicateLabel) {
		t.Fatalf("dup in unprotected: want ErrDuplicateLabel, got %v", err)
	}
}

func TestDetachedPayload(t *testing.T) {
	pub, priv := testKey(t)
	unprot := unprotectedWithKid(someKid)
	content := []byte("detached-content")
	prot := protectedCanonical()

	// Null payload, signature over detached content.
	sig := ed25519.Sign(priv, sigStructure(prot, nil, content))
	msg := encodeSign1(prot, unprot, nil, sig, true)
	m, err := cose.ReadSign1(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Detached() {
		t.Fatal("expected Detached()=true")
	}

	// No detached content supplied -> fail before the verifier runs.
	rec := &recordingVerifier{}
	if err := m.Verify(rec, nil, nil); !errors.Is(err, cose.ErrDetachedPayload) {
		t.Fatalf("want ErrDetachedPayload, got %v", err)
	}
	if rec.calls != 0 {
		t.Fatal("verifier must not be called when detached content missing")
	}

	// Correct detached content supplied -> passes the injected backend.
	if err := m.Verify(verifierFor(pub), content, nil); err != nil {
		t.Fatalf("detached verify: %v", err)
	}

	// Empty (zero-length) detached content is legal but must be a non-nil
	// slice; nil still means "not provided".
	emptySig := ed25519.Sign(priv, sigStructure(prot, nil, []byte{}))
	emptyMsg := encodeSign1(prot, unprot, nil, emptySig, false)
	em, err := cose.ReadSign1(emptyMsg)
	if err != nil {
		t.Fatal(err)
	}
	if err := em.Verify(verifierFor(pub), []byte{}, nil); err != nil {
		t.Fatalf("empty detached verify: %v", err)
	}
	if err := em.Verify(verifierFor(pub), nil, nil); !errors.Is(err, cose.ErrDetachedPayload) {
		t.Fatalf("nil detached content must fail, got %v", err)
	}

	// Inline payload: detached argument is ignored.
	inlineSig := ed25519.Sign(priv, sigStructure(prot, nil, content))
	inlineMsg := encodeSign1(prot, unprot, content, inlineSig, true)
	im, err := cose.ReadSign1(inlineMsg)
	if err != nil {
		t.Fatal(err)
	}
	if im.Detached() {
		t.Fatal("inline payload must not report detached")
	}
	if err := im.Verify(verifierFor(pub), []byte("ignored"), nil); err != nil {
		t.Fatalf("inline verify should ignore detached arg: %v", err)
	}
}

func TestElementTypesAndShape(t *testing.T) {
	prot := protectedCanonical()
	unprot := cbMap(0)
	goodPayload := []byte("p")
	goodSig := []byte("s")

	cases := map[string]struct {
		// build returns the array/tag content
		build  func() []byte
		tagged bool
	}{
		"protected is int not bstr": {
			build: func() []byte { return encodeRawArray(cbUint(5), unprot, cbBstr(goodPayload), cbBstr(goodSig)) },
		},
		"unprotected is array not map": {
			build: func() []byte { return encodeRawArray(cbBstr(prot), cbArray(0), cbBstr(goodPayload), cbBstr(goodSig)) },
		},
		"payload is int not bstr": {
			build: func() []byte { return encodeRawArray(cbBstr(prot), unprot, cbUint(5), cbBstr(goodSig)) },
		},
		"signature is int not bstr": {
			build: func() []byte { return encodeRawArray(cbBstr(prot), unprot, cbBstr(goodPayload), cbUint(5)) },
		},
		"protected bstr not a map": {
			build: func() []byte { return encodeRawArray(cbBstr(cbUint(1)), unprot, cbBstr(goodPayload), cbBstr(goodSig)) },
		},
		"three elements": {
			build: func() []byte {
				e := append(cbArray(3), cbBstr(prot)...)
				e = append(e, unprot...)
				e = append(e, cbBstr(goodPayload)...)
				return e
			},
		},
		"five elements": {
			build: func() []byte {
				e := append(cbArray(5), cbBstr(prot)...)
				e = append(e, unprot...)
				e = append(e, cbBstr(goodPayload)...)
				e = append(e, cbBstr(goodSig)...)
				e = append(e, cbNull...)
				return e
			},
		},
		"label key is bstr": {
			build: func() []byte {
				bad := append(cbMap(1), cbBstr([]byte("x"))...)
				bad = append(bad, cbNull...)
				return encodeRawArray(cbBstr(prot), bad, cbBstr(goodPayload), cbBstr(goodSig))
			},
		},
		"trailing bytes": {
			build: func() []byte {
				return append(encodeRawArray(cbBstr(prot), unprot, cbBstr(goodPayload), cbBstr(goodSig)), 0x00)
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := cose.ReadSign1(tc.build()); !errors.Is(err, cose.ErrMalformed) {
				t.Fatalf("want ErrMalformed, got %v", err)
			}
		})
	}

	// Wrong tag number rejected.
	badTag := append(cbTag(998), encodeRawArray(cbBstr(prot), unprot, cbBstr(goodPayload), cbBstr(goodSig))...)
	if _, err := cose.ReadSign1(badTag); !errors.Is(err, cose.ErrMalformed) {
		t.Fatalf("wrong tag: want ErrMalformed, got %v", err)
	}

	// Bare array and tag 18 both accepted.
	bare := encodeRawArray(cbBstr(prot), unprot, cbBstr(goodPayload), cbBstr(goodSig))
	if _, err := cose.ReadSign1(bare); err != nil {
		t.Fatalf("bare array: %v", err)
	}
	tagged := append(cbTag(18), bare...)
	if _, err := cose.ReadSign1(tagged); err != nil {
		t.Fatalf("tag 18: %v", err)
	}
}

// encodeRawArray wraps four pre-encoded raw items in a 4-array.
func encodeRawArray(items ...[]byte) []byte {
	e := cbArray(len(items))
	for _, it := range items {
		e = append(e, it...)
	}
	return e
}

func TestExternalAAD(t *testing.T) {
	pub, priv := testKey(t)
	prot := protectedCanonical()
	unprot := unprotectedWithKid(someKid)
	payload := []byte("payload")
	aad := []byte("the-aad")

	sig := ed25519.Sign(priv, sigStructure(prot, aad, payload))
	msg := encodeSign1(prot, unprot, payload, sig, true)
	m, err := cose.ReadSign1(msg)
	if err != nil {
		t.Fatal(err)
	}
	mv := verifierFor(pub)
	if err := m.Verify(mv, nil, aad); err != nil {
		t.Fatalf("verify with AAD: %v", err)
	}
	// Wrong AAD -> verification failure; nil AAD is empty bstr, != aad.
	if err := m.Verify(mv, nil, []byte("other")); !errors.Is(err, cose.ErrVerificationFailed) {
		t.Fatalf("wrong AAD: want ErrVerificationFailed, got %v", err)
	}
	if err := m.Verify(mv, nil, nil); !errors.Is(err, cose.ErrVerificationFailed) {
		t.Fatalf("missing AAD: want ErrVerificationFailed, got %v", err)
	}

	// AAD handed to verifier verbatim.
	rec := &recordingVerifier{}
	if err := m.Verify(rec, nil, aad); err != nil {
		t.Fatal(err)
	}
	if !equalBytes(rec.got.AAD, aad) {
		t.Fatalf("AAD = %x want %x", rec.got.AAD, aad)
	}
}

func TestMemoryVerifierKidAndAlg(t *testing.T) {
	pub, priv := testKey(t)
	prot := protectedCanonical()
	payload := []byte("p")
	kid := []byte("k-42")

	sig := ed25519.Sign(priv, sigStructure(prot, nil, payload))
	msg := encodeSign1(prot, unprotectedWithKid(kid), payload, sig, true)
	m, err := cose.ReadSign1(msg)
	if err != nil {
		t.Fatal(err)
	}

	// Verifier without the kid fails.
	mv := cose.NewMemoryVerifier(nil)
	if err := m.Verify(mv, nil, nil); !errors.Is(err, cose.ErrVerificationFailed) {
		t.Fatalf("unknown kid: want fail, got %v", err)
	}

	// Register key under kid.
	mv.AddKey(kid, pub)
	if err := m.Verify(mv, nil, nil); err != nil {
		t.Fatalf("keyed verify: %v", err)
	}

	// Corrupt signature -> failure.
	bad := encodeSign1(prot, unprotectedWithKid(kid), payload, []byte("deadbeefsig"), true)
	bm, _ := cose.ReadSign1(bad)
	if err := bm.Verify(mv, nil, nil); !errors.Is(err, cose.ErrVerificationFailed) {
		t.Fatalf("bad signature: want fail, got %v", err)
	}

	// Unsupported algorithm (ES256 = -7) rejected.
	es256 := append(cbMap(1), cbUint(1)...)
	es256 = append(es256, cbNint(6)...) // -7
	esSig := ed25519.Sign(priv, sigStructure(es256, nil, payload))
	esMsg := encodeSign1(es256, cbMap(0), payload, esSig, true)
	esm, err := cose.ReadSign1(esMsg)
	if err != nil {
		t.Fatal(err)
	}
	if err := esm.Verify(cose.NewMemoryVerifier(pub), nil, nil); !errors.Is(err, cose.ErrUnsupportedAlgorithm) {
		t.Fatalf("ES256: want ErrUnsupportedAlgorithm, got %v", err)
	}

	// Missing alg (empty protected) rejected.
	noalgSig := ed25519.Sign(priv, sigStructure(nil, nil, payload))
	noalgMsg := encodeSign1(nil, cbMap(0), payload, noalgSig, true)
	nm, err := cose.ReadSign1(noalgMsg)
	if err != nil {
		t.Fatal(err)
	}
	if err := nm.Verify(cose.NewMemoryVerifier(pub), nil, nil); !errors.Is(err, cose.ErrUnsupportedAlgorithm) {
		t.Fatalf("no alg: want ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestNoAliasingOfInputBuffer(t *testing.T) {
	pub, priv := testKey(t)
	prot := protectedCanonical()
	payload := []byte("payload-bytes")
	sig := ed25519.Sign(priv, sigStructure(prot, nil, payload))
	built := encodeSign1(prot, unprotectedWithKid(someKid), payload, sig, true)
	msg := append([]byte(nil), built...) // independent buffer to mutate

	m, err := cose.ReadSign1(msg)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the caller's wire buffer after parsing.
	for i := range msg {
		msg[i] = 0
	}
	if !equalBytes(m.ProtectedRaw, prot) {
		t.Fatalf("ProtectedRaw aliased input: %x", m.ProtectedRaw)
	}
	if !equalBytes(m.Payload, payload) {
		t.Fatalf("Payload aliased input: %x", m.Payload)
	}
	if !equalBytes(m.Signature, sig) {
		t.Fatalf("Signature aliased input: %x", m.Signature)
	}
	if err := m.Verify(verifierFor(pub), nil, nil); err != nil {
		t.Fatalf("verify after input mutation: %v", err)
	}
}

func TestNilVerifier(t *testing.T) {
	pub, priv := testKey(t)
	prot := protectedCanonical()
	sig := ed25519.Sign(priv, sigStructure(prot, nil, []byte("p")))
	msg := encodeSign1(prot, cbMap(0), []byte("p"), sig, false)
	m, err := cose.ReadSign1(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(nil, nil, nil); err == nil {
		t.Fatal("nil verifier should error")
	}
	_ = pub
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
