// Copyright (c) Faye Amacker. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

package cbor

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

// hmacVerifier is an in-memory Sign1Verifier that verifies a COSE_Sign1
// signature using HMAC-SHA256 with an in-memory key. It never reads key
// material from disk.
type hmacVerifier struct {
	key []byte
}

func (v *hmacVerifier) Verify(sigStructure, signature []byte) error {
	mac := hmac.New(sha256.New, v.key)
	mac.Write(sigStructure)
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, signature) {
		return errors.New("cose: signature mismatch")
	}
	return nil
}

// sign1Message is a helper for encoding COSE_Sign1 messages in tests.
type sign1Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[any]any
	Payload     []byte
	Signature   []byte
}

// sign1DetachedMessage is a helper for encoding COSE_Sign1 messages with a
// nil payload (detached content).
type sign1DetachedMessage struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[any]any
	Payload     any // nil for detached
	Signature   []byte
}

// signSigStructure computes the Sig_structure for COSE_Sign1 and signs it
// with the in-memory HMAC key.
func signSigStructure(t *testing.T, key, protected, externalAAD, payload []byte) []byte {
	t.Helper()
	enc, err := CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("failed to create encoder: %v", err)
	}
	if externalAAD == nil {
		externalAAD = []byte{}
	}
	sigStructure, err := enc.Marshal(sigStructure{
		Context:       "Signature1",
		BodyProtected: protected,
		ExternalAAD:   externalAAD,
		Payload:       payload,
	})
	if err != nil {
		t.Fatalf("failed to encode Sig_structure: %v", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(sigStructure)
	return mac.Sum(nil)
}

func TestSign1ReaderEmbeddedPayload(t *testing.T) {
	key := []byte("secret-key")
	verifier := &hmacVerifier{key: key}
	reader, err := NewSign1Reader(verifier)
	if err != nil {
		t.Fatalf("NewSign1Reader failed: %v", err)
	}

	protected := []byte{} // empty protected header
	unprotected := map[any]any{int64(4): "test"}
	payload := []byte("hello world")
	signature := signSigStructure(t, key, protected, nil, payload)

	msg := sign1Message{
		Protected:   protected,
		Unprotected: unprotected,
		Payload:     payload,
		Signature:   signature,
	}
	data, err := Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal message: %v", err)
	}

	got, err := reader.Read(data, Sign1ReadOptions{})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(got.Payload) != "hello world" {
		t.Errorf("payload = %q, want %q", got.Payload, "hello world")
	}
	if len(got.Protected) != 0 {
		t.Errorf("protected = %x, want empty", got.Protected)
	}
}

func TestSign1ReaderDetachedPayload(t *testing.T) {
	key := []byte("secret-key")
	verifier := &hmacVerifier{key: key}
	reader, err := NewSign1Reader(verifier)
	if err != nil {
		t.Fatalf("NewSign1Reader failed: %v", err)
	}

	protected := []byte{}
	unprotected := map[any]any{}
	detachedContent := []byte("detached payload")
	signature := signSigStructure(t, key, protected, nil, detachedContent)

	msg := sign1DetachedMessage{
		Protected:   protected,
		Unprotected: unprotected,
		Payload:     nil, // detached
		Signature:   signature,
	}
	data, err := Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal message: %v", err)
	}

	// Without detached content, Read must fail.
	if _, err := reader.Read(data, Sign1ReadOptions{}); err == nil {
		t.Error("Read with detached payload and no detached content should fail, but succeeded")
	}

	// With detached content, Read must succeed.
	got, err := reader.Read(data, Sign1ReadOptions{DetachedContent: detachedContent})
	if err != nil {
		t.Fatalf("Read with detached content failed: %v", err)
	}
	if string(got.Payload) != "detached payload" {
		t.Errorf("payload = %q, want %q", got.Payload, "detached payload")
	}
}

func TestSign1ReaderDetachedMissingContentFails(t *testing.T) {
	key := []byte("secret-key")
	verifier := &hmacVerifier{key: key}
	reader, err := NewSign1Reader(verifier)
	if err != nil {
		t.Fatalf("NewSign1Reader failed: %v", err)
	}

	protected := []byte{}
	unprotected := map[any]any{}
	// Sign with empty payload (the reader will require detached content).
	signature := signSigStructure(t, key, protected, nil, []byte{})

	msg := sign1DetachedMessage{
		Protected:   protected,
		Unprotected: unprotected,
		Payload:     nil,
		Signature:   signature,
	}
	data, err := Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal message: %v", err)
	}

	_, err = reader.Read(data, Sign1ReadOptions{})
	if err == nil {
		t.Error("Read should fail when detached content is missing")
	}
}

func TestSign1ReaderExternalAAD(t *testing.T) {
	key := []byte("secret-key")
	verifier := &hmacVerifier{key: key}
	reader, err := NewSign1Reader(verifier)
	if err != nil {
		t.Fatalf("NewSign1Reader failed: %v", err)
	}

	protected := []byte{}
	unprotected := map[any]any{}
	payload := []byte("payload")
	externalAAD := []byte("external-aad-data")
	// Sign with the external AAD assembled into the Sig_structure.
	signature := signSigStructure(t, key, protected, externalAAD, payload)

	msg := sign1Message{
		Protected:   protected,
		Unprotected: unprotected,
		Payload:     payload,
		Signature:   signature,
	}
	data, err := Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal message: %v", err)
	}

	// Without the AAD, verification must fail.
	if _, err := reader.Read(data, Sign1ReadOptions{}); err == nil {
		t.Error("Read without external AAD should fail verification, but succeeded")
	}

	// With the AAD, verification must succeed.
	got, err := reader.Read(data, Sign1ReadOptions{ExternalAAD: externalAAD})
	if err != nil {
		t.Fatalf("Read with external AAD failed: %v", err)
	}
	if string(got.Payload) != "payload" {
		t.Errorf("payload = %q, want %q", got.Payload, "payload")
	}
}

func TestSign1ReaderDuplicateProtectedLabelRejected(t *testing.T) {
	key := []byte("secret-key")
	verifier := &hmacVerifier{key: key}
	reader, err := NewSign1Reader(verifier)
	if err != nil {
		t.Fatalf("NewSign1Reader failed: %v", err)
	}

	// Build a protected header with a duplicate label (key 1 appears twice).
	// This is semantically invalid and must be rejected before verification.
	protected := []byte{0xa2, 0x01, 0x26, 0x01, 0x03} // map(2){1:-7, 1:-3}
	unprotected := map[any]any{}
	payload := []byte("payload")
	signature := signSigStructure(t, key, protected, nil, payload)

	msg := sign1Message{
		Protected:   protected,
		Unprotected: unprotected,
		Payload:     payload,
		Signature:   signature,
	}
	data, err := Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal message: %v", err)
	}

	_, err = reader.Read(data, Sign1ReadOptions{})
	if err == nil {
		t.Error("Read with duplicate protected label should fail, but succeeded")
	}
}

func TestSign1ReaderDuplicateUnprotectedLabelRejected(t *testing.T) {
	key := []byte("secret-key")
	verifier := &hmacVerifier{key: key}
	reader, err := NewSign1Reader(verifier)
	if err != nil {
		t.Fatalf("NewSign1Reader failed: %v", err)
	}

	protected := []byte{}
	payload := []byte("payload")
	signature := signSigStructure(t, key, protected, nil, payload)

	// Manually craft the unprotected map bytes with a duplicate key.
	unprotectedBytes := []byte{0xa2, 0x04, 0x78, 0x01, 0x61, 0x78, 0x04, 0x79, 0x61, 0x79} // map(2){4:"x", 4:"y"}

	// Encode the full message manually so we can inject the duplicate map.
	var buf []byte
	buf = append(buf, 0x84)      // array(4)
	buf = append(buf, 0x40)      // protected: empty bstr
	buf = append(buf, unprotectedBytes...)
	buf = append(buf, 0x47)      // payload: bstr(7)
	buf = append(buf, payload...)
	buf = append(buf, 0x58, 0x20) // signature: bstr(32)
	buf = append(buf, signature...)

	_, err = reader.Read(buf, Sign1ReadOptions{})
	if err == nil {
		t.Error("Read with duplicate unprotected label should fail, but succeeded")
	}
}

func TestSign1ReaderSemanticallySameProtectedDifferentBytes(t *testing.T) {
	key := []byte("secret-key")
	verifier := &hmacVerifier{key: key}
	reader, err := NewSign1Reader(verifier)
	if err != nil {
		t.Fatalf("NewSign1Reader failed: %v", err)
	}

	// Two protected headers that decode to the same map but have different
	// bytes (different key order). The reader must use each one's raw bytes
	// in the Sig_structure.
	protectedA := []byte{0xa2, 0x01, 0x26, 0x04, 0x78, 0x01, 0x78} // map(2){1:-7, 4:"x"}
	protectedB := []byte{0xa2, 0x04, 0x78, 0x01, 0x78, 0x01, 0x26} // map(2){4:"x", 1:-7}

	payload := []byte("payload")

	// Sign each message with its own raw protected bytes.
	sigA := signSigStructure(t, key, protectedA, nil, payload)
	sigB := signSigStructure(t, key, protectedB, nil, payload)

	msgA := sign1Message{
		Protected:   protectedA,
		Unprotected: map[any]any{},
		Payload:     payload,
		Signature:   sigA,
	}
	msgB := sign1Message{
		Protected:   protectedB,
		Unprotected: map[any]any{},
		Payload:     payload,
		Signature:   sigB,
	}

	dataA, err := Marshal(msgA)
	if err != nil {
		t.Fatalf("failed to marshal msgA: %v", err)
	}
	dataB, err := Marshal(msgB)
	if err != nil {
		t.Fatalf("failed to marshal msgB: %v", err)
	}

	// Both must verify because the reader uses the raw bytes.
	if _, err := reader.Read(dataA, Sign1ReadOptions{}); err != nil {
		t.Errorf("Read msgA failed: %v", err)
	}
	if _, err := reader.Read(dataB, Sign1ReadOptions{}); err != nil {
		t.Errorf("Read msgB failed: %v", err)
	}

	// Cross-verification must fail: sigA was signed with protectedA bytes,
	// but msgB has protectedB bytes. This proves the reader does not
	// re-encode the protected header.
	msgBWithSigA := sign1Message{
		Protected:   protectedB,
		Unprotected: map[any]any{},
		Payload:     payload,
		Signature:   sigA,
	}
	dataBWithSigA, err := Marshal(msgBWithSigA)
	if err != nil {
		t.Fatalf("failed to marshal msgBWithSigA: %v", err)
	}
	if _, err := reader.Read(dataBWithSigA, Sign1ReadOptions{}); err == nil {
		t.Error("cross-verification should fail: reader must use raw protected bytes")
	}
}

func TestSign1ReaderWrongElementCount(t *testing.T) {
	key := []byte("secret-key")
	verifier := &hmacVerifier{key: key}
	reader, err := NewSign1Reader(verifier)
	if err != nil {
		t.Fatalf("NewSign1Reader failed: %v", err)
	}

	// A 3-element array is not a valid COSE_Sign1.
	data := []byte{0x83, 0x40, 0xa0, 0x40} // array(3)
	_, err = reader.Read(data, Sign1ReadOptions{})
	if err == nil {
		t.Error("Read with wrong element count should fail, but succeeded")
	}
}

func TestSign1ReaderWrongElementType(t *testing.T) {
	key := []byte("secret-key")
	verifier := &hmacVerifier{key: key}
	reader, err := NewSign1Reader(verifier)
	if err != nil {
		t.Fatalf("NewSign1Reader failed: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "protected is not bstr",
			data: []byte{0x84, 0x01, 0xa0, 0x40, 0x40}, // protected: int(1)
		},
		{
			name: "unprotected is not map",
			data: []byte{0x84, 0x40, 0x01, 0x40, 0x40}, // unprotected: int(1)
		},
		{
			name: "payload is not bstr or nil",
			data: []byte{0x84, 0x40, 0xa0, 0x01, 0x40}, // payload: int(1)
		},
		{
			name: "signature is not bstr",
			data: []byte{0x84, 0x40, 0xa0, 0x40, 0x01}, // signature: int(1)
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := reader.Read(tc.data, Sign1ReadOptions{})
			if err == nil {
				t.Errorf("Read with %s should fail, but succeeded", tc.name)
			}
		})
	}
}

func TestSign1ReaderNilVerifier(t *testing.T) {
	_, err := NewSign1Reader(nil)
	if err == nil {
		t.Error("NewSign1Reader with nil verifier should fail, but succeeded")
	}
}

func TestSign1ReaderInvalidCBOR(t *testing.T) {
	key := []byte("secret-key")
	verifier := &hmacVerifier{key: key}
	reader, err := NewSign1Reader(verifier)
	if err != nil {
		t.Fatalf("NewSign1Reader failed: %v", err)
	}

	_, err = reader.Read([]byte{0xff}, Sign1ReadOptions{})
	if err == nil {
		t.Error("Read with invalid CBOR should fail, but succeeded")
	}
}

func TestSign1VerifierFunc(t *testing.T) {
	key := []byte("secret-key")
	verifier := Sign1VerifierFunc(func(sigStructure, signature []byte) error {
		mac := hmac.New(sha256.New, key)
		mac.Write(sigStructure)
		expected := mac.Sum(nil)
		if !hmac.Equal(expected, signature) {
			return fmt.Errorf("signature mismatch")
		}
		return nil
	})
	reader, err := NewSign1Reader(verifier)
	if err != nil {
		t.Fatalf("NewSign1Reader failed: %v", err)
	}

	protected := []byte{}
	payload := []byte("payload")
	signature := signSigStructure(t, key, protected, nil, payload)
	msg := sign1Message{
		Protected:   protected,
		Unprotected: map[any]any{},
		Payload:     payload,
		Signature:   signature,
	}
	data, err := Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal message: %v", err)
	}
	if _, err := reader.Read(data, Sign1ReadOptions{}); err != nil {
		t.Errorf("Read with Sign1VerifierFunc failed: %v", err)
	}
}

// countingVerifier records whether it was called.
type countingVerifier struct {
	called bool
}

func (v *countingVerifier) Verify(sigStructure, signature []byte) error {
	v.called = true
	return nil
}

func TestSign1ReaderVerifierNotCalledOnValidationFailure(t *testing.T) {
	key := []byte("secret-key")

	// Protected header with a duplicate label.
	protected := []byte{0xa2, 0x01, 0x26, 0x01, 0x03} // map(2){1:-7, 1:-3}
	payload := []byte("payload")
	signature := signSigStructure(t, key, protected, nil, payload)

	msg := sign1Message{
		Protected:   protected,
		Unprotected: map[any]any{},
		Payload:     payload,
		Signature:   signature,
	}
	data, err := Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal message: %v", err)
	}

	verifier := &countingVerifier{}
	reader, err := NewSign1Reader(verifier)
	if err != nil {
		t.Fatalf("NewSign1Reader failed: %v", err)
	}

	if _, err := reader.Read(data, Sign1ReadOptions{}); err == nil {
		t.Error("Read with duplicate protected label should fail, but succeeded")
	}
	if verifier.called {
		t.Error("verifier must not be called when duplicate protected label is rejected")
	}

	// Detached payload with no detached content must also not call the verifier.
	verifier2 := &countingVerifier{}
	reader2, err := NewSign1Reader(verifier2)
	if err != nil {
		t.Fatalf("NewSign1Reader failed: %v", err)
	}
	msgDetached := sign1DetachedMessage{
		Protected:   []byte{},
		Unprotected: map[any]any{},
		Payload:     nil,
		Signature:   signature,
	}
	dataDetached, err := Marshal(msgDetached)
	if err != nil {
		t.Fatalf("failed to marshal detached message: %v", err)
	}
	if _, err := reader2.Read(dataDetached, Sign1ReadOptions{}); err == nil {
		t.Error("Read with detached payload and no content should fail, but succeeded")
	}
	if verifier2.called {
		t.Error("verifier must not be called when detached content is missing")
	}
}
