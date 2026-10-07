// Copyright (c) Faye Amacker. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

package cbor

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// whitelistSpy is a registered tag content type that counts how many times
// its registered decoder (UnmarshalCBOR) is invoked.
type whitelistSpy struct {
	raw []byte
}

var whitelistSpyCalls int

func (s *whitelistSpy) UnmarshalCBOR(data []byte) error {
	whitelistSpyCalls++
	s.raw = append([]byte(nil), data...)
	return nil
}

// Small in-memory fixtures (CBOR encodings).
var (
	// 55798 = 0xd9f6, 9999 = 0x270f.
	fixtureArrayWithAllowedTag = []byte{0x81, 0xd9, 0xd9, 0xf6, 0x61, 0x61}             // [55798("a")]
	fixtureDoubleNestedBadTag  = []byte{0xd9, 0xd9, 0xf6, 0xd9, 0x27, 0x0f, 0x61, 0x61} // 55798(9999("a"))
	fixtureArrayWithBadTag     = []byte{0x82, 0x01, 0xd9, 0x27, 0x0f, 0x61, 0x61}       // [1, 9999("a")]
	fixturePlainValue          = []byte{0x18, 0x2a}                                     // 42
)

func newNestedTagWhitelistDecMode(t *testing.T) DecMode {
	t.Helper()
	tags := NewTagSet()
	if err := tags.Add(TagOptions{DecTag: DecTagOptional, EncTag: EncTagNone}, reflect.TypeOf(whitelistSpy{}), 55798); err != nil {
		t.Fatalf("failed to register tag: %v", err)
	}
	dm, err := DecOptions{NestedTagWhitelist: NestedTagWhitelistEnforced}.DecModeWithTags(tags)
	if err != nil {
		t.Fatalf("failed to create DecMode: %v", err)
	}
	return dm
}

// TestNestedTagWhitelistArrayWithAllowedTag decodes an array containing a
// whitelisted (registered) tag. The registered decoder is invoked exactly once.
func TestNestedTagWhitelistArrayWithAllowedTag(t *testing.T) {
	dm := newNestedTagWhitelistDecMode(t)

	whitelistSpyCalls = 0
	var v any
	if err := dm.Unmarshal(fixtureArrayWithAllowedTag, &v); err != nil {
		t.Fatalf("Unmarshal() returned error %v", err)
	}
	if whitelistSpyCalls != 1 {
		t.Errorf("registered decoder invoked %d times, want 1", whitelistSpyCalls)
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 1 {
		t.Fatalf("decoded value = %#v, want []any of length 1", v)
	}
	if _, ok := arr[0].(whitelistSpy); !ok {
		t.Errorf("decoded element type = %T, want cbor.whitelistSpy", arr[0])
	}
}

// TestNestedTagWhitelistDoubleNestedTagRejected decodes a double-nested tag
// whose inner tag (9999) is not whitelisted. Decoding fails before the
// registered decoder is invoked, and the error records tag number and path.
func TestNestedTagWhitelistDoubleNestedTagRejected(t *testing.T) {
	dm := newNestedTagWhitelistDecMode(t)

	whitelistSpyCalls = 0
	var v whitelistSpy
	err := dm.Unmarshal(fixtureDoubleNestedBadTag, &v)
	if err == nil {
		t.Fatal("Unmarshal() didn't return error")
	}
	var wlErr *TagWhitelistError
	if !errors.As(err, &wlErr) {
		t.Fatalf("error type = %T, want *TagWhitelistError", err)
	}
	if wlErr.TagNum != 9999 {
		t.Errorf("TagWhitelistError.TagNum = %d, want 9999", wlErr.TagNum)
	}
	if wlErr.Path != "$" {
		t.Errorf("TagWhitelistError.Path = %q, want %q", wlErr.Path, "$")
	}
	if whitelistSpyCalls != 0 {
		t.Errorf("registered decoder invoked %d times, want 0", whitelistSpyCalls)
	}
}

// TestNestedTagWhitelistRejectedTagPath checks the container path recorded in
// TagWhitelistError for a rejected tag nested inside an array.
func TestNestedTagWhitelistRejectedTagPath(t *testing.T) {
	dm := newNestedTagWhitelistDecMode(t)

	var v any
	err := dm.Unmarshal(fixtureArrayWithBadTag, &v)
	var wlErr *TagWhitelistError
	if !errors.As(err, &wlErr) {
		t.Fatalf("error = %v (%T), want *TagWhitelistError", err, err)
	}
	if wlErr.TagNum != 9999 {
		t.Errorf("TagWhitelistError.TagNum = %d, want 9999", wlErr.TagNum)
	}
	if wlErr.Path != "$[1]" {
		t.Errorf("TagWhitelistError.Path = %q, want %q", wlErr.Path, "$[1]")
	}
}

// TestNestedTagWhitelistPlainValueUnchanged decodes a plain (untagged) value
// with the whitelist enforced; behavior is unchanged.
func TestNestedTagWhitelistPlainValueUnchanged(t *testing.T) {
	dm := newNestedTagWhitelistDecMode(t)

	whitelistSpyCalls = 0
	var v any
	if err := dm.Unmarshal(fixturePlainValue, &v); err != nil {
		t.Fatalf("Unmarshal() returned error %v", err)
	}
	if v != uint64(42) {
		t.Errorf("decoded value = %#v, want uint64(42)", v)
	}
	if whitelistSpyCalls != 0 {
		t.Errorf("registered decoder invoked %d times, want 0", whitelistSpyCalls)
	}
}

// TestNestedTagWhitelistDisabledByDefault verifies that the default tag
// policy is unchanged: nested unregistered tags decode to cbor.Tag without error.
func TestNestedTagWhitelistDisabledByDefault(t *testing.T) {
	var v any
	if err := Unmarshal(fixtureDoubleNestedBadTag, &v); err != nil {
		t.Fatalf("Unmarshal() returned error %v", err)
	}
	tag, ok := v.(Tag)
	if !ok {
		t.Fatalf("decoded value type = %T, want cbor.Tag", v)
	}
	if tag.Number != 55798 {
		t.Errorf("outer tag number = %d, want 55798", tag.Number)
	}
	inner, ok := tag.Content.(Tag)
	if !ok {
		t.Fatalf("inner content type = %T, want cbor.Tag", tag.Content)
	}
	if inner.Number != 9999 || inner.Content != "a" {
		t.Errorf("inner tag = %v(%v), want 9999(a)", inner.Number, inner.Content)
	}
}

// TestNestedTagWhitelistDecOptionsRoundTrip verifies the option is exposed by
// DecMode.DecOptions() and that invalid mode values are rejected.
func TestNestedTagWhitelistDecOptionsRoundTrip(t *testing.T) {
	dm := newNestedTagWhitelistDecMode(t)
	if got := dm.DecOptions().NestedTagWhitelist; got != NestedTagWhitelistEnforced {
		t.Errorf("DecOptions().NestedTagWhitelist = %d, want %d", got, NestedTagWhitelistEnforced)
	}

	if _, err := (DecOptions{NestedTagWhitelist: maxNestedTagWhitelistMode}).DecMode(); err == nil {
		t.Error("DecMode() with invalid NestedTagWhitelist didn't return error")
	}
}

// TestNestedTagWhitelistTempDirFixtures decodes the same fixtures from files
// in a temporary directory to demonstrate the behavior with file-based input.
func TestNestedTagWhitelistTempDirFixtures(t *testing.T) {
	dm := newNestedTagWhitelistDecMode(t)
	dir := t.TempDir()

	fixtures := map[string][]byte{
		"allowed.cbor":  fixtureArrayWithAllowedTag,
		"rejected.cbor": fixtureDoubleNestedBadTag,
		"plain.cbor":    fixturePlainValue,
	}
	for name, data := range fixtures {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	whitelistSpyCalls = 0
	var allowed any
	if err := dm.Unmarshal(read("allowed.cbor"), &allowed); err != nil {
		t.Errorf("allowed.cbor: Unmarshal() returned error %v", err)
	}
	if whitelistSpyCalls != 1 {
		t.Errorf("allowed.cbor: registered decoder invoked %d times, want 1", whitelistSpyCalls)
	}

	whitelistSpyCalls = 0
	var rejected whitelistSpy
	err := dm.Unmarshal(read("rejected.cbor"), &rejected)
	var wlErr *TagWhitelistError
	if !errors.As(err, &wlErr) {
		t.Errorf("rejected.cbor: error = %v (%T), want *TagWhitelistError", err, err)
	} else if wlErr.TagNum != 9999 || wlErr.Path != "$" {
		t.Errorf("rejected.cbor: TagWhitelistError = %+v, want TagNum 9999 at $", wlErr)
	}
	if whitelistSpyCalls != 0 {
		t.Errorf("rejected.cbor: registered decoder invoked %d times, want 0", whitelistSpyCalls)
	}

	var plain any
	if err := dm.Unmarshal(read("plain.cbor"), &plain); err != nil {
		t.Errorf("plain.cbor: Unmarshal() returned error %v", err)
	}
	if plain != uint64(42) {
		t.Errorf("plain.cbor: decoded value = %#v, want uint64(42)", plain)
	}
}
