// Copyright (c) Faye Amacker. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

package cbor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// tagWhitelistSpy is a cbor.Unmarshaler that records how many times its
// UnmarshalCBOR method is invoked.
type tagWhitelistSpy struct {
	calls int
	data  []byte
}

func (s *tagWhitelistSpy) UnmarshalCBOR(data []byte) error {
	s.calls++
	s.data = append([]byte(nil), data...)
	return nil
}

// TestTagWhitelistNested checks that a tag whitelist is enforced on every
// nested tag (not just the outermost one) using three small encodings:
// an allowed tag inside an array, a rejected tag nested two arrays deep,
// and a plain (non-tag) value.
func TestTagWhitelistNested(t *testing.T) {
	dm, err := DecOptions{TagWhitelist: NewTagWhitelist(1000)}.DecMode()
	if err != nil {
		t.Fatalf("DecMode() returned error %v", err)
	}

	testCases := []struct {
		name        string
		data        []byte
		wantValue   any
		wantErr     bool
		wantTagNum  uint64
		wantErrPath string
		wantErrMsg  string
	}{
		{
			name:      "allowed tag in array",
			data:      mustHexDecode("81d903e801"), // [1000(1)]
			wantValue: []any{Tag{Number: 1000, Content: uint64(1)}},
		},
		{
			name:        "rejected tag nested two levels deep",
			data:        mustHexDecode("8181d903e701"), // [[999(1)]]
			wantErr:     true,
			wantTagNum:  999,
			wantErrPath: "[0][0]",
			wantErrMsg:  "cbor: tag number 999 is not allowed by tag whitelist at [0][0]",
		},
		{
			name:      "plain value",
			data:      mustHexDecode("01"), // 1
			wantValue: uint64(1),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var v any
			err := dm.Unmarshal(tc.data, &v)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("Unmarshal() returned error %v", err)
				}
				if !reflect.DeepEqual(v, tc.wantValue) {
					t.Errorf("Unmarshal() = %v (%T), want %v (%T)", v, v, tc.wantValue, tc.wantValue)
				}
				return
			}

			var tagErr *TagNotAllowedError
			if !errors.As(err, &tagErr) {
				t.Fatalf("Unmarshal() error = %v (%T), want *TagNotAllowedError", err, err)
			}
			if tagErr.TagNum != tc.wantTagNum {
				t.Errorf("TagNotAllowedError.TagNum = %d, want %d", tagErr.TagNum, tc.wantTagNum)
			}
			if tagErr.Path != tc.wantErrPath {
				t.Errorf("TagNotAllowedError.Path = %q, want %q", tagErr.Path, tc.wantErrPath)
			}
			if err.Error() != tc.wantErrMsg {
				t.Errorf("TagNotAllowedError.Error() = %q, want %q", err.Error(), tc.wantErrMsg)
			}
		})
	}
}

// TestTagWhitelistUnmarshalerSpy checks that a registered (Unmarshaler)
// decoder is only invoked after its tag is allowed by the whitelist: on
// rejection the spy must see zero calls and the error must carry the tag
// number and container path.
func TestTagWhitelistUnmarshalerSpy(t *testing.T) {
	data := mustHexDecode("d903e701") // 999(1)

	// Rejected: tag 999 is not in the whitelist.
	dmReject, err := DecOptions{TagWhitelist: NewTagWhitelist(1000)}.DecMode()
	if err != nil {
		t.Fatalf("DecMode() returned error %v", err)
	}
	var spy tagWhitelistSpy
	err = dmReject.Unmarshal(data, &spy)
	var tagErr *TagNotAllowedError
	if !errors.As(err, &tagErr) {
		t.Fatalf("Unmarshal() error = %v (%T), want *TagNotAllowedError", err, err)
	}
	if tagErr.TagNum != 999 {
		t.Errorf("TagNotAllowedError.TagNum = %d, want 999", tagErr.TagNum)
	}
	if tagErr.Path != "" {
		t.Errorf("TagNotAllowedError.Path = %q, want empty (top-level tag)", tagErr.Path)
	}
	if spy.calls != 0 {
		t.Errorf("spy UnmarshalCBOR calls = %d, want 0 (decoder must not run for rejected tag)", spy.calls)
	}

	// Allowed: tag 999 is in the whitelist.
	dmAllow, err := DecOptions{TagWhitelist: NewTagWhitelist(999)}.DecMode()
	if err != nil {
		t.Fatalf("DecMode() returned error %v", err)
	}
	spy = tagWhitelistSpy{}
	if err := dmAllow.Unmarshal(data, &spy); err != nil {
		t.Fatalf("Unmarshal() returned error %v", err)
	}
	if spy.calls != 1 {
		t.Errorf("spy UnmarshalCBOR calls = %d, want 1", spy.calls)
	}
}

// tagWhitelistRegisteredContent is a named type registered in a TagSet.
type tagWhitelistRegisteredContent struct {
	N int `cbor:"n"`
}

// TestTagWhitelistRegisteredTag checks that the whitelist is enforced before
// registered tag content decoders run, for both interface and concrete
// destination types.
func TestTagWhitelistRegisteredTag(t *testing.T) {
	tags := NewTagSet()
	if err := tags.Add(
		TagOptions{DecTag: DecTagRequired, EncTag: EncTagRequired},
		reflect.TypeOf(tagWhitelistRegisteredContent{}),
		1000,
	); err != nil {
		t.Fatalf("TagSet.Add() returned error %v", err)
	}

	data := mustHexDecode("d903e8a1616e01") // 1000({"n": 1})

	// Allowed tag: registered content decodes normally.
	dmAllow, err := DecOptions{TagWhitelist: NewTagWhitelist(1000)}.DecModeWithTags(tags)
	if err != nil {
		t.Fatalf("DecModeWithTags() returned error %v", err)
	}
	var v any
	if err := dmAllow.Unmarshal(data, &v); err != nil {
		t.Fatalf("Unmarshal() returned error %v", err)
	}
	if want := (tagWhitelistRegisteredContent{N: 1}); !reflect.DeepEqual(v, want) {
		t.Errorf("Unmarshal() = %v (%T), want %v (%T)", v, v, want, want)
	}

	// Rejected tag: registered content decoder is never reached.
	dmReject, err := DecOptions{TagWhitelist: NewTagWhitelist(2000)}.DecModeWithTags(tags)
	if err != nil {
		t.Fatalf("DecModeWithTags() returned error %v", err)
	}
	for _, dst := range []any{new(any), new(tagWhitelistRegisteredContent)} {
		err := dmReject.Unmarshal(data, dst)
		var tagErr *TagNotAllowedError
		if !errors.As(err, &tagErr) {
			t.Fatalf("Unmarshal() into %T error = %v (%T), want *TagNotAllowedError", dst, err, err)
		}
		if tagErr.TagNum != 1000 {
			t.Errorf("TagNotAllowedError.TagNum = %d, want 1000", tagErr.TagNum)
		}
		if tagErr.Path != "" {
			t.Errorf("TagNotAllowedError.Path = %q, want empty", tagErr.Path)
		}
	}
}

// TestTagWhitelistNilDefaultUnchanged checks that decoding behavior is
// unchanged when no tag whitelist is set (default tag policy).
func TestTagWhitelistNilDefaultUnchanged(t *testing.T) {
	data := mustHexDecode("8181d903e701") // [[999(1)]]

	// Default mode (no whitelist): nested unrecognized tags decode to cbor.Tag.
	var v any
	if err := Unmarshal(data, &v); err != nil {
		t.Fatalf("Unmarshal() returned error %v", err)
	}
	want := []any{[]any{Tag{Number: 999, Content: uint64(1)}}}
	if !reflect.DeepEqual(v, want) {
		t.Errorf("Unmarshal() = %v (%T), want %v (%T)", v, v, want, want)
	}

	// Explicit DecMode without whitelist behaves the same.
	dm, err := DecOptions{}.DecMode()
	if err != nil {
		t.Fatalf("DecMode() returned error %v", err)
	}
	v = nil
	if err := dm.Unmarshal(data, &v); err != nil {
		t.Fatalf("Unmarshal() returned error %v", err)
	}
	if !reflect.DeepEqual(v, want) {
		t.Errorf("Unmarshal() = %v (%T), want %v (%T)", v, v, want, want)
	}
}

// TestTagWhitelistDecOptions checks that DecMode.DecOptions() round-trips
// the TagWhitelist option.
func TestTagWhitelistDecOptions(t *testing.T) {
	wl := NewTagWhitelist(1000, 2000)
	dm, err := DecOptions{TagWhitelist: wl}.DecMode()
	if err != nil {
		t.Fatalf("DecMode() returned error %v", err)
	}
	if dm.DecOptions().TagWhitelist != wl {
		t.Errorf("DecOptions().TagWhitelist = %v, want %v", dm.DecOptions().TagWhitelist, wl)
	}

	dmDefault, err := DecOptions{}.DecMode()
	if err != nil {
		t.Fatalf("DecMode() returned error %v", err)
	}
	if dmDefault.DecOptions().TagWhitelist != nil {
		t.Errorf("DecOptions().TagWhitelist = %v, want nil", dmDefault.DecOptions().TagWhitelist)
	}
}

// TestTagWhitelistDemo decodes the three small acceptance fixtures plus a
// map-nested rejection with a whitelist-enabled DecMode, and writes a small
// report to a temporary directory to demonstrate the results.
func TestTagWhitelistDemo(t *testing.T) {
	dm, err := DecOptions{TagWhitelist: NewTagWhitelist(1000)}.DecMode()
	if err != nil {
		t.Fatalf("DecMode() returned error %v", err)
	}

	fixtures := []struct {
		name string
		hex  string
	}{
		{"allowed tag in array [1000(1)]", "81d903e801"},
		{"rejected nested tag [[999(1)]]", "8181d903e701"},
		{"plain value 1", "01"},
		{"rejected tag in map value {\"a\":[999(1)]}", "a1616181d903e701"},
	}

	var sb strings.Builder
	sb.WriteString("tag whitelist demo (whitelist: [1000])\n")
	for _, f := range fixtures {
		var v any
		err := dm.Unmarshal(mustHexDecode(f.hex), &v)
		if err != nil {
			fmt.Fprintf(&sb, "%-45s hex=%s -> error: %v\n", f.name, f.hex, err)
		} else {
			fmt.Fprintf(&sb, "%-45s hex=%s -> value: %#v\n", f.name, f.hex, v)
		}
	}

	report := sb.String()
	path := filepath.Join(t.TempDir(), "tag_whitelist_demo.txt")
	if err := os.WriteFile(path, []byte(report), 0o600); err != nil {
		t.Fatalf("failed to write demo report: %v", err)
	}
	t.Logf("demo report written to %s\n%s", path, report)
}
