// Copyright (c) Faye Amacker. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

package cbor

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

// Small (23-byte) CBOR sequence fixture (RFC 8949 Section 8.1):
//
//	01                          -- integer 1
//	9f 01 82 02 03 ff           -- indefinite-length array [1, [2, 3]]
//	6f "hello, CBOR seq"        -- text string
var cborSequenceFixture = []byte{
	0x01,
	0x9f, 0x01, 0x82, 0x02, 0x03, 0xff,
	0x6f,
	'h', 'e', 'l', 'l', 'o', ',', ' ', 'C', 'B', 'O', 'R', ' ', 's', 'e', 'q',
}

func TestSequenceReaderSplitsThreeTopLevelItems(t *testing.T) {
	r := NewSequenceReader(cborSequenceFixture)

	want := []struct {
		start, end int
		decode     any
	}{
		{0, 1, uint64(1)},
		{1, 7, []any{uint64(1), []any{uint64(2), uint64(3)}}},
		{7, 23, "hello, CBOR seq"},
	}

	for i, w := range want {
		item, err := r.Next()
		if err != nil {
			t.Fatalf("item %d: %v", i, err)
		}
		if item.Index != i {
			t.Errorf("item %d: got index %d", i, item.Index)
		}
		if item.Start != w.start || item.End != w.end {
			t.Errorf("item %d: got range [%d:%d], want [%d:%d]", i, item.Start, item.End, w.start, w.end)
		}
		if string(item.Raw) != string(cborSequenceFixture[w.start:w.end]) {
			t.Errorf("item %d: raw bytes % x do not match range % x", i, item.Raw, cborSequenceFixture[w.start:w.end])
		}
		var v any
		if err := Unmarshal(item.Raw, &v); err != nil {
			t.Fatalf("item %d raw not decodable: %v", i, err)
		}
		if !reflect.DeepEqual(v, w.decode) {
			t.Errorf("item %d: decoded to %#v, want %#v", i, v, w.decode)
		}
	}

	// The break code inside the indefinite array (offset 6) was consumed as
	// part of item 1, so the sequence is fully drained now.
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("after last item got %v, want io.EOF", err)
	}
}

func TestSequenceReaderTruncatedLastItemKeepsDeliveredItems(t *testing.T) {
	// Drop 4 bytes from the text string: head declares 15 bytes, only 11
	// remain, so the last top-level item is truncated.
	truncated := cborSequenceFixture[:len(cborSequenceFixture)-4]
	r := NewSequenceReader(truncated)

	wantRanges := [][2]int{{0, 1}, {1, 7}}
	for i, wantRange := range wantRanges {
		item, err := r.Next()
		if err != nil {
			t.Fatalf("item %d should be delivered intact, got %v", i, err)
		}
		if item.Start != wantRange[0] || item.End != wantRange[1] {
			t.Errorf("item %d: got range [%d:%d], want [%d:%d]", i, item.Start, item.End, wantRange[0], wantRange[1])
		}
		// Previously delivered bytes are identical to those in the intact fixture.
		if string(item.Raw) != string(cborSequenceFixture[item.Start:item.End]) {
			t.Errorf("item %d: raw bytes differ from intact fixture", i)
		}
	}

	_, err := r.Next()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated item: got %v, want io.ErrUnexpectedEOF", err)
	}
	// Error is sticky: the bad fragment must never be re-delivered.
	if _, err = r.Next(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("repeated call: got %v, want the same truncation error", err)
	}
}

func TestSequenceReaderRejectsTopLevelBreak(t *testing.T) {
	// Two well-formed items followed by a break code outside any
	// indefinite-length container.
	data := []byte{
		0x01,
		0x9f, 0x01, 0x82, 0x02, 0x03, 0xff,
		0xff,
	}
	r := NewSequenceReader(data)

	if _, err := r.Next(); err != nil {
		t.Fatalf("item 0: %v", err)
	}
	if _, err := r.Next(); err != nil {
		t.Fatalf("item 1: %v", err)
	}
	_, err := r.Next()
	var se *SyntaxError
	if !errors.As(err, &se) {
		t.Fatalf("bare break: got %T (%v), want *SyntaxError", err, err)
	}
	if !strings.Contains(err.Error(), "break") {
		t.Fatalf("bare break error message %q should mention break", err)
	}
}

func TestSequenceReaderEmpty(t *testing.T) {
	r := NewSequenceReader(nil)
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("empty sequence: got %v, want io.EOF", err)
	}
}

func TestSequenceReaderDoesNotReplaceSingleValueDecoder(t *testing.T) {
	var v any
	if err := Unmarshal(cborSequenceFixture[:1], &v); err != nil {
		t.Fatalf("single item still decodable with Unmarshal: %v", err)
	}
	// The original single-value decoder rejects trailing sequence items.
	if err := Unmarshal(cborSequenceFixture, &v); err == nil {
		t.Fatal("Unmarshal of a multi-item sequence should report extraneous data")
	} else {
		var e *ExtraneousDataError
		if !errors.As(err, &e) {
			t.Fatalf("Unmarshal of sequence: got %T, want *ExtraneousDataError", err)
		}
	}
}
