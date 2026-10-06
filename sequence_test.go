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

// sequenceFixture is a small CBOR sequence (RFC 8742) of three top-level items:
//
//	01                -- item 0: unsigned integer 1
//	9f 01 02 ff       -- item 1: indefinite-length array [1, 2]
//	63 61 62 63       -- item 2: text string "abc"
var sequenceFixture = []byte{
	0x01,
	0x9f, 0x01, 0x02, 0xff,
	0x63, 0x61, 0x62, 0x63,
}

var sequenceFixtureItems = []SequenceItem{
	{Index: 0, Start: 0, End: 1},
	{Index: 1, Start: 1, End: 5},
	{Index: 2, Start: 5, End: 9},
}

func TestSplitSequence(t *testing.T) {
	items, err := SplitSequence(sequenceFixture)
	if err != nil {
		t.Fatalf("SplitSequence() returned error %v", err)
	}
	if !reflect.DeepEqual(items, sequenceFixtureItems) {
		t.Errorf("SplitSequence() = %+v, want %+v", items, sequenceFixtureItems)
	}

	// Raw bytes of each item must round-trip through the single-value decoder.
	want := []any{uint64(1), []any{uint64(1), uint64(2)}, "abc"}
	for i, item := range items {
		raw := item.Bytes(sequenceFixture)
		var v any
		if err := Unmarshal(raw, &v); err != nil {
			t.Errorf("Unmarshal(item %d bytes %x) returned error %v", i, raw, err)
			continue
		}
		if !reflect.DeepEqual(v, want[i]) {
			t.Errorf("item %d decoded to %v (%T), want %v (%T)", i, v, v, want[i], want[i])
		}
	}
}

func TestSplitSequenceTruncatedLastItem(t *testing.T) {
	// Drop the last byte of the final text string.
	truncated := sequenceFixture[:len(sequenceFixture)-1]

	items, err := SplitSequence(truncated)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("SplitSequence() error = %v, want io.ErrUnexpectedEOF", err)
	}
	// The two complete items before the truncation must still be delivered.
	if !reflect.DeepEqual(items, sequenceFixtureItems[:2]) {
		t.Errorf("SplitSequence() = %+v, want %+v", items, sequenceFixtureItems[:2])
	}
}

func TestSplitSequenceExtraneousBreak(t *testing.T) {
	// A "break" stop code outside any indefinite-length container.
	data := []byte{0x01, 0xff, 0x02}

	items, err := SplitSequence(data)
	if err == nil {
		t.Fatal("SplitSequence() didn't return error for extraneous break")
	}
	var synErr *SyntaxError
	if !errors.As(err, &synErr) {
		t.Errorf("SplitSequence() error = %v (%T), want *SyntaxError", err, err)
	}
	if !strings.Contains(err.Error(), "break") {
		t.Errorf("SplitSequence() error = %q, want mention of break", err.Error())
	}
	// The item before the illegal break must still be delivered.
	want := []SequenceItem{{Index: 0, Start: 0, End: 1}}
	if !reflect.DeepEqual(items, want) {
		t.Errorf("SplitSequence() = %+v, want %+v", items, want)
	}
}

func TestSequenceReaderNext(t *testing.T) {
	r := NewSequenceReader(sequenceFixture)
	for _, want := range sequenceFixtureItems {
		item, err := r.Next()
		if err != nil {
			t.Fatalf("Next() returned error %v", err)
		}
		if item != want {
			t.Errorf("Next() = %+v, want %+v", item, want)
		}
	}
	if _, err := r.Next(); err != io.EOF {
		t.Errorf("Next() after last item = %v, want io.EOF", err)
	}
}

func TestSequenceReaderTruncatedLastItem(t *testing.T) {
	r := NewSequenceReader(sequenceFixture[:len(sequenceFixture)-1])

	for i, want := range sequenceFixtureItems[:2] {
		item, err := r.Next()
		if err != nil {
			t.Fatalf("Next() item %d returned error %v", i, err)
		}
		if item != want {
			t.Errorf("Next() = %+v, want %+v", item, want)
		}
	}

	// Truncated final item reports io.ErrUnexpectedEOF...
	if _, err := r.Next(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Next() = %v, want io.ErrUnexpectedEOF", err)
	}
	// ...and previously delivered items are not redelivered on retry.
	if _, err := r.Next(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("Next() after truncation = %v, want io.ErrUnexpectedEOF (no redelivery)", err)
	}
}

func TestSequenceReaderBreakInsideIndefiniteContainer(t *testing.T) {
	// The break terminating the indefinite-length array must not end the
	// sequence: the item after the array is still delivered as a top-level item.
	r := NewSequenceReader(sequenceFixture)

	if _, err := r.Next(); err != nil {
		t.Fatalf("Next() item 0 returned error %v", err)
	}
	item, err := r.Next()
	if err != nil {
		t.Fatalf("Next() item 1 returned error %v", err)
	}
	if item.End != 5 {
		t.Errorf("indefinite-length array item ended at %d, want 5 (break belongs to the array)", item.End)
	}
	item, err = r.Next()
	if err != nil {
		t.Fatalf("Next() item 2 returned error %v", err)
	}
	if item.Index != 2 || item.Start != 5 || item.End != 9 {
		t.Errorf("Next() = %+v, want {Index:2 Start:5 End:9}", item)
	}
}

func TestSplitSequenceEmpty(t *testing.T) {
	items, err := SplitSequence(nil)
	if err != nil {
		t.Fatalf("SplitSequence(nil) returned error %v", err)
	}
	if len(items) != 0 {
		t.Errorf("SplitSequence(nil) = %+v, want no items", items)
	}
}
