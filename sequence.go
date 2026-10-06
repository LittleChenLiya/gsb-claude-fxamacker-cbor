// Copyright (c) Faye Amacker. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

package cbor

import (
	"io"
	"strconv"
)

// SequenceItem describes one top-level CBOR data item in a CBOR sequence (RFC 8742).
// It reports the item's zero-based position in the sequence and the raw byte range
// the item occupies in the input buffer.
type SequenceItem struct {
	// Index is the zero-based sequence number of the item.
	Index int
	// Start is the byte offset of the first byte of the encoded item.
	Start int
	// End is the byte offset one past the last byte of the encoded item.
	End int
}

// Bytes returns the raw encoded bytes of the item within data.
// data must be the same buffer the item was read from.
func (item SequenceItem) Bytes(data []byte) []byte {
	return data[item.Start:item.End]
}

// SequenceReader reads the top-level data items of a CBOR sequence (RFC 8742)
// one at a time from an in-memory buffer. It is intended for small sequences
// that already fit in memory; it does not buffer or reassemble streamed chunks.
//
// A "break" stop code (0xff) inside an indefinite-length container terminates
// that container only; it is never reported as the end of a top-level item.
//
// The single-value decoding entry points (Unmarshal, Decoder, etc.) are
// unaffected by SequenceReader.
type SequenceReader struct {
	data []byte
	off  int // offset of the next top-level item
	next int // index of the next top-level item
}

// NewSequenceReader returns a SequenceReader that reads top-level CBOR data
// items from data. data is not copied and must not be modified while reading.
func NewSequenceReader(data []byte) *SequenceReader {
	return &SequenceReader{data: data}
}

// Next returns the raw byte range and sequence number of the next top-level
// CBOR data item.
//
// Next returns io.EOF when the sequence is fully consumed. If the final item
// is truncated, Next returns io.ErrUnexpectedEOF and items already returned
// remain valid; no item is returned more than once. A "break" stop code
// outside an indefinite-length container is reported as a *SyntaxError.
func (r *SequenceReader) Next() (SequenceItem, error) {
	if r.off == len(r.data) {
		return SequenceItem{}, io.EOF
	}
	d := decoder{data: r.data, off: r.off, dm: defaultDecMode}
	if err := d.wellformed(true, false); err != nil {
		return SequenceItem{}, err
	}
	item := SequenceItem{Index: r.next, Start: r.off, End: d.off}
	r.off = d.off
	r.next++
	return item, nil
}

// SplitSequence splits data into the top-level data items of a CBOR sequence
// (RFC 8742), returning each item's raw byte range and sequence number.
// It is a convenience wrapper around SequenceReader for small sequences.
//
// If the final item is truncated, SplitSequence returns the items completed
// before the truncation (without duplicating any item) together with
// io.ErrUnexpectedEOF. A "break" stop code outside an indefinite-length
// container is reported as a *SyntaxError.
func SplitSequence(data []byte) ([]SequenceItem, error) {
	r := NewSequenceReader(data)
	var items []SequenceItem
	for {
		item, err := r.Next()
		if err == io.EOF {
			return items, nil
		}
		if err != nil {
			return items, err
		}
		items = append(items, item)
	}
}

// String returns a human-readable description of the item's position and range.
func (item SequenceItem) String() string {
	return "item " + strconv.Itoa(item.Index) + " at bytes [" + strconv.Itoa(item.Start) + ", " + strconv.Itoa(item.End) + ")"
}
