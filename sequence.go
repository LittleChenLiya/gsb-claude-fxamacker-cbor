// Copyright (c) Faye Amacker. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

package cbor

import "io"

// SequenceItem describes one top-level CBOR data item read from a CBOR
// sequence (RFC 8949, Section 8.1).
type SequenceItem struct {
	// Index is the zero-based ordinal of the data item within the sequence.
	Index int

	// Start is the offset of the first byte of the data item within the
	// slice passed to NewSequenceReader.
	Start int

	// End is the offset immediately following the last byte of the data
	// item, so the item's raw CBOR encoding is data[Start:End].
	End int

	// Raw is the raw CBOR encoding of the data item. It aliases the slice
	// passed to NewSequenceReader and must be copied if it needs to outlive
	// that slice.
	Raw []byte
}

// SequenceReader reads top-level CBOR data items from a CBOR sequence held in
// a single byte slice, one item at a time. It is intended for small sequences
// only: the whole sequence must already be in memory, and SequenceReader does
// not implement any incremental or chunked input protocol.
//
// Break codes (0xff) inside indefinite-length arrays, maps, and strings are
// consumed as part of their container and never terminate a top-level item.
// A break code outside any indefinite-length container is rejected.
type SequenceReader struct {
	d     decoder
	index int
	err   error // sticky: first error (other than io.EOF) encountered
}

// NewSequenceReader returns a SequenceReader that reads the CBOR sequence in
// data using the default decoding options.
func NewSequenceReader(data []byte) *SequenceReader {
	return defaultDecMode.NewSequenceReader(data)
}

// NewSequenceReader returns a SequenceReader that reads the CBOR sequence in
// data using dm decoding options.
func (dm *decMode) NewSequenceReader(data []byte) *SequenceReader {
	return &SequenceReader{d: decoder{data: data, dm: dm}}
}

// Next returns the next top-level CBOR data item along with its raw byte
// range and zero-based index. It returns io.EOF when every item has been
// delivered.
//
// If the next item is truncated or otherwise not well-formed (including a
// break code found at the top level), Next returns the error and does not
// deliver the bad item. All items delivered earlier stay valid, keep their
// byte ranges, and are never repeated.
func (r *SequenceReader) Next() (*SequenceItem, error) {
	if r.err != nil {
		return nil, r.err
	}
	if len(r.d.data) == r.d.off {
		return nil, io.EOF
	}
	start := r.d.off
	// Validate exactly one top-level item. Further items are allowed to
	// follow but are not consumed. Break codes inside indefinite-length
	// containers are handled inside wellformedInternal and cannot end the
	// top-level item.
	if err := r.d.wellformed(true, false); err != nil {
		// Make the error sticky so a trailing fragment of the bad item can
		// never be re-delivered as a new top-level item.
		r.err = err
		return nil, err
	}
	end := r.d.off
	item := &SequenceItem{
		Index: r.index,
		Start: start,
		End:   end,
		Raw:   r.d.data[start:end],
	}
	r.index++
	return item, nil
}
