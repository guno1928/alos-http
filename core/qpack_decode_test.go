package core

import (
	"errors"
	"testing"
)

// validQPACKHeaderBlock builds a static-only QPACK header block with a
// zero Required Insert Count and zero Delta Base prefix, then appends an
// indexed static-table reference. Index 25 is ":method GET" in the RFC 9204
// static table.
func validQPACKHeaderBlock() []byte {
	var enc QPACKEncoder
	enc.Reset(nil)
	enc.encodeRequiredInsertCount() // RIC=0, Delta Base=0
	enc.encodeIndexedLarge(25)
	return enc.Bytes()
}

func TestQPACKDecodeValidStaticBlock(t *testing.T) {
	var d QPACKDecoder
	headers, err := d.Decode(validQPACKHeaderBlock())
	if err != nil {
		t.Fatalf("valid static block rejected: %v", err)
	}
	if len(headers) != 1 {
		t.Fatalf("got %d headers, want 1", len(headers))
	}
	if headers[0] != qpackStaticTable[25] {
		t.Fatalf("got %v, want %v", headers[0], qpackStaticTable[25])
	}
}

func TestQPACKDecodeLiteralWithStaticNameRef(t *testing.T) {
	var enc QPACKEncoder
	enc.Reset(nil)
	enc.encodeRequiredInsertCount()
	// content-length (static name index 23) with a literal value.
	enc.encodeLiteralWithNameRef(qpackFindStaticNameIndex("content-length"), "42")

	var d QPACKDecoder
	headers, err := d.Decode(enc.Bytes())
	if err != nil {
		t.Fatalf("valid literal-with-name-ref rejected: %v", err)
	}
	if len(headers) != 1 || headers[0][0] != "content-length" || headers[0][1] != "42" {
		t.Fatalf("got %v, want [content-length 42]", headers)
	}
}

func TestQPACKDecodeRejectsNonzeroRIC(t *testing.T) {
	// RIC=1 in the 8-bit prefix; we advertise zero dynamic capacity.
	block := append([]byte{0x01, 0x00}, validQPACKHeaderBlock()[2:]...)

	var d QPACKDecoder
	if _, err := d.Decode(block); !errors.Is(err, ErrQPACKDecompressionFailed) {
		t.Fatalf("nonzero RIC: got err %v, want ErrQPACKDecompressionFailed", err)
	}
}

func TestQPACKDecodeRejectsOutOfRangeStaticIndex(t *testing.T) {
	var enc QPACKEncoder
	enc.Reset(nil)
	enc.encodeRequiredInsertCount()
	// Index 999 is far beyond the static table.
	enc.encodeIndexedLarge(999)

	var d QPACKDecoder
	if _, err := d.Decode(enc.Bytes()); !errors.Is(err, ErrQPACKDecompressionFailed) {
		t.Fatalf("out-of-range static index: got err %v, want ErrQPACKDecompressionFailed", err)
	}
}

func TestQPACKDecodeRejectsOutOfRangeStaticNameRef(t *testing.T) {
	var enc QPACKEncoder
	enc.Reset(nil)
	enc.encodeRequiredInsertCount()
	// Literal with a static name reference past the end of the table.
	enc.encodeLiteralWithNameRef(999, "x")

	var d QPACKDecoder
	if _, err := d.Decode(enc.Bytes()); !errors.Is(err, ErrQPACKDecompressionFailed) {
		t.Fatalf("out-of-range static name ref: got err %v, want ErrQPACKDecompressionFailed", err)
	}
}

func TestQPACKDecodeRejectsDynamicIndexedRef(t *testing.T) {
	var enc QPACKEncoder
	enc.Reset(nil)
	enc.encodeRequiredInsertCount()
	// Indexed reference with the static bit cleared (dynamic table), which
	// cannot exist because dynamic capacity is zero. 0x80 = indexed, T=0.
	enc.buf = append(enc.buf, 0x80)

	var d QPACKDecoder
	if _, err := d.Decode(enc.Bytes()); !errors.Is(err, ErrQPACKDecompressionFailed) {
		t.Fatalf("dynamic indexed ref: got err %v, want ErrQPACKDecompressionFailed", err)
	}
}
