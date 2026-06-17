package core

import (
	"bytes"
	"errors"
	"testing"
)

func innerRecord(content []byte, contentType byte, padding int) []byte {
	out := append([]byte{}, content...)
	out = append(out, contentType)
	out = append(out, make([]byte, padding)...)
	return out
}

// TestStripInnerPlaintext covers the RFC 8446 §5.4 padding scan bound (M4):
// reasonable padding is accepted, excessive padding is rejected to cap CPU.
func TestStripInnerPlaintext(t *testing.T) {
	content := []byte("hello")

	// No padding.
	if got, ct, err := StripInnerPlaintext(innerRecord(content, 0x17, 0)); err != nil || ct != 0x17 || !bytes.Equal(got, content) {
		t.Fatalf("no padding: got=%q ct=%#x err=%v", got, ct, err)
	}
	// Moderate padding (within the bound).
	if got, ct, err := StripInnerPlaintext(innerRecord(content, 0x16, 200)); err != nil || ct != 0x16 || !bytes.Equal(got, content) {
		t.Fatalf("moderate padding: got=%q ct=%#x err=%v", got, ct, err)
	}
	// Excessive padding (> bound) is rejected.
	if _, _, err := StripInnerPlaintext(innerRecord(content, 0x17, maxInnerPaddingScan+8)); !errors.Is(err, ErrInnerPaddingTooLong) {
		t.Fatalf("excessive padding: err = %v, want ErrInnerPaddingTooLong", err)
	}
	// All-zero record (short) still classified as such.
	if _, _, err := StripInnerPlaintext(make([]byte, 16)); !errors.Is(err, ErrAllZeroInner) {
		t.Fatalf("all-zero: err = %v, want ErrAllZeroInner", err)
	}
}

func BenchmarkStripInnerPlaintext(b *testing.B) {
	rec := innerRecord([]byte("response body chunk"), 0x17, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = StripInnerPlaintext(rec)
	}
}
