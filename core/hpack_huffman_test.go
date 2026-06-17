package core

import "testing"

// TestHpackHuffmanRoundTrip confirms valid Huffman encodings (produced by the
// encoder, which pads with the EOS prefix) decode back to the original string.
func TestHpackHuffmanRoundTrip(t *testing.T) {
	for _, s := range []string{"", "a", "0", "Hello, World!", "/index.html", "text/html; charset=utf-8", "no-cache"} {
		enc := hpackHuffmanAppend(nil, s)
		got, ok := hpackHuffmanDecode(enc)
		if !ok {
			t.Fatalf("valid encoding of %q rejected", s)
		}
		if got != s {
			t.Fatalf("round-trip %q -> %q", s, got)
		}
	}
}

// TestHpackHuffmanRejectsBadPadding ensures the decoder fails closed on the
// RFC 7541 §5.2 error cases instead of silently returning a partial string.
func TestHpackHuffmanRejectsBadPadding(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"non-all-ones-padding", []byte{0x00}},            // '0' then "000" pad
		{"overlong-padding", []byte{0xff}},                // >=8 undecodable bits
		{"eos-run", []byte{0xff, 0xff, 0xff, 0xff, 0xff}}, // all-ones run
	}
	for _, c := range cases {
		if _, ok := hpackHuffmanDecode(c.in); ok {
			t.Errorf("%s: hpackHuffmanDecode(%x) accepted, want rejected", c.name, c.in)
		}
	}
}

// TestHpackDecodeStringRejectsBadHuffman ensures a malformed Huffman literal in
// the string-decode path surfaces as an error (consumed <= 0).
func TestHpackDecodeStringRejectsBadHuffman(t *testing.T) {
	_, n := HpackDecodeString([]byte{0x81, 0x00}) // huffman flag, len 1, bad payload
	if n > 0 {
		t.Fatalf("malformed Huffman literal accepted: consumed=%d", n)
	}
}

// BenchmarkHpackHuffmanDecode guards the decode hot path (incl. the new tail
// validation).
func BenchmarkHpackHuffmanDecode(b *testing.B) {
	enc := hpackHuffmanAppend(nil, "text/html; charset=utf-8")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := hpackHuffmanDecode(enc); !ok {
			b.Fatal("unexpected reject")
		}
	}
}
