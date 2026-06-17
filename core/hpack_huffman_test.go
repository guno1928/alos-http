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
		// '0' is the 5-bit code 0x00000; one byte 0x00 decodes '0' then leaves
		// 3 padding bits "000" — not the required all-ones EOS prefix.
		{"non-all-ones-padding", []byte{0x00}},
		// 0xFF has no <=8-bit code; a full undecodable byte remains (>=8 bits
		// of padding == over-long / embedded EOS).
		{"overlong-padding", []byte{0xff}},
		// A long all-ones run cannot terminate on a valid <8-bit all-ones pad.
		{"eos-run", []byte{0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, c := range cases {
		if _, ok := hpackHuffmanDecode(c.in); ok {
			t.Errorf("%s: hpackHuffmanDecode(%x) accepted, want rejected", c.name, c.in)
		}
	}
}

// TestHpackDecodeStringRejectsBadHuffman ensures a malformed Huffman literal in
// the string-decode path is surfaced as an error (consumed <= 0) rather than a
// silently-coerced value.
func TestHpackDecodeStringRejectsBadHuffman(t *testing.T) {
	// 0x81 0x00: Huffman flag set, length 1, payload 0x00 (bad padding).
	_, n := HpackDecodeString([]byte{0x81, 0x00})
	if n > 0 {
		t.Fatalf("malformed Huffman literal accepted: consumed=%d", n)
	}
}
