//go:build linux && amd64

package core

import "testing"

func hpackRawLiteralNoIndex(nameIndex byte, value string) []byte {
	return append([]byte{nameIndex, byte(len(value))}, value...)
}

func hpackHuffmanValueEndingIn(t *testing.T, last byte) (string, []byte) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	for _, a := range alphabet {
		for _, b := range alphabet {
			for _, c := range alphabet {
				value := string([]rune{a, b, c})
				encoded := hpackHuffmanAppend(nil, value)
				if encoded[len(encoded)-1] == last {
					return value, encoded
				}
			}
		}
	}
	t.Fatalf("no three-character value Huffman-encodes to a final byte %#x", last)
	return "", nil
}

func TestHpackSimpleGetFastPathFallsBackForExtendedLayouts(t *testing.T) {
	const path = "/fallback?q=1"
	value, huffman := hpackHuffmanValueEndingIn(t, 0x87)
	trailingHuffman := append([]byte{0x87, 0x00, 0x03, 'x', '-', 'v', 0x80 | byte(len(huffman))}, huffman...)
	cases := []struct {
		name  string
		tail  []byte
		field [2]string
	}{
		{name: "authority-before-scheme", tail: append(hpackRawLiteralNoIndex(0x01, "example.test"), 0x87), field: [2]string{":authority", "example.test"}},
		{name: "huffman-value-ending-0x87", tail: trailingHuffman, field: [2]string{"x-v", value}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			block := append([]byte{0x82}, hpackRawLiteralNoIndex(0x04, path)...)
			block = append(block, tc.tail...)
			headers, meta, _, err := NewHpackDecoder().DecodeRequest(nil, block)
			if err != nil {
				t.Fatalf("valid header block % x rejected: %v", block, err)
			}
			if meta.method != "GET" || meta.rawPath != path || meta.scheme != "https" {
				t.Fatalf("meta = method %q rawPath %q scheme %q", meta.method, meta.rawPath, meta.scheme)
			}
			found := false
			for _, h := range headers {
				found = found || h == tc.field
			}
			if !found {
				t.Fatalf("decoded headers %q lack %q", headers, tc.field)
			}
		})
	}
}

func TestHpackSimpleGetFastPathStillServesCanonicalLayout(t *testing.T) {
	block := append([]byte{0x82}, hpackRawLiteralNoIndex(0x04, "/simple")...)
	block = append(block, 0x87)
	headers, meta, _, err := NewHpackDecoder().DecodeRequest(nil, block)
	if err != nil || meta.path != "/simple" || len(headers) != 3 {
		t.Fatalf("canonical block: headers %q meta.path %q err %v", headers, meta.path, err)
	}
}
