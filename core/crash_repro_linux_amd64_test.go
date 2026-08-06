//go:build linux && amd64

package core

import "testing"

func TestDecodeChunkedInto_HugeSizeNoPanic(t *testing.T) {
	src := []byte("7fffffffffffffff\r\nAAAA")
	if _, ok := decodeChunkedInto(nil, src); ok {
		t.Fatal("decodeChunkedInto accepted oversize chunk")
	}
}

func TestDecodeChunkedInto_OversizeWithinCap(t *testing.T) {
	src := []byte("1000000000000\r\nAAAA")
	if _, ok := decodeChunkedInto(nil, src); ok {
		t.Fatal("decodeChunkedInto accepted chunk larger than buffer")
	}
}

func TestDecodeChunkedInto_Valid(t *testing.T) {
	src := []byte("4\r\nWiki\r\n0\r\n\r\n")
	dst, ok := decodeChunkedInto(nil, src)
	if !ok || string(dst) != "Wiki" {
		t.Fatalf("decodeChunkedInto valid failed: ok=%v dst=%q", ok, dst)
	}
}
