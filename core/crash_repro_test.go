package core

import "testing"

func TestAsyncChunkedComplete_HugeSizeNoPanic(t *testing.T) {
	buf := []byte("7fffffffffffffff\r\nAAAA")
	_, status, _ := asyncChunkedComplete(buf, 0)
	if status != -1 {
		t.Fatalf("expected reject status -1 for oversize chunk, got %d", status)
	}
}

func TestAsyncChunkedComplete_OversizeWithinCapNeedsMore(t *testing.T) {
	buf := []byte("1000000000000\r\nAAAA")
	_, status, _ := asyncChunkedComplete(buf, 0)
	if status != 0 {
		t.Fatalf("expected need-more status 0, got %d", status)
	}
}

func TestAsyncChunkedComplete_ValidBody(t *testing.T) {
	buf := []byte("4\r\nWiki\r\n0\r\n\r\n")
	bodyEnd, status, _ := asyncChunkedComplete(buf, 0)
	if status != 1 {
		t.Fatalf("expected complete status 1, got %d", status)
	}
	if bodyEnd != len(buf) {
		t.Fatalf("expected bodyEnd %d, got %d", len(buf), bodyEnd)
	}
}

func TestParseHex64Bytes_RejectsOverflow(t *testing.T) {
	if _, ok := parseHex64Bytes([]byte("7fffffffffffffff")); ok {
		t.Fatal("parseHex64Bytes accepted a value above maxParsedLength")
	}
	if v, ok := parseHex64Bytes([]byte("ff")); !ok || v != 255 {
		t.Fatalf("parseHex64Bytes rejected valid 0xff: v=%d ok=%v", v, ok)
	}
}

func TestParseClientHello_SessionIDOverflowNoPanic(t *testing.T) {
	ch := make([]byte, 75)
	ch[0], ch[1] = 0x03, 0x03
	ch[34] = 40
	data := make([]byte, 4+len(ch))
	data[0] = 0x01
	data[1] = byte(len(ch) >> 16)
	data[2] = byte(len(ch) >> 8)
	data[3] = byte(len(ch))
	copy(data[4:], ch)
	var result ParsedClientHello
	if err := ParseClientHello(data, &result); err != ErrSessionIDTruncated {
		t.Fatalf("expected ErrSessionIDTruncated, got %v", err)
	}
}
