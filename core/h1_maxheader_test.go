package core

import (
	"strings"
	"testing"
)

func TestParseH1RequestHeadHappyPath(t *testing.T) {
	var req Request
	data := []byte("GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n")

	headerEnd, _, _, _, _, ok, reject := ParseH1RequestHead(data, &req, 8192)
	if reject {
		t.Fatalf("small valid request was rejected")
	}
	if !ok {
		t.Fatalf("small valid request did not parse")
	}
	if headerEnd != len(data) {
		t.Fatalf("headerEnd = %d, want %d", headerEnd, len(data))
	}
	if req.Method != "GET" || req.Path != "/hello" || req.Host != "example.com" {
		t.Fatalf("parsed fields wrong: method=%q path=%q host=%q", req.Method, req.Path, req.Host)
	}
}

func TestParseH1RequestHeadOverBudgetNoTerminator(t *testing.T) {
	const maxHeaderSize = 8192

	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\n")
	for b.Len() <= maxHeaderSize {
		b.WriteString("X-Pad: 0123456789abcdef\r\n")
	}
	// No terminating CRLFCRLF: an attacker would otherwise drive the read
	// buffer to MaxReadSize waiting for the end of the header block.
	data := []byte(b.String())
	if len(data) <= maxHeaderSize {
		t.Fatalf("test setup: payload not over budget (%d <= %d)", len(data), maxHeaderSize)
	}

	_, _, _, _, _, ok, reject := ParseH1RequestHead(data, &Request{}, maxHeaderSize)
	if ok {
		t.Fatalf("over-budget unterminated head returned ok=true")
	}
	if !reject {
		t.Fatalf("over-budget unterminated head was not rejected")
	}
}

func TestParseH1RequestHeadUnderBudgetNoTerminator(t *testing.T) {
	// Partial head under the cap must ask for more data, never reject.
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n")

	_, _, _, _, _, ok, reject := ParseH1RequestHead(data, &Request{}, 8192)
	if ok {
		t.Fatalf("partial head returned ok=true")
	}
	if reject {
		t.Fatalf("partial head under budget was rejected instead of waiting for more data")
	}
}

func TestParseH1RequestHeadTooManyHeaders(t *testing.T) {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\n")
	for i := 0; i < 200; i++ {
		b.WriteString("X-H: v\r\n")
	}
	b.WriteString("\r\n")
	data := []byte(b.String())

	// Terminated and within MaxHeaderSize, but exceeds the 128-header cap:
	// must be a hard reject rather than an accepted, truncated parse.
	_, _, _, _, _, ok, reject := ParseH1RequestHead(data, &Request{}, len(data)+1)
	if ok {
		t.Fatalf("header-count overflow returned ok=true")
	}
	if !reject {
		t.Fatalf("header-count overflow was not rejected")
	}
}
