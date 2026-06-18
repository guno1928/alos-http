package core

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func parseProxyResp(raw string) error {
	br := bufio.NewReader(strings.NewReader(raw))
	_, _, _, _, _, _, err := parseHTTPResponse(br)
	return err
}

// TestParseHTTPResponseRejectsAmbiguousFraming verifies a backend response that
// carries both Content-Length and Transfer-Encoding is rejected (RFC 9112 §6.1)
// — the response-smuggling / cache-poisoning vector.
func TestParseHTTPResponseRejectsAmbiguousFraming(t *testing.T) {
	if err := parseProxyResp("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello"); !errors.Is(err, ErrProxyBadResponse) {
		t.Fatalf("CL+TE: err = %v, want ErrProxyBadResponse", err)
	}
}

// TestParseHTTPResponseAcceptsUnambiguous confirms CL-only and chunked-only
// responses still parse.
func TestParseHTTPResponseAcceptsUnambiguous(t *testing.T) {
	if err := parseProxyResp("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"); err != nil {
		t.Fatalf("CL-only rejected: %v", err)
	}
	if err := parseProxyResp("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"); err != nil {
		t.Fatalf("chunked-only rejected: %v", err)
	}
}

func BenchmarkParseHTTPResponse(b *testing.B) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		br := bufio.NewReader(strings.NewReader(raw))
		_, _, _, _, _, _, _ = parseHTTPResponse(br)
	}
}
