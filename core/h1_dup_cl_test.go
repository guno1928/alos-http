//go:build linux && amd64

package core

import "testing"

// TestParseH1RejectsDuplicateContentLength ensures a request with two
// Content-Length headers is flagged invalid (contentLength < 0), which both
// io_uring callers reject with 400 — closing the request-smuggling vector
// (RFC 9112 §6.3.3).
func TestParseH1RejectsDuplicateContentLength(t *testing.T) {
	for _, body := range []string{
		"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n", // even identical
	} {
		var req Request
		req.resetFastH1()
		_, contentLength, hasCL, _, _, ok := ParseH1RequestHead([]byte(body), &req)
		if !ok {
			t.Fatalf("parse failed for %q", body)
		}
		if !hasCL || contentLength >= 0 {
			t.Fatalf("duplicate Content-Length not rejected: hasCL=%v len=%d (%q)", hasCL, contentLength, body)
		}
	}
}

// TestParseH1AcceptsSingleContentLength confirms the normal case still parses.
func TestParseH1AcceptsSingleContentLength(t *testing.T) {
	var req Request
	req.resetFastH1()
	_, contentLength, hasCL, _, _, ok := ParseH1RequestHead(
		[]byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n"), &req)
	if !ok || !hasCL || contentLength != 5 {
		t.Fatalf("single Content-Length: ok=%v hasCL=%v len=%d", ok, hasCL, contentLength)
	}
}

func BenchmarkParseH1RequestHead(b *testing.B) {
	data := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\nAccept: */*\r\n\r\n")
	var req Request
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.resetFastH1()
		_, _, _, _, _, _ = ParseH1RequestHead(data, &req)
	}
}
