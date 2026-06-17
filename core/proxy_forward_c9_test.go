package core

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

// readBody consumes exactly the fixed Content-Length body the same way the
// proxy forward path does, so the test can then assert on residual buffered
// bytes (the signal used to decide whether a connection is safe to pool).
func readFixedBody(t *testing.T, br *bufio.Reader, n int64) {
	t.Helper()
	if n <= 0 {
		return
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(br, body); err != nil {
		t.Fatalf("reading fixed body: %v", err)
	}
}

func TestParseHTTPResponse_TEAndCLRejected(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 5\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"hello"
	br := bufio.NewReader(strings.NewReader(raw))

	_, _, _, _, _, _, err := parseHTTPResponse(br)
	if err != ErrProxyBadResponse {
		t.Fatalf("TE+CL response: want ErrProxyBadResponse, got %v", err)
	}
}

func TestParseHTTPResponse_DuplicateConflictingCLRejected(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 5\r\n" +
		"Content-Length: 6\r\n" +
		"\r\n" +
		"hello"
	br := bufio.NewReader(strings.NewReader(raw))

	_, _, _, _, _, _, err := parseHTTPResponse(br)
	if err != ErrProxyBadResponse {
		t.Fatalf("conflicting duplicate CL: want ErrProxyBadResponse, got %v", err)
	}
}

func TestParseHTTPResponse_UnparseableCLRejected(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: not-a-number\r\n" +
		"\r\n"
	br := bufio.NewReader(strings.NewReader(raw))

	_, _, _, _, _, _, err := parseHTTPResponse(br)
	if err != ErrProxyBadResponse {
		t.Fatalf("unparseable CL: want ErrProxyBadResponse, got %v", err)
	}
}

func TestParseHTTPResponse_DuplicateIdenticalCLAccepted(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 5\r\n" +
		"Content-Length: 5\r\n" +
		"\r\n" +
		"hello"
	br := bufio.NewReader(strings.NewReader(raw))

	status, _, cl, chunked, keepAlive, _, err := parseHTTPResponse(br)
	if err != nil {
		t.Fatalf("identical duplicate CL: unexpected error %v", err)
	}
	if status != 200 || cl != 5 || chunked || !keepAlive {
		t.Fatalf("identical duplicate CL: status=%d cl=%d chunked=%v keepAlive=%v", status, cl, chunked, keepAlive)
	}
}

func TestParseHTTPResponse_CleanResponsePoolable(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 5\r\n" +
		"\r\n" +
		"hello"
	br := bufio.NewReader(strings.NewReader(raw))

	status, _, cl, chunked, keepAlive, _, err := parseHTTPResponse(br)
	if err != nil {
		t.Fatalf("clean response: unexpected error %v", err)
	}
	if status != 200 || cl != 5 || chunked || !keepAlive {
		t.Fatalf("clean response: status=%d cl=%d chunked=%v keepAlive=%v", status, cl, chunked, keepAlive)
	}

	readFixedBody(t, br, cl)

	// Unambiguous framing, body fully consumed, nothing left over: safe to pool.
	if got := br.Buffered(); got != 0 {
		t.Fatalf("clean response: want 0 buffered residue, got %d (would be served as next client's status line)", got)
	}
}

func TestParseHTTPResponse_TrailingResidueNotPoolable(t *testing.T) {
	// Backend smuggles extra bytes past the declared Content-Length. After the
	// proxy consumes exactly CL bytes, the residue stays in the buffered reader;
	// the forward path must discard rather than pool such a connection.
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Length: 5\r\n" +
		"\r\n" +
		"hello" +
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(raw))

	_, _, cl, _, keepAlive, _, err := parseHTTPResponse(br)
	if err != nil {
		t.Fatalf("residue response: unexpected error %v", err)
	}
	if !keepAlive {
		t.Fatalf("residue response: expected keep-alive")
	}

	readFixedBody(t, br, cl)

	// Leftover bytes => keepAlive alone is not sufficient; pool gate must reject.
	if got := br.Buffered(); got == 0 {
		t.Fatalf("residue response: expected leftover buffered bytes, got 0")
	}
	if keepAlive && br.Buffered() != 0 {
		// This is exactly the condition the forward path now checks before pooling.
		t.Logf("connection correctly classified as NOT poolable (%d residual bytes)", br.Buffered())
	}
}
