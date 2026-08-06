package protocols_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/guno1928/alos-http/core"
)

func parseH1(raw string, maxBytes, maxCount int) (*core.Request, int, bool, bool, bool, bool, bool, bool) {
	req := &core.Request{}
	end, length, hasLength, closeConn, badTE, chunked, tooLarge, ok := core.ParseH1RequestHead([]byte(raw), req, maxBytes, maxCount)
	return req, end, hasLength, closeConn, badTE, chunked, tooLarge, ok && length >= 0
}

func TestHTTP1MethodAndTargetMatrix(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"}
	for i := 0; i < 8; i++ {
		for _, method := range methods {
			method := method
			t.Run(fmt.Sprintf("%s_%02d", strings.ToLower(method), i), func(t *testing.T) {
				path := fmt.Sprintf("/v1/resource/%d?q=value-%d", i, i)
				raw := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: example.test\r\nX-Case: %d\r\n\r\n", method, path, i)
				req, end, hasLength, closeConn, badTE, chunked, tooLarge, ok := parseH1(raw, 8192, 64)
				if !ok || end != len(raw) || hasLength || closeConn || badTE || chunked || tooLarge {
					t.Fatalf("unexpected parse flags: end=%d length=%v close=%v badTE=%v chunked=%v tooLarge=%v ok=%v", end, hasLength, closeConn, badTE, chunked, tooLarge, ok)
				}
				if req.Method != method || req.Path != fmt.Sprintf("/v1/resource/%d", i) || req.Query != fmt.Sprintf("q=value-%d", i) || req.Host != "example.test" {
					t.Fatalf("request mismatch: %#v", req)
				}
			})
		}
	}
}

func TestHTTP1ConnectionAndBodyMatrix(t *testing.T) {
	cases := []struct {
		name      string
		headers   string
		hasLength bool
		closeConn bool
		badTE     bool
		chunked   bool
	}{
		{"content_length", "Content-Length: 12\r\n", true, false, false, false},
		{"connection_close", "Connection: close\r\n", false, true, false, false},
		{"chunked", "Transfer-Encoding: chunked\r\n", false, false, false, true},
		{"chunked_case", "Transfer-Encoding: Chunked\r\n", false, false, false, true},
		{"unsupported_te", "Transfer-Encoding: gzip\r\n", false, false, true, false},
		{"keep_alive", "Connection: keep-alive\r\n", false, false, false, false},
	}
	for repeat := 0; repeat < 8; repeat++ {
		for _, tc := range cases {
			tc := tc
			t.Run(fmt.Sprintf("%s_%02d", tc.name, repeat), func(t *testing.T) {
				raw := "POST /upload HTTP/1.1\r\nHost: upload.test\r\n" + tc.headers + fmt.Sprintf("X-Repeat: %d\r\n\r\n", repeat)
				_, _, hasLength, closeConn, badTE, chunked, tooLarge, ok := parseH1(raw, 8192, 64)
				if !ok || tooLarge || hasLength != tc.hasLength || closeConn != tc.closeConn || badTE != tc.badTE || chunked != tc.chunked {
					t.Fatalf("flags length=%v close=%v badTE=%v chunked=%v tooLarge=%v ok=%v", hasLength, closeConn, badTE, chunked, tooLarge, ok)
				}
			})
		}
	}
}

func TestHTTP1HeaderLimits(t *testing.T) {
	for limit := 1; limit <= 32; limit++ {
		t.Run(fmt.Sprintf("count_%02d", limit), func(t *testing.T) {
			var b strings.Builder
			b.WriteString("GET / HTTP/1.1\r\nHost: example.test\r\n")
			for i := 0; i < limit+1; i++ {
				fmt.Fprintf(&b, "X-%d: value\r\n", i)
			}
			b.WriteString("\r\n")
			_, _, _, _, _, _, tooLarge, ok := parseH1(b.String(), 65536, limit)
			if ok || !tooLarge {
				t.Fatalf("header count limit %d not enforced: tooLarge=%v ok=%v", limit, tooLarge, ok)
			}
		})
	}
}
