//go:build linux && amd64

package core

import (
	"io"
	"net"
	"strings"
	"testing"
)

type h2FixH1Outcome struct {
	closeConn bool
	reject    h1RejectReason
	chunked   bool
	ok        bool
}

func h2FixParseH1(raw string) h2FixH1Outcome {
	var req Request
	_, _, _, closeConn, reject, chunked, _, ok := parseH1RequestHead([]byte(raw), &req, 0, 0)
	return h2FixH1Outcome{closeConn: closeConn, reject: reject, chunked: chunked, ok: ok}
}

func TestH2FixH1HTTP10TransferEncodingIsRejected(t *testing.T) {
	got := h2FixParseH1("POST / HTTP/1.0\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n")
	if got.reject != h1RejectTransferEncoding {
		t.Fatalf("HTTP/1.0 + Transfer-Encoding: chunked parsed as %+v, want h1RejectTransferEncoding", got)
	}
	if got := h2FixParseH1("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"); got.reject != h1RejectNone || !got.chunked {
		t.Fatalf("HTTP/1.1 chunked request parsed as %+v", got)
	}
}

func TestH2FixH1EmptyTransferEncodingIsRejected(t *testing.T) {
	got := h2FixParseH1("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: \r\nContent-Length: 5\r\n\r\n")
	if got.reject != h1RejectTransferEncoding {
		t.Fatalf("empty Transfer-Encoding parsed as %+v, want h1RejectTransferEncoding", got)
	}
}

func TestH2FixH1ConnectionCloseTokenList(t *testing.T) {
	for _, tc := range []struct {
		name, head string
		wantClose  bool
	}{
		{"close-list", "GET /x HTTP/1.1\r\nHost: x\r\nConnection: close, te\r\n\r\n", true},
		{"list-close", "GET /x HTTP/1.1\r\nHost: x\r\nConnection: te, Close\r\n\r\n", true},
		{"close-then-keepalive", "GET /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n", true},
		{"close-then-other", "GET /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\nConnection: upgrade\r\n\r\n", true},
		{"keepalive", "GET /x HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n", false},
		{"http10-keepalive-list", "GET /x HTTP/1.0\r\nConnection: foo, keep-alive\r\n\r\n", false},
		{"http10-keepalive-then-close", "GET /x HTTP/1.0\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n", true},
		{"http10-default", "GET /x HTTP/1.0\r\n\r\n", true},
	} {
		got := h2FixParseH1(tc.head)
		if !got.ok || got.reject != h1RejectNone || got.closeConn != tc.wantClose {
			t.Errorf("%s: parsed as %+v, want close=%v", tc.name, got, tc.wantClose)
		}
	}
}

func TestH2FixH1RootFastPathConnectionCloseTokenList(t *testing.T) {
	for _, tc := range []struct {
		name, head    string
		wantKeepAlive bool
	}{
		{"close-list", "GET / HTTP/1.1\r\nHost: x\r\nConnection: close, te\r\n\r\n", false},
		{"close-then-keepalive", "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n", false},
		{"keepalive", "GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n", true},
		{"none", "GET / HTTP/1.1\r\nHost: x\r\n\r\n", true},
		{"long-close-list", "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: " + strings.Repeat("u", 120) + "\r\nConnection: close, te\r\nAccept: */*\r\n\r\n", false},
	} {
		_, keepAlive, ok, _ := parsePlainFastRootRequest([]byte(tc.head), len(rootPrefixBytes), 8192, defaultMaxHeaderCount)
		if !ok || keepAlive != tc.wantKeepAlive {
			t.Errorf("%s: root fast path keepAlive=%v ok=%v, want keepAlive=%v", tc.name, keepAlive, ok, tc.wantKeepAlive)
		}
	}
}

func h2FixH1Exchange(t *testing.T, addr, raw string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, h2FixCeiling)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(wallDeadline(h2FixCeiling))
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, _ := io.ReadAll(conn)
	return string(out)
}

func TestH2FixH1ConnectionCloseListStopsPipelining(t *testing.T) {
	addr := startH2FixServer(t, nil, func(srv *Server) {
		srv.Router.GET("/x", func(req *Request, resp *Response) { resp.Status(200).String("x") })
	})
	out := h2FixH1Exchange(t, addr, "GET /x HTTP/1.1\r\nHost: a\r\nConnection: close, te\r\n\r\nGET /x HTTP/1.1\r\nHost: a\r\n\r\n")
	if n := strings.Count(out, "HTTP/1.1 200"); n != 1 {
		t.Fatalf("got %d responses after Connection: close, te; want exactly 1\n%s", n, out)
	}
}

func TestH2FixH1HTTP10ChunkedIsRejected(t *testing.T) {
	addr := startH2FixServer(t, nil, func(srv *Server) {
		srv.Router.POST("/", func(req *Request, resp *Response) { resp.Status(200).String("posted") })
		srv.Router.GET("/next", func(req *Request, resp *Response) { resp.Status(200).String("next") })
	})
	out := h2FixH1Exchange(t, addr, "POST / HTTP/1.0\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nGET /next HTTP/1.0\r\n\r\n")
	if !strings.HasPrefix(out, "HTTP/1.1 400") || strings.Contains(out, "next") || strings.Contains(out, "posted") {
		t.Fatalf("HTTP/1.0 chunked request was served:\n%s", out)
	}
}
