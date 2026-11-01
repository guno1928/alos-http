//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
)

func requireRedirectDate(t *testing.T, raw []byte, wantStatus int) {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		t.Fatalf("parse response %q: %v", raw, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("status=%d want %d", resp.StatusCode, wantStatus)
	}
	perfH1AssertFreshDate(t, resp.Status, resp.Header.Values("Date"))
}

func redirectListenerResponse(t *testing.T, request string) []byte {
	t.Helper()
	server, client := net.Pipe()
	srv := New(Config{Addr: ":8443"})
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleHTTPRedirect(server)
	}()
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(client)
	_ = client.Close()
	<-done
	return raw
}

func TestHTTPRedirectListenerResponsesCarryDate(t *testing.T) {
	cases := []struct {
		name    string
		request string
		status  int
	}{
		{"redirect", "GET /path HTTP/1.1\r\nHost: example.test\r\n\r\n", 301},
		{"bad host", "GET / HTTP/1.1\r\nHost: bad host\r\n\r\n", 400},
		{"acme without acme", "GET /.well-known/acme-challenge/token HTTP/1.1\r\nHost: example.test\r\n\r\n", 404},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireRedirectDate(t, redirectListenerResponse(t, tc.request), tc.status)
		})
	}
}

func TestHTTPRedirectBuiltResponsesCarryDate(t *testing.T) {
	requireRedirectDate(t, buildRedirectResponse("https://example.test/"), 301)
	requireRedirectDate(t, buildACMEResponse([]byte("key-authorization")), 200)
	for _, status := range []int{400, 404, 413, 431, 502, 504} {
		server, client := net.Pipe()
		go func() {
			writeHTTPRouteStatus(server, status)
			_ = server.Close()
		}()
		raw, _ := io.ReadAll(client)
		_ = client.Close()
		requireRedirectDate(t, raw, status)
	}
}
