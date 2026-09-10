package core

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func redirectFor(t *testing.T, s *Server, rawRequest string) *http.Response {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		s.handleHTTPRedirect(server)
		_ = server.Close()
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write([]byte(rawRequest)); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()
	return resp
}

func TestHTTPRedirectRejectsNonOriginFormTarget(t *testing.T) {
	s := New(Config{Addr: ":8443", HTTPAddr: "-", LogRequests: false})
	cases := []struct {
		name   string
		target string
	}{
		{"userinfo smuggle", "@evil.test/"},
		{"bare host", "evil.test/x"},
		{"backslash", "\\evil.test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := redirectFor(t, s, "GET "+tc.target+" HTTP/1.1\r\nHost: good.test\r\n\r\n")
			loc := resp.Header.Get("Location")
			if resp.StatusCode != 400 || loc != "" {
				t.Fatalf("target %q produced status %d Location %q; a non-origin-form target must be rejected, this Location sends the browser to a foreign host", tc.target, resp.StatusCode, loc)
			}
		})
	}
}

func TestHTTPRedirectKeepsOriginAndAbsoluteForms(t *testing.T) {
	s := New(Config{Addr: ":8443", HTTPAddr: "-", LogRequests: false})
	cases := []struct {
		target string
		want   string
	}{
		{"/a/b?c=1", "https://good.test:8443/a/b?c=1"},
		{"http://good.test/x", "https://good.test:8443/x"},
		{"http://good.test", "https://good.test:8443/"},
	}
	for _, tc := range cases {
		resp := redirectFor(t, s, "GET "+tc.target+" HTTP/1.1\r\nHost: good.test\r\n\r\n")
		if got := resp.Header.Get("Location"); got != tc.want || !strings.HasPrefix(http.StatusText(resp.StatusCode), "") || resp.StatusCode/100 != 3 {
			t.Fatalf("target %q: status %d Location %q, want 3xx %q", tc.target, resp.StatusCode, got, tc.want)
		}
	}
}
