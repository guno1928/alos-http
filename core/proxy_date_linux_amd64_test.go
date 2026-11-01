package core

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
)

const proxyDateBackendValue = "Tue, 15 Nov 1994 08:12:31 GMT"

func proxyDateValues(t *testing.T, head []byte) []string {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(head)), nil)
	if err != nil {
		t.Fatalf("parse head %q: %v", head, err)
	}
	return resp.Header.Values("Date")
}

func TestProxyResponseHeadsAddMissingDate(t *testing.T) {
	var noDate, withDate h1Parser
	if _, _, err := noDate.parseHeaderBlock([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Origin: a"), "GET"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := withDate.parseHeaderBlock([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nDate: "+proxyDateBackendValue), "GET"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		headers respHeaders
		backend bool
	}{
		{"raw-missing", respHeaders{raw: noDate.hdr}, false},
		{"raw-present", respHeaders{raw: withDate.hdr}, true},
		{"str-missing", respHeaders{str: [][2]string{{"x-origin", "a"}}}, false},
		{"str-present-mixed-case", respHeaders{str: [][2]string{{"DaTe", proxyDateBackendValue}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			heads := map[string][]byte{
				"buffered": appendProxyResponseHead(nil, 200, tc.headers, 2, true, "text/plain"),
				"stream":   appendProxyStreamHead(nil, 200, tc.headers, -1, true),
			}
			for kind, head := range heads {
				values := proxyDateValues(t, head)
				if tc.backend {
					if len(values) != 1 || values[0] != proxyDateBackendValue {
						t.Fatalf("%s: backend Date %q, want exactly [%q]", kind, values, proxyDateBackendValue)
					}
					continue
				}
				perfH1AssertFreshDate(t, kind, values)
			}
		})
	}
}

func TestProxyRelayAddsDateWhenBackendOmitsIt(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response string
	}{
		{"content-length", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"},
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := rawOrigin(t, func(c net.Conn) { _, _ = io.WriteString(c, tc.response) })
			_, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(backend), nil)
			resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, "/date"))
			if resp.StatusCode != 200 || body != "ok" {
				t.Fatalf("status=%d body=%q", resp.StatusCode, body)
			}
			perfH1AssertFreshDate(t, tc.name, resp.Header.Values("Date"))
		})
	}
}
