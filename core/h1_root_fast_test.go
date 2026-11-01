//go:build linux && amd64

package core

import (
	"strings"
	"testing"
)

const rootFastMaxHeader = 8192

var rootFastTemplates = []string{
	"GET / HTTP/1.1\r\nHost: ab.c:80\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\nX-A: v w\r\n\r\n",
	"GET / HTTP/1.1\r\nUser-Agent: curl/8.5.0\r\nhost:\t[::1]:8080 \r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (X11)\r\nAccept: text/html,*/*;q=0.8\r\nConnection: close\r\n\r\n",
}

type rootFastResult struct {
	consumed  int
	keepAlive bool
	ok        bool
	needRead  bool
}

func rootFastBoth(raw []byte) (got, want rootFastResult) {
	got.consumed, got.keepAlive, got.ok, got.needRead = parsePlainFastRootRequest(raw, len(rootPrefixBytes), rootFastMaxHeader, defaultMaxHeaderCount)
	want.consumed, want.keepAlive, want.ok, want.needRead = parsePlainFastRootRequestRef(raw, len(rootPrefixBytes), rootFastMaxHeader)
	return got, want
}

func TestPlainFastRootMatchesReferenceOnEveryByte(t *testing.T) {
	checked := 0
	for _, tmpl := range rootFastTemplates {
		for pos := len(rootPrefixBytes); pos < len(tmpl); pos++ {
			raw := []byte(tmpl)
			for b := 0; b < 256; b++ {
				raw[pos] = byte(b)
				got, want := rootFastBoth(raw)
				if got != want {
					t.Fatalf("%q: got %+v, reference %+v", raw, got, want)
				}
				checked++
			}
		}
	}
	t.Logf("checked %d mutations", checked)
}

func TestPlainFastRootMatchesReferenceOnCases(t *testing.T) {
	cases := append([]string{}, rootFastTemplates...)
	cases = append(cases,
		"GET / HTTP/1.1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a",
		"GET / HTTP/1.1\r\nHost: a\r\n",
		"GET / HTTP/1.1\r\nHost:\r\n\r\n",
		"GET / HTTP/1.1\r\nHost:   \r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a b\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a \t\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n",
		"GET / HTTP/1.1\r\nHOST: a\r\nCONNECTION: CLOSE\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nConnection: close, keep-alive\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nExpecs: 1\r\nContent-Lengtx: 1\r\nTransfer-Encodinx: 1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-A: \x80\xff\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-A: a\rb\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-A: a\nb\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\n\rX: 1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\n:x\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX : 1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: "+strings.Repeat("a", 300)+"\r\nX-Long: "+strings.Repeat("v", 300)+"\r\n\r\n",
		"GET / HTTP/1.1\r\n"+strings.Repeat("X-Pad: 1\r\n", 1000)+"\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-Pad: "+strings.Repeat("x", 90)+"\r\n\r\nGET / HTTP/1.1\r\nHost: b\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.1\r\nHost: b\r\nX-Pad: "+strings.Repeat("y", 90)+"\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\n\r\n\r\nX-Pad: "+strings.Repeat("z", 90)+"\r\n\r\n",
		"GET / HTTP/1.1\r\n\r\nHost: a\r\nX-Pad: "+strings.Repeat("w", 90)+"\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\nX-Pad: "+strings.Repeat("v", 90)+"\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-Pad: "+strings.Repeat("u", 90)+"\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n\x00\x01\r\n\r\n",
	)
	for _, raw := range cases {
		got, want := rootFastBoth([]byte(raw))
		if got != want {
			t.Errorf("%q: got %+v, reference %+v", raw, got, want)
		}
	}
}

func FuzzPlainFastRootDifferential(f *testing.F) {
	for _, tmpl := range rootFastTemplates {
		f.Add([]byte(tmpl[len(rootPrefixBytes):]))
	}
	f.Fuzz(func(t *testing.T, rest []byte) {
		raw := append(append([]byte{}, rootPrefixBytes...), rest...)
		got, want := rootFastBoth(raw)
		if got != want {
			t.Fatalf("%q: got %+v, reference %+v", raw, got, want)
		}
	})
}
