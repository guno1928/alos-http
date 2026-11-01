//go:build linux && amd64

package core

import (
	"fmt"
	"testing"
)

const h1StrictHost = "Host: example.com\r\n"

func parseStrict(raw string) (*Request, h1RejectReason, bool) {
	var req Request
	_, _, _, _, reject, _, _, ok := parseH1RequestHead([]byte(raw), &req, 8192, 128)
	return &req, reject, ok
}

type h1StrictCase struct {
	name string
	raw  string
	want h1RejectReason
}

func h1StrictCases() []h1StrictCase {
	cases := []h1StrictCase{
		{"baseline", "GET / HTTP/1.1\r\n" + h1StrictHost + "\r\n", h1RejectNone},
		{"space in name", "GET / HTTP/1.1\r\n" + h1StrictHost + "X Y: 1\r\n\r\n", h1RejectName},
		{"paren in name", "GET / HTTP/1.1\r\n" + h1StrictHost + "X(Y: 1\r\n\r\n", h1RejectName},
		{"tab in name", "GET / HTTP/1.1\r\n" + h1StrictHost + "X\tY: 1\r\n\r\n", h1RejectName},
		{"space before colon", "GET / HTTP/1.1\r\nHost : example.com\r\n\r\n", h1RejectName},
		{"non-ascii in name", "GET / HTTP/1.1\r\n" + h1StrictHost + "X\xc3\xa9: 1\r\n\r\n", h1RejectName},
		{"obs-fold space", "GET / HTTP/1.1\r\n" + h1StrictHost + "X-A: 1\r\n continued\r\n\r\n", h1RejectFold},
		{"obs-fold tab", "GET / HTTP/1.1\r\n" + h1StrictHost + "X-A: 1\r\n\tcontinued\r\n\r\n", h1RejectFold},
		{"line without colon", "GET / HTTP/1.1\r\n" + h1StrictHost + "NoColonHere\r\n\r\n", h1RejectNoColon},
		{"empty name", "GET / HTTP/1.1\r\n" + h1StrictHost + ": x\r\n\r\n", h1RejectNoColon},
		{"bare LF in value", "GET / HTTP/1.1\r\n" + h1StrictHost + "X-A: a\nb\r\n\r\n", h1RejectCTL},
		{"lone CR in value", "GET / HTTP/1.1\r\n" + h1StrictHost + "X-A: a\rb\r\n\r\n", h1RejectCTL},
		{"bare LF line ending", "GET / HTTP/1.1\r\n" + h1StrictHost + "X-A: a\n\r\n", h1RejectCTL},
		{"missing host 1.1", "GET / HTTP/1.1\r\nX-A: 1\r\n\r\n", h1RejectHost},
		{"two hosts", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", h1RejectHost},
		{"two identical hosts", "GET / HTTP/1.1\r\nHost: a\r\nhost: a\r\n\r\n", h1RejectHost},
		{"two hosts 1.0", "GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n", h1RejectHost},
		{"host with userinfo", "GET / HTTP/1.1\r\nHost: user@example.com\r\n\r\n", h1RejectHost},
		{"host with slash", "GET / HTTP/1.1\r\nHost: example.com/x\r\n\r\n", h1RejectHost},
		{"host with space inside", "GET / HTTP/1.1\r\nHost: exa mple.com\r\n\r\n", h1RejectHost},
		{"empty host accepted", "GET / HTTP/1.1\r\nHost:\r\n\r\n", h1RejectNone},
		{"1.0 without host accepted", "GET / HTTP/1.0\r\n\r\n", h1RejectNone},
		{"obs-text value accepted", "GET / HTTP/1.1\r\n" + h1StrictHost + "X-A: caf\xc3\xa9 \x80\xff\r\n\r\n", h1RejectNone},
		{"tab in value accepted", "GET / HTTP/1.1\r\n" + h1StrictHost + "X-A: a\tb\r\n\r\n", h1RejectNone},
		{"te gzip", "POST / HTTP/1.1\r\n" + h1StrictHost + "Transfer-Encoding: gzip\r\n\r\n", h1RejectTransferEncoding},
		{"te chunked plus cl", "POST / HTTP/1.1\r\n" + h1StrictHost + "Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n", h1RejectTransferEncoding},
		{"ctl in target", "GET /\x01 HTTP/1.1\r\n" + h1StrictHost + "\r\n", h1RejectRequestLine},
		{"del in target", "GET /\x7f HTTP/1.1\r\n" + h1StrictHost + "\r\n", h1RejectRequestLine},
		{"empty target", "GET  HTTP/1.1\r\n" + h1StrictHost + "\r\n", h1RejectRequestLine},
		{"no spaces", "GET\r\n" + h1StrictHost + "\r\n", h1RejectRequestLine},
		{"bad version", "GET / HTTP/2.0\r\n" + h1StrictHost + "\r\n", h1RejectRequestLine},
		{"lowercase version", "GET / http/1.1\r\n" + h1StrictHost + "\r\n", h1RejectRequestLine},
		{"extra space before version", "GET /  HTTP/1.1\r\n" + h1StrictHost + "\r\n", h1RejectRequestLine},
		{"bare LF request line", "GET / HTTP/1.1\n" + h1StrictHost + "\r\n", h1RejectRequestLine},
		{"non-token method", "G(T / HTTP/1.1\r\n" + h1StrictHost + "\r\n", h1RejectRequestLine},
		{"absolute form bad host", "GET http:///p HTTP/1.1\r\n" + h1StrictHost + "\r\n", h1RejectHost},
		{"absolute form userinfo", "GET http://u@h/p HTTP/1.1\r\n" + h1StrictHost + "\r\n", h1RejectHost},
		{"absolute form still needs host header", "GET http://example.com/p HTTP/1.1\r\n\r\n", h1RejectHost},
	}
	for c := 0; c < 0x20; c++ {
		if c == '\t' {
			continue
		}
		want := h1RejectCTL
		cases = append(cases,
			h1StrictCase{fmt.Sprintf("byte %#02x in name", c), "GET / HTTP/1.1\r\n" + h1StrictHost + "X" + string(rune(c)) + "Y: 1\r\n\r\n", want},
			h1StrictCase{fmt.Sprintf("byte %#02x in value", c), "GET / HTTP/1.1\r\n" + h1StrictHost + "X-A: a" + string(rune(c)) + "b\r\n\r\n", want},
		)
	}
	cases = append(cases,
		h1StrictCase{"byte 0x7f in name", "GET / HTTP/1.1\r\n" + h1StrictHost + "X\x7fY: 1\r\n\r\n", h1RejectCTL},
		h1StrictCase{"byte 0x7f in value", "GET / HTTP/1.1\r\n" + h1StrictHost + "X-A: a\x7fb\r\n\r\n", h1RejectCTL},
	)
	return cases
}

func TestH1StrictRejections(t *testing.T) {
	cases := h1StrictCases()
	if len(cases) < 60 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, c := range cases {
		_, reject, ok := parseStrict(c.raw)
		if !ok {
			t.Errorf("%s: parser asked for more input on a complete head", c.name)
			continue
		}
		if reject != c.want {
			t.Errorf("%s: reject = %d, want %d", c.name, reject, c.want)
		}
	}
}

func TestH1StrictPublicWrapperReportsRejection(t *testing.T) {
	var req Request
	_, _, _, _, rejected, _, _, ok := ParseH1RequestHead([]byte("GET / HTTP/1.1\r\nX Y: 1\r\n\r\n"), &req, 8192, 128)
	if !ok || !rejected {
		t.Fatalf("ok=%v rejected=%v, want a rejection", ok, rejected)
	}
}

func TestH1StrictTrimsOptionalWhitespace(t *testing.T) {
	req, reject, ok := parseStrict("POST / HTTP/1.1\r\nHost: \t example.com \t\r\nX-A:\t  v  w \t\r\nContent-Length: 5 \r\n\r\n")
	if !ok || reject != h1RejectNone {
		t.Fatalf("ok=%v reject=%d", ok, reject)
	}
	if req.Host != "example.com" {
		t.Errorf("Host = %q", req.Host)
	}
	if got := req.Header("x-a"); got != "v  w" {
		t.Errorf("X-A = %q, want %q", got, "v  w")
	}
	_, cl, hasCL, _, _, _, _, _ := parseH1RequestHead([]byte("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5 \r\n\r\n"), &Request{}, 8192, 128)
	if !hasCL || cl != 5 {
		t.Errorf("Content-Length with trailing OWS: has=%v value=%d", hasCL, cl)
	}
}

func TestH1StrictAbsoluteForm(t *testing.T) {
	cases := []struct {
		raw, host, path, query string
	}{
		{"GET http://example.com/p?q=1 HTTP/1.1\r\nHost: other.test\r\n\r\n", "example.com", "/p", "q=1"},
		{"GET HTTPS://Example.com:8443 HTTP/1.1\r\nHost: other.test\r\n\r\n", "Example.com:8443", "/", ""},
		{"GET http://example.com?x=y HTTP/1.1\r\nHost: other.test\r\n\r\n", "example.com", "/", "x=y"},
		{"GET http://[::1]:80/a/b HTTP/1.1\r\nHost: other.test\r\n\r\n", "[::1]:80", "/a/b", ""},
	}
	for _, c := range cases {
		req, reject, ok := parseStrict(c.raw)
		if !ok || reject != h1RejectNone {
			t.Errorf("%q: ok=%v reject=%d", c.raw, ok, reject)
			continue
		}
		if req.Host != c.host || req.Header("host") != c.host || req.Path != c.path || req.Query != c.query {
			t.Errorf("%q: host=%q header=%q path=%q query=%q", c.raw, req.Host, req.Header("host"), req.Path, req.Query)
		}
	}
}

func TestH1StrictIncompleteHeadWaits(t *testing.T) {
	for _, raw := range []string{
		"GET / HTTP/1.1",
		"GET / HTTP/1.1\r",
		"GET / HTTP/1.1\r\nHost: a",
		"GET / HTTP/1.1\r\nHost: a\r",
		"GET / HTTP/1.1\r\nHost: a\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\n\r",
	} {
		_, reject, ok := parseStrict(raw)
		if ok || reject != h1RejectNone {
			t.Errorf("%q: ok=%v reject=%d, want a request for more input", raw, ok, reject)
		}
	}
}

func TestSplitAbsoluteForm(t *testing.T) {
	cases := []struct {
		in, authority, rest string
		ok                  bool
	}{
		{"/p", "", "", false},
		{"*", "", "", false},
		{"example.com:443", "", "", false},
		{"http://h", "h", "/", true},
		{"http://h/", "h", "/", true},
		{"http://h?q", "h", "/?q", true},
		{"https://h:1/a?b", "h:1", "/a?b", true},
		{"HtTp://h/x", "h", "/x", true},
		{"http:/h", "", "", false},
		{"ftp://h/x", "", "", false},
	}
	for _, c := range cases {
		authority, rest, ok := splitAbsoluteForm(c.in)
		if authority != c.authority || rest != c.rest || ok != c.ok {
			t.Errorf("splitAbsoluteForm(%q) = (%q, %q, %v), want (%q, %q, %v)", c.in, authority, rest, ok, c.authority, c.rest, c.ok)
		}
	}
}

func TestParsePlainFastRootRequestDefersAnythingUnusual(t *testing.T) {
	accept := []string{
		"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
		"GET / HTTP/1.1\r\nUser-Agent: x\r\nhost:a\r\nAccept: */*\r\n\r\n",
	}
	for _, raw := range accept {
		if _, _, ok, needRead := parsePlainFastRootRequest([]byte(raw), len(rootPrefixBytes), 8192, defaultMaxHeaderCount); !ok || needRead {
			t.Errorf("fast path refused a clean request %q", raw)
		}
	}
	deferred := []string{
		"GET / HTTP/1.1\r\nX-A: 1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a@b\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX Y: 1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-A: \x01\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nX-A: a\nb\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nNoColon\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a\r\nexpect: foo\r\n\r\n",
	}
	for _, raw := range deferred {
		if _, _, ok, _ := parsePlainFastRootRequest([]byte(raw), len(rootPrefixBytes), 8192, defaultMaxHeaderCount); ok {
			t.Errorf("fast path accepted %q instead of deferring to the strict parser", raw)
		}
	}
}
