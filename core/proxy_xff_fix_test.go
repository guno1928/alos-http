package core

import (
	"strings"
	"testing"
)

func parseBackendHeaders(raw []byte) [][2]string {
	text := string(raw)
	if i := strings.Index(text, "\r\n\r\n"); i >= 0 {
		text = text[:i]
	}
	lines := strings.Split(text, "\r\n")
	var out [][2]string
	for _, ln := range lines {
		if c := strings.Index(ln, ": "); c >= 0 {
			out = append(out, [2]string{ln[:c], ln[c+2:]})
		}
	}
	return out
}

func countHeader(headers [][2]string, name string) (int, []string) {
	var vals []string
	n := 0
	for _, h := range headers {
		if EqualFoldASCII(h[0], name) {
			n++
			vals = append(vals, h[1])
		}
	}
	return n, vals
}

func TestBuildProxyRequestStripsClientForwardingHeaders(t *testing.T) {
	req := &Request{
		Method:     "GET",
		Path:       "/api/transfer",
		Host:       "app.example.com",
		RemoteAddr: "1.2.3.4:5555",
		Headers: [][2]string{
			{"X-Forwarded-For", "9.9.9.9"},
			{"x-forwarded-for", "203.0.113.7, 10.0.0.1"},
			{"X-Real-IP", "8.8.8.8"},
			{"Forwarded", "for=7.7.7.7;proto=https"},
			{"X-Custom", "keep-me"},
			{"User-Agent", "test"},
		},
	}

	out := buildProxyRequest(nil, req, "backend.local:80", &DomainConfig{})
	headers := parseBackendHeaders(out)

	xffCount, xffVals := countHeader(headers, "X-Forwarded-For")
	if xffCount != 1 {
		t.Fatalf("expected exactly 1 X-Forwarded-For sent to backend, got %d (%v)", xffCount, xffVals)
	}
	if xffVals[0] != "1.2.3.4" {
		t.Fatalf("expected proxy to set X-Forwarded-For to the real client IP 1.2.3.4, got %q", xffVals[0])
	}
	for _, spoof := range []string{"9.9.9.9", "203.0.113.7", "10.0.0.1"} {
		if strings.Contains(xffVals[0], spoof) {
			t.Fatalf("client-supplied XFF value %q leaked to backend in %q", spoof, xffVals[0])
		}
	}

	if n, v := countHeader(headers, "X-Real-IP"); n != 0 {
		t.Fatalf("client X-Real-IP must not be forwarded, got %d (%v)", n, v)
	}
	if n, v := countHeader(headers, "Forwarded"); n != 0 {
		t.Fatalf("client Forwarded must not be forwarded, got %d (%v)", n, v)
	}

	if n, _ := countHeader(headers, "X-Custom"); n != 1 {
		t.Fatalf("legitimate header X-Custom should pass through, got %d", n)
	}
}

func TestBuildProxyRequestSetsXFFWhenClientSendsNone(t *testing.T) {
	req := &Request{
		Method:     "GET",
		Path:       "/",
		Host:       "app.example.com",
		RemoteAddr: "203.0.113.50:40000",
		Headers:    [][2]string{{"User-Agent", "test"}},
	}
	out := buildProxyRequest(nil, req, "backend.local:80", &DomainConfig{})
	headers := parseBackendHeaders(out)
	n, vals := countHeader(headers, "X-Forwarded-For")
	if n != 1 || vals[0] != "203.0.113.50" {
		t.Fatalf("expected single XFF=203.0.113.50, got %d %v", n, vals)
	}
}

var filterSweepNames = []string{
	"host", "content-length", "x-forwarded-for", "x-real-ip", "forwarded",
	"user-agent", "accept", "accept-encoding", "transfer-encoding", "te",
	"x-custom-header", "authorization", "cookie", "connection", "keep-alive",
}

func BenchmarkIsProxyFilteredHeaderFold(b *testing.B) {
	b.ReportAllocs()
	sink := false
	for i := 0; i < b.N; i++ {
		for _, n := range filterSweepNames {
			sink = sink != isProxyFilteredHeaderFold(n)
		}
	}
	if sink {
		b.SetBytes(1)
	}
}

func BenchmarkBuildProxyRequest(b *testing.B) {
	req := &Request{
		Method:     "POST",
		Path:       "/api/v1/resource",
		Host:       "app.example.com",
		RemoteAddr: "203.0.113.7:51000",
		Headers: [][2]string{
			{"X-Forwarded-For", "9.9.9.9"},
			{"X-Real-IP", "8.8.8.8"},
			{"User-Agent", "Mozilla/5.0 benchmark"},
			{"Accept", "application/json"},
			{"Authorization", "Bearer abcdef0123456789"},
			{"Cookie", "session=deadbeefcafebabe; theme=dark"},
			{"X-Custom-Header", "some-value"},
		},
		Body: []byte(`{"k":"v"}`),
	}
	cfg := &DomainConfig{}
	buf := make([]byte, 0, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = buildProxyRequest(buf[:0], req, "backend.local:80", cfg)
	}
	_ = buf
}
