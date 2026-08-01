//go:build linux

package core

import (
	"strings"
	"testing"
)

// A response head of the shape a CDN origin actually returns.
var probeHeadTypical = []byte("HTTP/1.1 200 OK\r\n" +
	"Content-Type: text/html; charset=utf-8\r\n" +
	"Content-Length: 1024\r\n" +
	"Date: Mon, 30 Jul 2026 08:47:33 GMT\r\n" +
	"Server: origin\r\n" +
	"Cache-Control: public, max-age=3600\r\n" +
	"ETag: \"a1b2c3d4e5f6\"\r\n" +
	"Last-Modified: Sun, 29 Jul 2026 12:00:00 GMT\r\n" +
	"Accept-Ranges: bytes\r\n")

// The two-header shape the end-to-end allocation tests measure against.
var probeHeadMinimal = []byte("HTTP/1.1 200 OK\r\n" +
	"Content-Length: 1024\r\n" +
	"Content-Type: text/plain\r\n")

// parseHeaderBlock must not allocate: names and values are slices of the
// parser's own reused copy of the header block. Anything above zero here means
// a string materialisation crept back onto the hot path.
func TestParseHeaderBlockDoesNotAllocate(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation, so budgets do not apply")
	}
	for _, tc := range []struct {
		name string
		head []byte
		want int
	}{
		{"typical", probeHeadTypical, 8},
		{"minimal", probeHeadMinimal, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p h1Parser
			src := make([]byte, len(tc.head))
			for i := 0; i < 200; i++ {
				copy(src, tc.head)
				p.hdr = p.hdr[:0]
				if _, _, err := p.parseHeaderBlock(src, "GET"); err != nil {
					t.Fatalf("warmup parse: %v", err)
				}
			}
			if len(p.hdr) != tc.want {
				t.Fatalf("parsed %d headers, want %d", len(p.hdr), tc.want)
			}

			const iters = 2000
			var before, after MemStatsAlias
			readMem(&before)
			for i := 0; i < iters; i++ {
				copy(src, tc.head)
				p.hdr = p.hdr[:0]
				if _, _, err := p.parseHeaderBlock(src, "GET"); err != nil {
					t.Fatalf("parse: %v", err)
				}
			}
			readMem(&after)
			per := float64(after.Mallocs-before.Mallocs) / float64(iters)
			t.Logf("%s: %.3f allocations per header block", tc.name, per)
			if per > 0.01 {
				t.Fatalf("%.3f allocations per header block; the parser must not materialise strings", per)
			}
		})
	}
}

// Names must come out lowercased in place, because the byte-form comparisons
// used by the serializers do not case-fold.
func TestParseHeaderBlockLowercasesNames(t *testing.T) {
	var p h1Parser
	src := append([]byte(nil), probeHeadTypical...)
	if _, _, err := p.parseHeaderBlock(src, "GET"); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, h := range p.hdr {
		for _, ch := range h[0] {
			if ch >= 'A' && ch <= 'Z' {
				t.Fatalf("header name %q is not lowercased", h[0])
			}
		}
	}
	if !headerNameIsBytes(p.hdr[0][0], "content-type") {
		t.Fatalf("first header name is %q, want content-type", p.hdr[0][0])
	}
}

// The refs must survive the read buffer being overwritten, which is what
// happens while a buffered response body streams through it.
func TestParsedHeadersSurviveSourceBufferReuse(t *testing.T) {
	var p h1Parser
	src := append([]byte(nil), probeHeadTypical...)
	if _, _, err := p.parseHeaderBlock(src, "GET"); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for i := range src {
		src[i] = 'X'
	}
	got := string(appendProxyResponseHead(nil, 200, respHeaders{raw: p.hdr}, 1024, true, ""))
	for _, want := range []string{
		"content-type: text/html; charset=utf-8\r\n",
		"etag: \"a1b2c3d4e5f6\"\r\n",
		"cache-control: public, max-age=3600\r\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("serialised head lost %q; got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "XXX") {
		t.Fatalf("serialised head aliased the overwritten source buffer:\n%s", got)
	}
}

func benchParse(b *testing.B, head []byte) {
	var p h1Parser
	src := make([]byte, len(head))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(src, head)
		p.hdr = p.hdr[:0]
		if _, _, err := p.parseHeaderBlock(src, "GET"); err != nil {
			b.Fatalf("parse: %v", err)
		}
	}
	if len(p.hdr) == 0 {
		b.Fatal("parsed nothing")
	}
}

func benchParseAndMaterialise(b *testing.B, head []byte) {
	var p h1Parser
	src := make([]byte, len(head))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(src, head)
		p.hdr = p.hdr[:0]
		if _, _, err := p.parseHeaderBlock(src, "GET"); err != nil {
			b.Fatalf("parse: %v", err)
		}
		p.stringHeaders()
	}
	if len(p.strs) == 0 {
		b.Fatal("materialised nothing")
	}
}

func BenchmarkResponseHeaderParseTypical(b *testing.B) { benchParse(b, probeHeadTypical) }
func BenchmarkResponseHeaderParseMinimal(b *testing.B) { benchParse(b, probeHeadMinimal) }

// The cost a hook or a cacheable response still pays, for comparison.
func BenchmarkResponseHeaderMaterialiseTypical(b *testing.B) {
	benchParseAndMaterialise(b, probeHeadTypical)
}
