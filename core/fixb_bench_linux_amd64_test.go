package core

import "testing"

type fixBDiscardTransport struct{}

func (fixBDiscardTransport) start(*backendConn) error           { return nil }
func (fixBDiscardTransport) feed(*backendConn, []byte) error    { return nil }
func (fixBDiscardTransport) wrapOut(*backendConn, []byte) error { return nil }
func (fixBDiscardTransport) negotiatedALPN() string             { return "h2" }

var fixBChunkedTrailerResponse = []byte("HTTP/1.1 200 OK\r\n" +
	"Content-Type: text/plain\r\n" +
	"Transfer-Encoding: chunked\r\n\r\n" +
	"10\r\n0123456789abcdef\r\n" +
	"10\r\n0123456789abcdef\r\n" +
	"0\r\nX-Checksum: abc123\r\nX-Trailer-Two: value\r\n\r\n")

func BenchmarkFixBBackendReadChunkedTrailers(b *testing.B) {
	fpFixBenchBackendRead(b, fixBChunkedTrailerResponse)
}

func fixBH2Conn() (*eventLoop, *backendConn) {
	l := newLoopForTest()
	l.cfg.fill(1)
	c := &backendConn{fd: -1, be: &l.beLoop, state: connReady, key: poolKey{h2: true}, transport: fixBDiscardTransport{}}
	c.proto = &l.h2proto
	c.h2init()
	l.h2conns[c.key] = c
	l.liveConns = 1
	return l, c
}

func BenchmarkFixBH2HeadersOpenStream(b *testing.B) {
	l, c := fixBH2Conn()
	c.h2.nextID = 3
	var e hpackEncoder
	e.reset(nil)
	e.buf = append(e.buf, 0x88)
	e.field("content-type", "text/html; charset=utf-8")
	e.field("content-length", "1024")
	e.field("server", "origin")
	e.field("cache-control", "public, max-age=3600")
	block := e.buf
	h := &l.h2proto
	ex := &Exchange{req: &fpRequest{Method: "GET"}}
	st := &h2Stream{id: 1, ex: ex}
	b.ReportAllocs()
	for b.Loop() {
		*st = h2Stream{id: 1, ex: ex, headers: st.headers[:0]}
		c.h2.streams[1] = st
		if err := h.handleFrame(c, h2FrameHeaders, h2FlagEndHeaders, 1, block); err != nil {
			b.Fatalf("headers: %v", err)
		}
	}
}

func BenchmarkFixBH2DataFrame(b *testing.B) {
	l, c := fixBH2Conn()
	c.h2.nextID = 3
	h := &l.h2proto
	st := &h2Stream{id: 1, ex: &Exchange{req: &fpRequest{Method: "GET"}}}
	c.h2.streams[1] = st
	payload := make([]byte, 1024)
	b.ReportAllocs()
	for b.Loop() {
		st.body = st.body[:0]
		if err := h.handleFrame(c, h2FrameData, 0, 1, payload); err != nil {
			b.Fatalf("data: %v", err)
		}
	}
}

func BenchmarkFixBH2OpenStream(b *testing.B) {
	l, c := fixBH2Conn()
	h := &l.h2proto
	ex := &Exchange{req: &fpRequest{Method: "GET", Scheme: "http", Authority: "origin.test", Path: "/bench"}}
	b.ReportAllocs()
	for b.Loop() {
		c.h2.nextID = 1
		c.h2.pending = append(c.h2.pending[:0], ex)
		h.flushPending(c)
		delete(c.h2.streams, 1)
	}
}

func BenchmarkFixBProxyHeadNoDate(b *testing.B) {
	var p h1Parser
	if _, _, err := p.parseHeaderBlock([]byte("HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\nServer: origin\r\nCache-Control: no-cache\r\nX-Request-Id: 0123456789abcdef"), "GET"); err != nil {
		b.Fatal(err)
	}
	headers := respHeaders{raw: p.hdr}
	dst := appendProxyResponseHead(nil, 200, headers, 13, true, "")
	b.Run("buffered", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			dst = appendProxyResponseHead(dst[:0], 200, headers, 13, true, "")
		}
	})
	b.Run("stream", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			dst = appendProxyStreamHead(dst[:0], 200, headers, -1, true)
		}
	})
}

var fixBResponseHeaders = [][2]string{
	{"content-type", "text/html; charset=utf-8"},
	{"date", "Mon, 30 Jul 2026 08:47:33 GMT"},
	{"server", "origin"},
	{"cache-control", "public, max-age=3600"},
	{"content-length", "4096"},
	{"etag", "\"a1b2c3d4e5f6\""},
}

var fixBLengthSink int64

func BenchmarkFixBResponseContentLength(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		fixBLengthSink = fpResponseContentLength(fixBResponseHeaders)
	}
}
