package core

import (
	"net"
	"strings"
	"testing"
	"time"
)

type captureConn struct {
	buf []byte
}

func (c *captureConn) Write(p []byte) (int, error)      { c.buf = append(c.buf, p...); return len(p), nil }
func (c *captureConn) Read(p []byte) (int, error)       { return 0, net.ErrClosed }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return nil }
func (c *captureConn) RemoteAddr() net.Addr             { return nil }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

func plainResp(s *Server, method string, status int) *Response {
	resp := &Response{StatusCode: status}
	resp.lazyReq = &Request{Method: method, server: s}
	return resp
}

// ===================== #1 rootFastEligible (hooks bypass) =====================

func TestRootFastEligible(t *testing.T) {
	t.Run("baseline-eligible", func(t *testing.T) {
		if !New(Config{}).rootFastEligible() {
			t.Fatal("clean server should be fast-eligible")
		}
	})
	t.Run("onRequest-hook-disables", func(t *testing.T) {
		s := New(Config{})
		s.OnRequest(func(*Request, *Response) bool { return true })
		if s.rootFastEligible() {
			t.Fatal("OnRequest hook must disable fast path")
		}
	})
	t.Run("onResponse-hook-disables", func(t *testing.T) {
		s := New(Config{})
		s.OnResponse(func(*Request, *Response) {})
		if s.rootFastEligible() {
			t.Fatal("OnResponse hook must disable fast path")
		}
	})
	t.Run("ratelimit-disables", func(t *testing.T) {
		s := New(Config{})
		s.RateLimit = &RateLimitEngine{}
		if s.rootFastEligible() {
			t.Fatal("RateLimit must disable fast path")
		}
	})
	t.Run("cors-disables", func(t *testing.T) {
		s := New(Config{})
		s.CORS = &CORSEngine{}
		if s.rootFastEligible() {
			t.Fatal("CORS must disable fast path")
		}
	})
	t.Run("compress-disables", func(t *testing.T) {
		if New(Config{EnableCompress: true}).rootFastEligible() {
			t.Fatal("compression must disable fast path")
		}
	})
	t.Run("perip-disables", func(t *testing.T) {
		s := New(Config{})
		s.perIPLimiter = &perIPRequestLimiter{}
		if s.rootFastEligible() {
			t.Fatal("perIP limiter must disable fast path")
		}
	})
}

// ===================== #11 New() defaults =====================

func TestNewDefaultsComplete(t *testing.T) {
	s := New(Config{})
	cases := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"ReadTimeout", s.config.ReadTimeout, 30 * time.Second},
		{"WriteTimeout", s.config.WriteTimeout, 30 * time.Second},
		{"IdleTimeout", s.config.IdleTimeout, 120 * time.Second},
		{"HandshakeTimeout", s.config.HandshakeTimeout, 30 * time.Second},
		{"ShutdownTimeout", s.config.ShutdownTimeout, 30 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Fatalf("%s = %v, want %v", c.name, c.got, c.want)
			}
		})
	}
	t.Run("MaxHeaderSize", func(t *testing.T) {
		if s.config.MaxHeaderSize != 8192 {
			t.Fatalf("MaxHeaderSize = %d", s.config.MaxHeaderSize)
		}
	})
	t.Run("ServerName", func(t *testing.T) {
		if s.config.ServerName != "ALOS" {
			t.Fatalf("ServerName = %q", s.config.ServerName)
		}
	})
	t.Run("explicit-values-preserved", func(t *testing.T) {
		s2 := New(Config{ReadTimeout: 5 * time.Second, WriteTimeout: 7 * time.Second})
		if s2.config.ReadTimeout != 5*time.Second || s2.config.WriteTimeout != 7*time.Second {
			t.Fatalf("explicit timeouts overwritten: r=%v w=%v", s2.config.ReadTimeout, s2.config.WriteTimeout)
		}
	})
}

// ===================== #2 ServerName sanitize + wiring =====================

func TestServerNameSanitizeTable(t *testing.T) {
	cases := []struct{ in, want string }{
		{"MyServer", "MyServer"},
		{"a\r\nb", "ab"},
		{"a\nb", "ab"},
		{"a\rb", "ab"},
		{"nginx/1.0", "nginx/1.0"},
		{"", "ALOS"},
		{"\r\n", "ALOS"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := New(Config{ServerName: c.in}).config.ServerName
			if got != c.want {
				t.Fatalf("ServerName(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestPlainResponseServerNameCustom(t *testing.T) {
	out := string(appendPlainResponseMode(plainResp(New(Config{ServerName: "Zed"}), "GET", 200), nil, true, false))
	if !strings.Contains(out, "Server: Zed\r\n") {
		t.Fatalf("missing custom Server:\n%s", out)
	}
}

func TestPlainResponseServerNameDefault(t *testing.T) {
	out := string(appendPlainResponseMode(plainResp(New(Config{}), "GET", 200), nil, true, false))
	if !strings.Contains(out, "Server: ALOS\r\n") {
		t.Fatalf("missing default Server:\n%s", out)
	}
}

func TestPlainResponseCloseUsesServerName(t *testing.T) {
	out := string(appendPlainResponseMode(plainResp(New(Config{ServerName: "Zed"}), "GET", 200), nil, false, false))
	if !strings.Contains(out, "Connection: close\r\nServer: Zed\r\n") {
		t.Fatalf("close response wrong:\n%s", out)
	}
}

func TestBuildH1ResponseServerName(t *testing.T) {
	s := New(Config{ServerName: "Zed"})
	resp := &Response{}
	resp.lazyReq = &Request{Method: "GET", server: s}
	resp.Status(200).String("hi")
	data, bp := BuildH1Response(resp)
	got := string(data)
	if bp != nil {
		*bp = (*bp)[:0]
	}
	if !strings.Contains(got, "Server: Zed\r\n") {
		t.Fatalf("BuildH1Response missing custom Server:\n%s", got)
	}
}

func TestRootFastServerName(t *testing.T) {
	t.Run("custom", func(t *testing.T) {
		s := New(Config{ServerName: "Zed"})
		s.Router.GET("/", func(req *Request, resp *Response) { resp.String("ok") })
		s.Router.Build()
		s.computePlainRootFastResponse(true)
		if !s.plainRootFast.enabled || !strings.Contains(string(s.plainRootFast.getKeepAlive), "Server: Zed\r\n") {
			t.Fatalf("root fast custom name failed:\n%s", s.plainRootFast.getKeepAlive)
		}
	})
	t.Run("default", func(t *testing.T) {
		s := New(Config{})
		s.Router.GET("/", func(req *Request, resp *Response) { resp.String("ok") })
		s.Router.Build()
		s.computePlainRootFastResponse(true)
		if !strings.Contains(string(s.plainRootFast.getKeepAlive), "Server: ALOS\r\n") {
			t.Fatalf("root fast default name failed:\n%s", s.plainRootFast.getKeepAlive)
		}
	})
}

func TestStreamPlainEmitsServer(t *testing.T) {
	s := New(Config{ServerName: "Zed"})
	cc := &captureConn{}
	w := s.NewPlainH1StreamWriter(cc)
	w.method = "GET"
	if err := w.WriteHeader(200, nil, "text/plain"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cc.buf), "Server: Zed\r\n") {
		t.Fatalf("streaming writer did not emit Server:\n%s", cc.buf)
	}
}

func TestStreamPlainRespectsHandlerServer(t *testing.T) {
	s := New(Config{ServerName: "Zed"})
	cc := &captureConn{}
	w := s.NewPlainH1StreamWriter(cc)
	w.method = "GET"
	if err := w.WriteHeader(200, [][2]string{{"Server", "Custom"}}, "text/plain"); err != nil {
		t.Fatal(err)
	}
	out := string(cc.buf)
	if !strings.Contains(out, "Server: Custom\r\n") {
		t.Fatalf("handler Server not present:\n%s", out)
	}
	if strings.Contains(out, "Server: Zed\r\n") {
		t.Fatalf("duplicate Server header emitted:\n%s", out)
	}
}

// ===================== #7 resolveReadCap =====================

func TestResolveReadCapTable(t *testing.T) {
	cases := []struct {
		in   int64
		want int
	}{
		{0, 2 << 20},
		{1, 1},
		{4096, 4096},
		{8 << 20, 8 << 20},
		{-1, readCapUnlimited},
		{-100, readCapUnlimited},
	}
	for _, c := range cases {
		t.Run(strings.TrimSpace(time.Duration(c.in).String()), func(t *testing.T) {
			if got := resolveReadCap(c.in); got != c.want {
				t.Fatalf("resolveReadCap(%d) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

// ===================== helpers defaultDuration / defaultUint32 =====================

func TestDefaultDuration(t *testing.T) {
	if defaultDuration(0, 9) != 9 {
		t.Fatal("zero should use fallback")
	}
	if defaultDuration(-3, 9) != 9 {
		t.Fatal("negative should use fallback")
	}
	if defaultDuration(5, 9) != 5 {
		t.Fatal("positive should be kept")
	}
}

func TestDefaultUint32(t *testing.T) {
	if defaultUint32(0, 7) != 7 {
		t.Fatal("zero should use fallback")
	}
	if defaultUint32(3, 7) != 3 {
		t.Fatal("nonzero should be kept")
	}
}

// ===================== #9 / extra5 H2 resolvers + SETTINGS =====================

func TestH2ResolversTable(t *testing.T) {
	def := New(Config{})
	cus := New(Config{H2MaxConcurrentStreams: 100, H2InitialWindowSize: 65535, H2MaxFrameSize: 32768})
	cases := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"streams-default", def.h2MaxStreams(), H2MaxConcurrentStream},
		{"window-default", def.h2InitialWindow(), H2StreamWindowSize},
		{"frame-default", def.h2MaxFrameSize(), H2DefaultMaxFrameSize},
		{"streams-custom", cus.h2MaxStreams(), 100},
		{"window-custom", cus.h2InitialWindow(), 65535},
		{"frame-custom", cus.h2MaxFrameSize(), 32768},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Fatalf("%s = %d, want %d", c.name, c.got, c.want)
			}
		})
	}
}

func decodeH2Settings(frame []byte) map[uint16]uint32 {
	m := map[uint16]uint32{}
	if len(frame) < 9 {
		return m
	}
	plen := int(frame[0])<<16 | int(frame[1])<<8 | int(frame[2])
	p := frame[9:]
	if plen > len(p) {
		return m
	}
	p = p[:plen]
	for len(p) >= 6 {
		id := uint16(p[0])<<8 | uint16(p[1])
		val := uint32(p[2])<<24 | uint32(p[3])<<16 | uint32(p[4])<<8 | uint32(p[5])
		m[id] = val
		p = p[6:]
	}
	return m
}

func h2SettingsFor(s *Server) map[uint16]uint32 {
	settings := [][2]uint32{
		{uint32(H2SettingHeaderTableSize), 0},
		{uint32(H2SettingMaxConcurrentStreams), s.h2MaxStreams()},
		{uint32(H2SettingInitialWindowSize), s.h2InitialWindow()},
		{uint32(H2SettingMaxFrameSize), s.h2MaxFrameSize()},
	}
	return decodeH2Settings(H2WriteSettings(nil, settings))
}

func TestH2SettingsFrameDefault(t *testing.T) {
	m := h2SettingsFor(New(Config{}))
	if m[uint16(H2SettingMaxConcurrentStreams)] != uint32(H2MaxConcurrentStream) {
		t.Fatalf("streams setting = %d", m[uint16(H2SettingMaxConcurrentStreams)])
	}
	if m[uint16(H2SettingMaxFrameSize)] != uint32(H2DefaultMaxFrameSize) {
		t.Fatalf("frame setting = %d", m[uint16(H2SettingMaxFrameSize)])
	}
}

func TestH2SettingsFrameCustom(t *testing.T) {
	m := h2SettingsFor(New(Config{H2MaxConcurrentStreams: 128, H2InitialWindowSize: 65535, H2MaxFrameSize: 32768}))
	if m[uint16(H2SettingMaxConcurrentStreams)] != 128 {
		t.Fatalf("streams = %d, want 128", m[uint16(H2SettingMaxConcurrentStreams)])
	}
	if m[uint16(H2SettingInitialWindowSize)] != 65535 {
		t.Fatalf("window = %d, want 65535", m[uint16(H2SettingInitialWindowSize)])
	}
	if m[uint16(H2SettingMaxFrameSize)] != 32768 {
		t.Fatalf("frame = %d, want 32768", m[uint16(H2SettingMaxFrameSize)])
	}
}

// ===================== #6 / #11 / extra11 header size + count =====================

func mkHeaders(n int) []byte {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\n")
	for i := 0; i < n; i++ {
		b.WriteString("X-H: v\r\n")
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

func mkBytes(target int) []byte {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\n")
	pad := "X-Pad: " + strings.Repeat("a", 200) + "\r\n"
	for b.Len() < target {
		b.WriteString(pad)
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

func TestParseHeaderByteLimit(t *testing.T) {
	cases := []struct {
		name         string
		data         []byte
		maxBytes     int
		wantTooLarge bool
	}{
		{"small-ok", []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), 8192, false},
		{"over-8k", mkBytes(9000), 8192, true},
		{"under-custom", mkBytes(3000), 8192, false},
		{"over-custom-small", mkBytes(3000), 2048, true},
		{"default-limit-zero", mkBytes(9000), 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, _, _, _, _, tooLarge, _ := ParseH1RequestHead(c.data, &Request{}, c.maxBytes, 1024)
			if tooLarge != c.wantTooLarge {
				t.Fatalf("tooLarge = %v, want %v", tooLarge, c.wantTooLarge)
			}
		})
	}
}

func TestParseHeaderCountLimit(t *testing.T) {
	cases := []struct {
		name         string
		n            int
		maxCount     int
		wantTooLarge bool
	}{
		{"under", 50, 128, false},
		{"at-limit", 128, 128, false},
		{"over", 200, 128, true},
		{"custom-small", 20, 10, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, _, _, _, _, tooLarge, _ := ParseH1RequestHead(mkHeaders(c.n), &Request{}, 1<<20, c.maxCount)
			if tooLarge != c.wantTooLarge {
				t.Fatalf("n=%d maxCount=%d tooLarge=%v want %v", c.n, c.maxCount, tooLarge, c.wantTooLarge)
			}
		})
	}
}

func TestParseCorrectnessPreserved(t *testing.T) {
	t.Run("get-path", func(t *testing.T) {
		req := &Request{}
		_, _, _, _, _, _, tooLarge, ok := ParseH1RequestHead([]byte("GET /foo HTTP/1.1\r\nHost: a\r\n\r\n"), req, 0, 0)
		if !ok || tooLarge || req.Method != "GET" || req.Path != "/foo" || req.Host != "a" {
			t.Fatalf("parse mismatch: ok=%v method=%q path=%q host=%q", ok, req.Method, req.Path, req.Host)
		}
	})
	t.Run("post-content-length", func(t *testing.T) {
		req := &Request{}
		_, cl, hasCL, _, _, _, _, ok := ParseH1RequestHead([]byte("POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 42\r\n\r\n"), req, 0, 0)
		if !ok || !hasCL || cl != 42 || req.Method != "POST" {
			t.Fatalf("post parse mismatch: ok=%v hasCL=%v cl=%d", ok, hasCL, cl)
		}
	})
	t.Run("connection-close", func(t *testing.T) {
		req := &Request{}
		_, _, _, closeConn, _, _, _, ok := ParseH1RequestHead([]byte("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"), req, 0, 0)
		if !ok || !closeConn {
			t.Fatalf("close flag mismatch: ok=%v close=%v", ok, closeConn)
		}
	})
	t.Run("chunked-flagged", func(t *testing.T) {
		req := &Request{}
		_, _, _, _, _, chunked, _, ok := ParseH1RequestHead([]byte("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"), req, 0, 0)
		if !ok || !chunked {
			t.Fatalf("chunked flag mismatch: ok=%v chunked=%v", ok, chunked)
		}
	})
	t.Run("incomplete-reads-more", func(t *testing.T) {
		req := &Request{}
		_, _, _, _, _, _, tooLarge, ok := ParseH1RequestHead([]byte("GET / HTTP/1.1\r\nHost: a\r\n"), req, 8192, 128)
		if ok || tooLarge {
			t.Fatalf("incomplete should be ok=false tooLarge=false, got ok=%v tooLarge=%v", ok, tooLarge)
		}
	})
}

// ===================== #8 MaxWriteSize streaming =====================

func TestStreamMaxWriteAllWriters(t *testing.T) {
	t.Run("plain-over-cap", func(t *testing.T) {
		w := &PlainH1StreamWriter{headersSent: true, maxWrite: 10}
		if err := w.WriteChunk(make([]byte, 20)); err != ErrBodyTooLarge {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("h1-over-cap", func(t *testing.T) {
		w := &H1StreamWriter{headersSent: true, maxWrite: 10}
		if err := w.WriteChunk(make([]byte, 20)); err != ErrBodyTooLarge {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("h2-over-cap", func(t *testing.T) {
		w := &H2StreamWriter{headersSent: true, maxWrite: 10}
		if err := w.WriteChunk(make([]byte, 20)); err != ErrBodyTooLarge {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("plain-factory-sets-cap", func(t *testing.T) {
		s := New(Config{MaxWriteSize: 4096})
		w := s.NewPlainH1StreamWriter(&captureConn{})
		if w.maxWrite != 4096 || w.written != 0 {
			t.Fatalf("factory maxWrite=%d written=%d", w.maxWrite, w.written)
		}
	})
	t.Run("h1-factory-sets-cap", func(t *testing.T) {
		s := New(Config{MaxWriteSize: 4096})
		w := s.NewH1StreamWriter(&captureConn{}, nil)
		if w.maxWrite != 4096 || w.written != 0 {
			t.Fatalf("factory maxWrite=%d written=%d", w.maxWrite, w.written)
		}
	})
}

// ===================== #5 / extra6 QUIC idle + flow control =====================

func newTestQUIC(s *Server) *QUICConn {
	return newQUICConn(s, nil, nil, make([]byte, 8), make([]byte, 8))
}

func TestQUICConnConfig(t *testing.T) {
	t.Run("idle-default", func(t *testing.T) {
		qc := newTestQUIC(New(Config{}))
		if qc.idleTimeout != 120*time.Second {
			t.Fatalf("idle = %v (config IdleTimeout default is 120s)", qc.idleTimeout)
		}
	})
	t.Run("idle-custom", func(t *testing.T) {
		qc := newTestQUIC(New(Config{IdleTimeout: 15 * time.Second}))
		if qc.idleTimeout != 15*time.Second {
			t.Fatalf("idle = %v, want 15s", qc.idleTimeout)
		}
	})
	t.Run("maxdata-default", func(t *testing.T) {
		qc := newTestQUIC(New(Config{}))
		if qc.maxDataLocal != uint64(quicInitialMaxData) {
			t.Fatalf("maxDataLocal = %d, want %d", qc.maxDataLocal, quicInitialMaxData)
		}
	})
	t.Run("maxdata-custom", func(t *testing.T) {
		qc := newTestQUIC(New(Config{QUICMaxData: 5 << 20}))
		if qc.maxDataLocal != 5<<20 {
			t.Fatalf("maxDataLocal = %d, want %d", qc.maxDataLocal, 5<<20)
		}
	})
}

func decodeQUICTP(tp []byte, wantID uint64) (uint64, bool) {
	i := 0
	for i < len(tp) {
		id, n := quicParseVarint(tp[i:])
		if n == 0 {
			return 0, false
		}
		i += n
		l, n2 := quicParseVarint(tp[i:])
		if n2 == 0 {
			return 0, false
		}
		i += n2
		if i+int(l) > len(tp) {
			return 0, false
		}
		val := tp[i : i+int(l)]
		i += int(l)
		if id == wantID {
			v, _ := quicParseVarint(val)
			return v, true
		}
	}
	return 0, false
}

func TestQUICTransportParams(t *testing.T) {
	t.Run("idle-ms-custom", func(t *testing.T) {
		qc := newTestQUIC(New(Config{IdleTimeout: 20 * time.Second}))
		tp := quicBuildTransportParams(qc)
		got, ok := decodeQUICTP(tp, quicTPMaxIdleTimeout)
		if !ok || got != 20000 {
			t.Fatalf("idle TP = %d ms (ok=%v), want 20000", got, ok)
		}
	})
	t.Run("maxdata-custom", func(t *testing.T) {
		qc := newTestQUIC(New(Config{QUICMaxData: 3 << 20}))
		tp := quicBuildTransportParams(qc)
		got, ok := decodeQUICTP(tp, quicTPInitialMaxData)
		if !ok || got != 3<<20 {
			t.Fatalf("maxdata TP = %d (ok=%v), want %d", got, ok, 3<<20)
		}
	})
	t.Run("streamdata-custom", func(t *testing.T) {
		qc := newTestQUIC(New(Config{QUICMaxStreamData: 512 << 10}))
		tp := quicBuildTransportParams(qc)
		got, ok := decodeQUICTP(tp, quicTPInitialMaxStreamBidiR)
		if !ok || got != 512<<10 {
			t.Fatalf("streamdata TP = %d (ok=%v), want %d", got, ok, 512<<10)
		}
	})
}

// ===================== #10 WebSocket timeout resolution =====================

func TestWSTimeoutResolution(t *testing.T) {
	t.Run("read-default", func(t *testing.T) {
		if got := defaultDuration(New(Config{}).config.WSReadTimeout, wsDefaultReadTimeout); got != wsDefaultReadTimeout {
			t.Fatalf("ws read default = %v", got)
		}
	})
	t.Run("read-custom", func(t *testing.T) {
		if got := defaultDuration(New(Config{WSReadTimeout: 9 * time.Second}).config.WSReadTimeout, wsDefaultReadTimeout); got != 9*time.Second {
			t.Fatalf("ws read custom = %v", got)
		}
	})
	t.Run("write-default", func(t *testing.T) {
		if got := defaultDuration(New(Config{}).config.WSWriteTimeout, wsDefaultWriteTimeout); got != wsDefaultWriteTimeout {
			t.Fatalf("ws write default = %v", got)
		}
	})
	t.Run("write-custom", func(t *testing.T) {
		if got := defaultDuration(New(Config{WSWriteTimeout: 3 * time.Second}).config.WSWriteTimeout, wsDefaultWriteTimeout); got != 3*time.Second {
			t.Fatalf("ws write custom = %v", got)
		}
	})
}

// ===================== throughput benchmarks (regression guard) =====================

func BenchmarkParseH1Head(b *testing.B) {
	data := []byte("GET /dashboard HTTP/1.1\r\nHost: alos.gg\r\nUser-Agent: x\r\nAccept-Encoding: gzip\r\nCookie: s=1\r\nConnection: keep-alive\r\n\r\n")
	req := &Request{Headers: make([][2]string, 0, 16)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req.resetFastH1()
		ParseH1RequestHead(data, req, 8192, 128)
	}
}

func BenchmarkPlainResponseServerName(b *testing.B) {
	s := New(Config{ServerName: "Zed"})
	resp := plainResp(s, "GET", 200)
	buf := make([]byte, 0, 512)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = appendPlainResponseMode(resp, buf[:0], true, false)
	}
}

func BenchmarkServerConnHeaders(b *testing.B) {
	resp := plainResp(New(Config{ServerName: "Zed"}), "GET", 200)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = serverConnHeaders(resp)
	}
}

func BenchmarkResolveReadCap(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = resolveReadCap(int64(i & 1))
	}
}

func BenchmarkH2Resolvers(b *testing.B) {
	s := New(Config{})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = s.h2MaxStreams()
		_ = s.h2InitialWindow()
		_ = s.h2MaxFrameSize()
	}
}
