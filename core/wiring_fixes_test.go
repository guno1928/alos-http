package core

import (
	"strings"
	"testing"
	"time"
)

func TestNewAppliesReadWriteTimeoutDefaults(t *testing.T) {
	s := New(Config{})
	if s.config.ReadTimeout != 30*time.Second {
		t.Fatalf("ReadTimeout = %v, want 30s", s.config.ReadTimeout)
	}
	if s.config.WriteTimeout != 30*time.Second {
		t.Fatalf("WriteTimeout = %v, want 30s", s.config.WriteTimeout)
	}
}

func TestNewSanitizesServerName(t *testing.T) {
	s := New(Config{ServerName: "evil\r\nX-Injected: 1"})
	if strings.ContainsAny(s.config.ServerName, "\r\n") {
		t.Fatalf("ServerName still contains CRLF: %q", s.config.ServerName)
	}
	if s.config.ServerName != "evilX-Injected: 1" {
		t.Fatalf("ServerName = %q", s.config.ServerName)
	}
}

func TestResolveReadCap(t *testing.T) {
	if got := resolveReadCap(0); got != 2<<20 {
		t.Fatalf("resolveReadCap(0) = %d, want %d", got, 2<<20)
	}
	if got := resolveReadCap(4096); got != 4096 {
		t.Fatalf("resolveReadCap(4096) = %d, want 4096", got)
	}
	if got := resolveReadCap(-1); got != readCapUnlimited {
		t.Fatalf("resolveReadCap(-1) = %d, want %d", got, readCapUnlimited)
	}
}

func TestH2SettingResolvers(t *testing.T) {
	def := New(Config{})
	if def.h2MaxStreams() != H2MaxConcurrentStream {
		t.Fatalf("default h2MaxStreams = %d, want %d", def.h2MaxStreams(), H2MaxConcurrentStream)
	}
	if def.h2InitialWindow() != H2StreamWindowSize {
		t.Fatalf("default h2InitialWindow = %d, want %d", def.h2InitialWindow(), H2StreamWindowSize)
	}
	if def.h2MaxFrameSize() != H2DefaultMaxFrameSize {
		t.Fatalf("default h2MaxFrameSize = %d, want %d", def.h2MaxFrameSize(), H2DefaultMaxFrameSize)
	}

	custom := New(Config{H2MaxConcurrentStreams: 100, H2InitialWindowSize: 65535, H2MaxFrameSize: 32768})
	if custom.h2MaxStreams() != 100 {
		t.Fatalf("custom h2MaxStreams = %d, want 100", custom.h2MaxStreams())
	}
	if custom.h2InitialWindow() != 65535 {
		t.Fatalf("custom h2InitialWindow = %d, want 65535", custom.h2InitialWindow())
	}
	if custom.h2MaxFrameSize() != 32768 {
		t.Fatalf("custom h2MaxFrameSize = %d, want 32768", custom.h2MaxFrameSize())
	}
}

func TestServerNameInPlainResponse(t *testing.T) {
	s := New(Config{ServerName: "MyServer"})
	resp := &Response{StatusCode: 200}
	resp.lazyReq = &Request{Method: "GET", server: s}
	out := string(appendPlainResponseMode(resp, nil, true, false))
	if !strings.Contains(out, "Server: MyServer\r\n") {
		t.Fatalf("plain response missing custom Server header:\n%s", out)
	}

	def := New(Config{})
	respD := &Response{StatusCode: 200}
	respD.lazyReq = &Request{Method: "GET", server: def}
	outD := string(appendPlainResponseMode(respD, nil, true, false))
	if !strings.Contains(outD, "Server: ALOS\r\n") {
		t.Fatalf("default plain response missing Server: ALOS:\n%s", outD)
	}
}

func TestRootFastPathUsesServerName(t *testing.T) {
	s := New(Config{ServerName: "MyServer"})
	s.Router.GET("/", func(req *Request, resp *Response) { resp.String("hi") })
	s.Router.Build()
	s.computePlainRootFastResponse(true)
	if !s.plainRootFast.enabled {
		t.Fatal("root fast response not enabled")
	}
	if !strings.Contains(string(s.plainRootFast.getKeepAlive), "Server: MyServer\r\n") {
		t.Fatalf("root fast response missing custom Server header:\n%s", s.plainRootFast.getKeepAlive)
	}
}

func TestStreamMaxWriteSizeEnforced(t *testing.T) {
	w := &PlainH1StreamWriter{headersSent: true, maxWrite: 10}
	if err := w.WriteChunk(make([]byte, 20)); err != ErrBodyTooLarge {
		t.Fatalf("over-cap WriteChunk err = %v, want ErrBodyTooLarge", err)
	}

	h2 := &H2StreamWriter{headersSent: true, maxWrite: 10}
	if err := h2.WriteChunk(make([]byte, 20)); err != ErrBodyTooLarge {
		t.Fatalf("over-cap H2 WriteChunk err = %v, want ErrBodyTooLarge", err)
	}
}

func TestParseH1MaxHeaderCountRejects(t *testing.T) {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\n")
	for i := 0; i < 200; i++ {
		b.WriteString("A: b\r\n")
	}
	b.WriteString("\r\n")
	req := &Request{}
	_, _, _, _, _, _, tooLarge, ok := ParseH1RequestHead([]byte(b.String()), req, 8192, 128)
	if !tooLarge {
		t.Fatalf("200 headers with maxCount=128 should be tooLarge (ok=%v)", ok)
	}
}

func TestParseH1MaxHeaderBytesRejects(t *testing.T) {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\n")
	pad := "X-Pad: " + strings.Repeat("a", 200) + "\r\n"
	for b.Len() < 9000 {
		b.WriteString(pad)
	}
	b.WriteString("\r\n")
	req := &Request{}
	_, _, _, _, _, _, tooLarge, _ := ParseH1RequestHead([]byte(b.String()), req, 8192, 1024)
	if !tooLarge {
		t.Fatalf("9KB header block with maxBytes=8192 should be tooLarge")
	}
}

func TestSlowlorisHeaderTable(t *testing.T) {
	const maxBytes, maxCount = 8192, 128
	buildHeaders := func(n int) string {
		var b strings.Builder
		b.WriteString("GET / HTTP/1.1\r\n")
		for i := 0; i < n; i++ {
			b.WriteString("X-H: v\r\n")
		}
		b.WriteString("\r\n")
		return b.String()
	}
	buildBytes := func(target int) string {
		var b strings.Builder
		b.WriteString("GET / HTTP/1.1\r\n")
		pad := "X-Pad: " + strings.Repeat("a", 200) + "\r\n"
		for b.Len() < target {
			b.WriteString(pad)
		}
		b.WriteString("\r\n")
		return b.String()
	}

	cases := []struct {
		name         string
		data         string
		wantTooLarge bool
		wantOK       bool
	}{
		{"complete-small", "GET / HTTP/1.1\r\nHost: a\r\n\r\n", false, true},
		{"incomplete-under-limit", "GET / HTTP/1.1\r\nHost: a\r\n", false, false},
		{"too-many-headers", buildHeaders(200), true, false},
		{"header-bytes-over-limit", buildBytes(9000), true, false},
		{"headers-at-count-limit", buildHeaders(100), false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := &Request{}
			_, _, _, _, _, _, tooLarge, ok := ParseH1RequestHead([]byte(c.data), req, maxBytes, maxCount)
			if tooLarge != c.wantTooLarge || ok != c.wantOK {
				t.Fatalf("tooLarge=%v ok=%v, want tooLarge=%v ok=%v", tooLarge, ok, c.wantTooLarge, c.wantOK)
			}
		})
	}
}
