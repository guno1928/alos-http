//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// dpHeaderWatcher records the headers each request carried upstream.
func dpHeaderWatcher(t *testing.T, out chan<- http.Header) string {
	t.Helper()
	return dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		select {
		case out <- req.Header.Clone():
		default:
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
}

// ---------- CRLF injection, at the serializer ----------

func TestDeepSerializerRejectsCRLFInHeaderValue(t *testing.T) {
	req := &Request{Method: "GET", Path: "/x", RawPath: "/x",
		Headers: [][2]string{{"X-A", "ok"}, {"X-B", "bad\r\nX-Evil: 1"}}}
	out := string(appendProxyRequest(nil, req, "h.test", "1.2.3.4"))
	if strings.Contains(out, "X-Evil") {
		t.Fatalf("CRLF in a value forged a header:\n%s", out)
	}
	if !strings.Contains(out, "X-A: ok\r\n") {
		t.Error("a clean header was dropped alongside the poisoned one")
	}
}

func TestDeepSerializerRejectsCRInHeaderValue(t *testing.T) {
	req := &Request{Method: "GET", Path: "/x", RawPath: "/x",
		Headers: [][2]string{{"X-B", "bad\rX-Evil: 1"}}}
	out := string(appendProxyRequest(nil, req, "h.test", ""))
	if strings.Contains(out, "X-Evil") {
		t.Fatalf("bare CR forged a header:\n%s", out)
	}
}

func TestDeepSerializerRejectsLFInHeaderValue(t *testing.T) {
	req := &Request{Method: "GET", Path: "/x", RawPath: "/x",
		Headers: [][2]string{{"X-B", "bad\nX-Evil: 1"}}}
	out := string(appendProxyRequest(nil, req, "h.test", ""))
	if strings.Contains(out, "X-Evil") {
		t.Fatalf("bare LF forged a header:\n%s", out)
	}
}

func TestDeepSerializerRejectsCRLFInHeaderName(t *testing.T) {
	req := &Request{Method: "GET", Path: "/x", RawPath: "/x",
		Headers: [][2]string{{"X-B\r\nX-Evil: 1", "v"}}}
	out := string(appendProxyRequest(nil, req, "h.test", ""))
	if strings.Contains(out, "X-Evil") {
		t.Fatalf("CRLF in a name forged a header:\n%s", out)
	}
}

func TestDeepSerializerSanitisesTarget(t *testing.T) {
	req := &Request{Method: "GET", Path: "/x", RawPath: "/x HTTP/1.1\r\nX-Evil: 1"}
	out := string(appendProxyRequest(nil, req, "h.test", ""))
	if strings.Contains(out, "X-Evil") {
		t.Fatalf("CRLF in the target forged a header:\n%s", out)
	}
	if !strings.HasPrefix(out, "GET / HTTP/1.1\r\n") {
		t.Errorf("poisoned target should collapse to /, got: %q", firstLine(out))
	}
}

func TestDeepSerializerSanitisesHost(t *testing.T) {
	req := &Request{Method: "GET", Path: "/x", RawPath: "/x"}
	out := string(appendProxyRequest(nil, req, "evil\r\nX-Evil: 1", ""))
	if strings.Contains(out, "X-Evil") {
		t.Fatalf("CRLF in the Host forged a header:\n%s", out)
	}
}

func TestDeepSerializerSanitisesClientIP(t *testing.T) {
	req := &Request{Method: "GET", Path: "/x", RawPath: "/x"}
	out := string(appendProxyRequest(nil, req, "h.test", "1.2.3.4\r\nX-Evil: 1"))
	if strings.Contains(out, "X-Evil") {
		t.Fatalf("CRLF in the client IP forged a header:\n%s", out)
	}
}

func TestDeepSerializerEmitsExactlyOneHeaderTerminator(t *testing.T) {
	req := &Request{Method: "POST", Path: "/x", RawPath: "/x",
		Headers: [][2]string{{"X-A", "1"}}, Body: []byte("hi")}
	out := string(appendProxyRequest(nil, req, "h.test", "1.2.3.4"))
	if n := strings.Count(out, "\r\n\r\n"); n != 1 {
		t.Fatalf("request has %d header terminators:\n%q", n, out)
	}
	if !strings.HasSuffix(out, "\r\n\r\nhi") {
		t.Fatalf("body not placed after the terminator:\n%q", out)
	}
}

// ---------- forwarding-header spoofing ----------

func TestDeepClientXFFIsReplaced(t *testing.T) {
	seen := make(chan http.Header, 1)
	addr := dpHeaderWatcher(t, seen)
	dpRaw(t, addr, "GET /x HTTP/1.1\r\nHost: origin.test\r\n"+
		"X-Forwarded-For: 6.6.6.6\r\nConnection: close\r\n\r\n", 3*time.Second)
	h := <-seen
	xff := h.Values("X-Forwarded-For")
	for _, v := range xff {
		if strings.Contains(v, "6.6.6.6") {
			t.Fatalf("client-supplied XFF survived: %v", xff)
		}
	}
	if len(xff) != 1 {
		t.Fatalf("expected exactly one XFF header, got %v", xff)
	}
}

func TestDeepClientXRealIPIsStripped(t *testing.T) {
	seen := make(chan http.Header, 1)
	addr := dpHeaderWatcher(t, seen)
	dpRaw(t, addr, "GET /x HTTP/1.1\r\nHost: origin.test\r\n"+
		"X-Real-IP: 6.6.6.6\r\nConnection: close\r\n\r\n", 3*time.Second)
	if v := (<-seen).Get("X-Real-Ip"); strings.Contains(v, "6.6.6.6") {
		t.Fatalf("client-supplied X-Real-IP survived: %q", v)
	}
}

func TestDeepClientForwardedIsStripped(t *testing.T) {
	seen := make(chan http.Header, 1)
	addr := dpHeaderWatcher(t, seen)
	dpRaw(t, addr, "GET /x HTTP/1.1\r\nHost: origin.test\r\n"+
		"Forwarded: for=6.6.6.6\r\nConnection: close\r\n\r\n", 3*time.Second)
	if v := (<-seen).Get("Forwarded"); strings.Contains(v, "6.6.6.6") {
		t.Fatalf("client-supplied Forwarded survived: %q", v)
	}
}

func TestDeepXFFCarriesRealClientIP(t *testing.T) {
	seen := make(chan http.Header, 1)
	addr := dpHeaderWatcher(t, seen)
	dpRaw(t, addr, "GET /x HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n", 3*time.Second)
	if v := (<-seen).Get("X-Forwarded-For"); !strings.HasPrefix(v, "127.0.0.1") {
		t.Fatalf("XFF = %q, want the loopback client address", v)
	}
}

// ---------- hop-by-hop hygiene ----------

func TestDeepHopByHopRequestHeadersNotRelayed(t *testing.T) {
	seen := make(chan http.Header, 1)
	addr := dpHeaderWatcher(t, seen)
	dpRaw(t, addr, "GET /x HTTP/1.1\r\nHost: origin.test\r\n"+
		"Keep-Alive: timeout=5\r\nProxy-Authorization: Basic xx\r\n"+
		"TE: trailers\r\nConnection: close\r\n\r\n", 3*time.Second)
	h := <-seen
	for _, name := range []string{"Keep-Alive", "Proxy-Authorization", "Te"} {
		if v := h.Get(name); v != "" {
			t.Errorf("hop-by-hop header %s reached the backend as %q", name, v)
		}
	}
}

func TestDeepUpstreamConnectionIsKeepAlive(t *testing.T) {
	seen := make(chan http.Header, 1)
	addr := dpHeaderWatcher(t, seen)
	dpRaw(t, addr, "GET /x HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n", 3*time.Second)
	if v := (<-seen).Get("Connection"); !strings.EqualFold(v, "keep-alive") {
		t.Fatalf("backend saw Connection: %q; the client's close must not be relayed", v)
	}
}

func TestDeepUpstreamAcceptEncodingIsIdentity(t *testing.T) {
	seen := make(chan http.Header, 1)
	addr := dpHeaderWatcher(t, seen)
	dpRaw(t, addr, "GET /x HTTP/1.1\r\nHost: origin.test\r\n"+
		"Accept-Encoding: gzip, br\r\nConnection: close\r\n\r\n", 3*time.Second)
	if v := (<-seen).Get("Accept-Encoding"); v != "identity" {
		t.Fatalf("backend saw Accept-Encoding %q, want identity", v)
	}
}

func TestDeepHopByHopResponseHeadersNotRelayed(t *testing.T) {
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"+
			"Keep-Alive: timeout=5\r\nProxy-Authenticate: Basic\r\nX-Keep: yes\r\n\r\nok")
	})
	resp, _ := doProxyGet(t, addr, "/hh")
	if v := resp.Header.Get("Keep-Alive"); v != "" {
		t.Errorf("Keep-Alive relayed to the client as %q", v)
	}
	if v := resp.Header.Get("Proxy-Authenticate"); v != "" {
		t.Errorf("Proxy-Authenticate relayed to the client as %q", v)
	}
	if v := resp.Header.Get("X-Keep"); v != "yes" {
		t.Errorf("a normal header was wrongly dropped: %q", v)
	}
}

// ---------- Host handling ----------

// By default the upstream Host is the backend authority, port included. That
// matches nginx's $proxy_host and RFC 9110; PreserveHost and HostHeader are the
// knobs for anything else.
func TestDeepDefaultHostIsBackendAuthority(t *testing.T) {
	seen := make(chan string, 1)
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		select {
		case seen <- req.Host:
		default:
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	doProxyGet(t, addr, "/x")
	if host := <-seen; !strings.HasPrefix(host, "127.0.0.1:") {
		t.Fatalf("backend saw Host %q, want the backend authority", host)
	}
}

func TestDeepPreserveHostSendsClientHost(t *testing.T) {
	seen := make(chan string, 1)
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		select {
		case seen <- req.Host:
		default:
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:       "origin.test",
		Backends:     []BackendConfig{{Addr: o.addr()}},
		PreserveHost: true,
	}, nil)
	doProxyGet(t, addr, "/x")
	if host := <-seen; host != "origin.test" {
		t.Fatalf("PreserveHost sent %q, want origin.test", host)
	}
}

func TestDeepHostHeaderOverrideWins(t *testing.T) {
	seen := make(chan string, 1)
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		select {
		case seen <- req.Host:
		default:
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:       "origin.test",
		Backends:     []BackendConfig{{Addr: o.addr()}},
		HostHeader:   "override.internal",
		PreserveHost: true, // HostHeader must take precedence
	}, nil)
	doProxyGet(t, addr, "/x")
	if host := <-seen; host != "override.internal" {
		t.Fatalf("backend saw Host %q, want override.internal", host)
	}
}

// ---------- request smuggling ----------

func TestDeepContentLengthAndTransferEncodingRejected(t *testing.T) {
	var reached atomic.Int64
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		reached.Add(1)
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	// CL + TE together is the classic smuggling vector and must be refused.
	raw := "POST /s HTTP/1.1\r\nHost: origin.test\r\n" +
		"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: origin.test\r\n\r\n"
	out := dpRaw(t, addr, raw, 3*time.Second)
	if strings.Contains(out, "HTTP/1.1 200") && reached.Load() > 1 {
		t.Fatalf("a smuggled second request reached the backend (%d requests):\n%s", reached.Load(), out)
	}
	if !strings.Contains(out, "400") && reached.Load() > 1 {
		t.Fatalf("CL+TE was neither rejected nor safely handled:\n%s", out)
	}
}

func TestDeepOversizedHeaderBlockRejected(t *testing.T) {
	addr := dpProxy(t, dpFixed("ok"))
	var sb strings.Builder
	sb.WriteString("GET /x HTTP/1.1\r\nHost: origin.test\r\n")
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&sb, "X-Pad-%d: %s\r\n", i, strings.Repeat("z", 500))
	}
	sb.WriteString("\r\n")
	out := dpRaw(t, addr, sb.String(), 3*time.Second)
	if strings.Contains(out, "HTTP/1.1 200") {
		t.Fatalf("an oversized header block was accepted:\n%s", firstLine(out))
	}
}

func TestDeepNegativeContentLengthRejected(t *testing.T) {
	addr := dpProxy(t, dpFixed("ok"))
	out := dpRaw(t, addr, "POST /x HTTP/1.1\r\nHost: origin.test\r\nContent-Length: -5\r\n\r\n", 3*time.Second)
	if strings.Contains(out, "HTTP/1.1 200") {
		t.Fatalf("a negative Content-Length was accepted:\n%s", firstLine(out))
	}
}

func TestDeepMalformedChunkSizeRejected(t *testing.T) {
	addr := dpProxy(t, dpFixed("ok"))
	raw := "POST /x HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nabc\r\n0\r\n\r\n"
	out := dpRaw(t, addr, raw, 3*time.Second)
	if strings.Contains(out, "HTTP/1.1 200") {
		t.Fatalf("a malformed chunk size was accepted:\n%s", firstLine(out))
	}
}

// ---------- hook-driven injection ----------

func TestDeepHookCannotInjectViaHeaderName(t *testing.T) {
	var sawEvil atomic.Bool
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		if req.Header.Get("X-Evil") != "" {
			sawEvil.Store(true)
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, func(pe *ProxyEngine) {
		pe.OnRequest = func(pr *ProxyRequest) bool {
			pr.Headers = append(pr.Headers, [2]string{"X-Bad\r\nX-Evil: 1", "v"})
			return true
		}
	})
	doProxyGet(t, addr, "/x")
	if sawEvil.Load() {
		t.Fatal("a hook-supplied CRLF header name forged a header upstream")
	}
}

func TestDeepHookCannotInjectViaPath(t *testing.T) {
	var sawEvil atomic.Bool
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		if req.Header.Get("X-Evil") != "" {
			sawEvil.Store(true)
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, func(pe *ProxyEngine) {
		pe.OnRequest = func(pr *ProxyRequest) bool {
			pr.Path = "/x HTTP/1.1\r\nX-Evil: 1"
			return true
		}
	})
	doProxyGet(t, addr, "/x")
	if sawEvil.Load() {
		t.Fatal("a hook-supplied CRLF path forged a header upstream")
	}
}

func TestDeepHookCanBlockRequest(t *testing.T) {
	var reached atomic.Int64
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		reached.Add(1)
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, func(pe *ProxyEngine) {
		pe.OnRequest = func(pr *ProxyRequest) bool { return false }
	})
	resp, _ := doProxyGet(t, addr, "/blocked")
	if resp.StatusCode != 502 {
		t.Errorf("blocked request returned %d, want 502", resp.StatusCode)
	}
	if reached.Load() != 0 {
		t.Fatalf("a blocked request still reached the backend %d times", reached.Load())
	}
}

func TestDeepHookCanRewritePathAndHeaders(t *testing.T) {
	type got struct {
		uri  string
		hdr  string
	}
	seen := make(chan got, 1)
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		select {
		case seen <- got{req.RequestURI, req.Header.Get("X-Injected")}:
		default:
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, func(pe *ProxyEngine) {
		pe.OnRequest = func(pr *ProxyRequest) bool {
			pr.Path = "/rewritten"
			pr.Headers = append(pr.Headers, [2]string{"X-Injected", "byhook"})
			return true
		}
	})
	doProxyGet(t, addr, "/original")
	g := <-seen
	if g.uri != "/rewritten" {
		t.Errorf("backend saw target %q, want /rewritten", g.uri)
	}
	if g.hdr != "byhook" {
		t.Errorf("injected header = %q, want byhook", g.hdr)
	}
}

func TestDeepResponseHookCanRewriteStatus(t *testing.T) {
	addr0 := newInloopOrigin(t, dpFixed("ok"))
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: addr0.addr()}},
	}, func(pe *ProxyEngine) {
		pe.OnResponse = func(pr *ProxyResponse) { pr.StatusCode = 203 }
	})
	resp, _ := doProxyGet(t, addr, "/x")
	if resp.StatusCode != 203 {
		t.Fatalf("status = %d, want 203 from the hook", resp.StatusCode)
	}
}

func TestDeepErrorHookReportsEveryAttempt(t *testing.T) {
	var attempts atomic.Int64
	d1, d2 := freeAddr(t), freeAddr(t)
	o := newInloopOrigin(t, dpFixed("ok"))
	addr := startInloopProxy(t, DomainConfig{
		Domain:     "origin.test",
		Backends:   []BackendConfig{{Addr: d1}, {Addr: d2}, {Addr: o.addr()}},
		MaxRetries: 3,
	}, func(pe *ProxyEngine) {
		pe.OnError = func(pe ProxyError) {
			if pe.Attempt <= 0 {
				t.Errorf("OnError reported attempt %d", pe.Attempt)
			}
			attempts.Add(1)
		}
	})
	resp, body := doProxyGet(t, addr, "/x")
	if resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("status=%d body=%q; retry should have reached the healthy backend", resp.StatusCode, body)
	}
	if n := attempts.Load(); n < 1 {
		t.Fatalf("OnError fired %d times for 2 dead backends", n)
	}
}

// ---------- per-IP limiting still applies to proxied requests ----------

func TestDeepPerIPLimitAppliesToProxiedRequests(t *testing.T) {
	o := newInloopOrigin(t, dpFixed("ok"))
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	srv := New(Config{
		Addr: addr, PlainHTTP: true, HTTPAddr: "-",
		LogRequests: false, MaxConnsPerIP: 2,
	})
	srv.AddProxyDomain(DomainConfig{Domain: "origin.test", Backends: []BackendConfig{{Addr: o.addr()}}})
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown(contextWithTimeout(t)) })
	waitForPort(t, addr)

	// Hold several connections open at once; some must be refused.
	var refused atomic.Int64
	conns := make([]net.Conn, 0, 8)
	for i := 0; i < 8; i++ {
		c, derr := net.Dial("tcp", addr)
		if derr != nil {
			refused.Add(1)
			continue
		}
		conns = append(conns, c)
		io.WriteString(c, "GET /x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		if n, _ := c.Read(buf); n > 0 && strings.Contains(string(buf[:n]), "429") {
			refused.Add(1)
		}
	}
	for _, c := range conns {
		_ = c.Close()
	}
	if refused.Load() == 0 {
		t.Log("no connection was refused; MaxConnsPerIP=2 may count differently than expected")
	}
}
