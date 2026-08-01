//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// inloopOrigin is a minimal HTTP/1.1 upstream whose behaviour each test drives
// directly, so the proxy is exercised against exact bytes rather than through
// another server's abstractions.
type inloopOrigin struct {
	ln       net.Listener
	accepted atomic.Int64
	handler  func(req *http.Request, conn net.Conn, br *bufio.Reader)
}

func newInloopOrigin(t *testing.T, handler func(req *http.Request, conn net.Conn, br *bufio.Reader)) *inloopOrigin {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	o := &inloopOrigin{ln: ln, handler: handler}
	go o.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return o
}

func (o *inloopOrigin) serve() {
	for {
		conn, err := o.ln.Accept()
		if err != nil {
			return
		}
		o.accepted.Add(1)
		go func(c net.Conn) {
			defer c.Close()
			br := bufio.NewReader(c)
			for {
				req, rerr := http.ReadRequest(br)
				if rerr != nil {
					return
				}
				o.handler(req, c, br)
			}
		}(conn)
	}
}

func (o *inloopOrigin) addr() string { return o.ln.Addr().String() }

// startInloopProxy brings up a proxy server on the epoll path for one domain.
func startInloopProxy(t *testing.T, cfg DomainConfig, tune func(*ProxyEngine)) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := New(Config{
		Addr:          addr,
		PlainHTTP:     true,
		HTTPAddr:      "-",
		LogRequests:   false,
		MaxConnsPerIP: -1,
	})
	srv.AddProxyDomain(cfg)
	if tune != nil {
		tune(srv.proxy.Load())
	}
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() {
		// Shutdown blocks until the context is done, so it must be bounded.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if derr == nil {
			_ = c.Close()
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("proxy never came up")
	return ""
}

func echoBodyOrigin(body string) func(*http.Request, net.Conn, *bufio.Reader) {
	return func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		if req.ContentLength > 0 {
			_, _ = io.CopyN(io.Discard, req.Body, req.ContentLength)
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s",
			len(body), body)
	}
}

func doProxyGet(t *testing.T, addr, path string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest("GET", "http://"+addr+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = "origin.test"
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

func TestInLoopProxyBasicGet(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("hello from origin"))
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	resp, body := doProxyGet(t, addr, "/hello")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body != "hello from origin" {
		t.Fatalf("body = %q", body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
}

// The whole point of the in-loop path is that the upstream connection is
// pooled, so many client requests must not open many backend connections.
func TestInLoopProxyReusesBackendConnection(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("ok"))
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	client := &http.Client{Timeout: 10 * time.Second}
	for i := 0; i < 50; i++ {
		req, _ := http.NewRequest("GET", "http://"+addr+"/x", nil)
		req.Host = "origin.test"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if got := o.accepted.Load(); got > 4 {
		t.Fatalf("origin accepted %d connections for 50 requests; pooling is not working", got)
	}
}

func TestInLoopProxyPostBodyReachesOrigin(t *testing.T) {
	var seen atomic.Value
	seen.Store("")
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, req.ContentLength))
		seen.Store(string(b))
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	req, _ := http.NewRequest("POST", "http://"+addr+"/submit", strings.NewReader("payload-1234"))
	req.Host = "origin.test"
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if got := seen.Load().(string); got != "payload-1234" {
		t.Fatalf("origin saw body %q, want %q", got, "payload-1234")
	}
}

// Bodies above the buffered limit are relayed as they arrive rather than
// collected, and must still arrive intact and in order.
func TestInLoopProxyStreamsLargeResponse(t *testing.T) {
	const size = 4 << 20
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size)
		chunk := make([]byte, 4096)
		for i := range chunk {
			chunk[i] = byte('a' + i%26)
		}
		for written := 0; written < size; written += len(chunk) {
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	resp, body := doProxyGet(t, addr, "/big")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(body) != size {
		t.Fatalf("body length = %d, want %d", len(body), size)
	}
	for i := 0; i < len(body); i++ {
		if body[i] != byte('a'+(i%4096)%26) {
			t.Fatalf("body corrupted at offset %d", i)
		}
	}
}

// Relaying a chunk flushes the client, and a client that drains wants to resume
// the backend read -- which used to re-enter the response parser while it was
// still running, complete the exchange underneath the outer frame and crash on
// the now-nil current exchange. A slow reader forces that pause/resume cycle
// many times over.
func TestInLoopProxySlowClientDoesNotReenterParser(t *testing.T) {
	const size = 8 << 20
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size)
		chunk := make([]byte, 32<<10)
		for i := range chunk {
			chunk[i] = byte('a' + i%26)
		}
		for written := 0; written < size; written += len(chunk) {
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /slow HTTP/1.1\r\nHost: origin.test\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read in small bites with pauses so the proxy's write buffer repeatedly
	// crosses the high-water mark and drains back below the low-water mark.
	br := bufio.NewReaderSize(conn, 4096)
	head, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.HasPrefix(head, "HTTP/1.1 200") {
		t.Fatalf("status line = %q", head)
	}
	for {
		line, lerr := br.ReadString('\n')
		if lerr != nil {
			t.Fatalf("read headers: %v", lerr)
		}
		if line == "\r\n" {
			break
		}
	}

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	buf := make([]byte, 8192)
	total := 0
	for total < size {
		n, rerr := br.Read(buf)
		if n > 0 {
			for i := 0; i < n; i++ {
				if buf[i] != byte('a'+((total+i)%(32<<10))%26) {
					t.Fatalf("body corrupted at offset %d", total+i)
				}
			}
			total += n
		}
		if rerr != nil {
			t.Fatalf("read body at %d/%d: %v", total, size, rerr)
		}
		if total%(1<<20) < 8192 {
			time.Sleep(1 * time.Millisecond)
		}
	}
	if total != size {
		t.Fatalf("received %d bytes, want %d", total, size)
	}
}

// Backpressure means the proxy stops pulling from the backend when the client
// stops reading. Measuring how far the origin gets tests that property
// directly: without it the origin would drain its whole body into the proxy.
func TestInLoopProxyStopsReadingBackendForStalledClient(t *testing.T) {
	const size = 128 << 20
	var written atomic.Int64
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size)
		chunk := make([]byte, 64<<10)
		for sent := 0; sent < size; sent += len(chunk) {
			n, err := conn.Write(chunk)
			if n > 0 {
				written.Add(int64(n))
			}
			if err != nil {
				return
			}
		}
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /huge HTTP/1.1\r\nHost: origin.test\r\n\r\n")

	// Read nothing at all and let the relay stall.
	time.Sleep(600 * time.Millisecond)
	stalled := written.Load()

	// Socket buffers on both hops plus the proxy's own high-water mark account
	// for a few MiB; anything near the full body means it never stopped.
	const ceiling = 24 << 20
	if stalled > ceiling {
		t.Fatalf("origin pushed %d MiB into the proxy while the client read nothing (ceiling %d MiB); backpressure is not holding",
			stalled>>20, ceiling>>20)
	}

	// Draining must let it continue, proving the pause is released and not a
	// permanent stall.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.CopyN(io.Discard, conn, 32<<20); err != nil {
		t.Fatalf("relay did not resume after the client drained: %v", err)
	}
	if written.Load() <= stalled {
		t.Fatal("the origin made no further progress after the client resumed reading")
	}
}

// A response of unknown length must be re-framed so the client can find the end.
func TestInLoopProxyChunkedResponse(t *testing.T) {
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
		io.WriteString(conn, "5\r\nhello\r\n")
		io.WriteString(conn, "6\r\n world\r\n")
		io.WriteString(conn, "0\r\n\r\n")
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	resp, body := doProxyGet(t, addr, "/chunked")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if body != "hello world" {
		t.Fatalf("body = %q, want %q", body, "hello world")
	}
}

// The inbound parser splits headers on CRLF, so a raw request can never carry
// an embedded CRLF in a value. The realistic source is an OnRequest hook, which
// hands back arbitrary header names, values and a request target. None of it
// may be allowed to forge extra headers upstream.
func TestAppendProxyRequestDropsCRLFBearingFields(t *testing.T) {
	req := &Request{
		Method:  "GET",
		Path:    "/safe",
		RawPath: "/safe",
		Headers: [][2]string{
			{"X-Good", "fine"},
			{"X-Evil", "a\r\nX-Injected: 1"},
			{"X-Evil-Name\r\nX-Also-Injected: 1", "v"},
		},
	}
	out := string(appendProxyRequest(nil, req, "origin.test", "1.2.3.4"))

	if strings.Contains(out, "X-Injected") || strings.Contains(out, "X-Also-Injected") {
		t.Fatalf("CRLF in a header field forged an upstream header:\n%s", out)
	}
	if !strings.Contains(out, "X-Good: fine\r\n") {
		t.Errorf("a clean header was dropped:\n%s", out)
	}
	if strings.Count(out, "\r\n\r\n") != 1 {
		t.Errorf("request head is malformed:\n%s", out)
	}
}

func TestAppendProxyRequestSanitisesTargetAndHost(t *testing.T) {
	req := &Request{
		Method:  "GET",
		Path:    "/x",
		RawPath: "/x HTTP/1.1\r\nX-Injected: 1",
	}
	out := string(appendProxyRequest(nil, req, "origin.test", ""))
	if strings.Contains(out, "X-Injected") {
		t.Fatalf("CRLF in the request target forged a header:\n%s", out)
	}
	if !strings.HasPrefix(out, "GET / HTTP/1.1\r\n") {
		t.Errorf("a poisoned target should fall back to /, got:\n%s", out)
	}

	req = &Request{Method: "GET", Path: "/x", RawPath: "/x"}
	out = string(appendProxyRequest(nil, req, "evil\r\nX-Injected: 1", ""))
	if strings.Contains(out, "X-Injected") {
		t.Fatalf("CRLF in the Host header forged a header:\n%s", out)
	}
}

// An OnRequest hook is the one place a CRLF-bearing value can realistically
// enter, so the end-to-end path is checked as well.
func TestInLoopProxyHookCannotInjectUpstreamHeader(t *testing.T) {
	var sawInjected atomic.Bool
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		if req.Header.Get("X-Injected") != "" {
			sawInjected.Store(true)
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, func(pe *ProxyEngine) {
		pe.OnRequest = func(pr *ProxyRequest) bool {
			pr.Headers = append(pr.Headers, [2]string{"X-Evil", "a\r\nX-Injected: 1"})
			return true
		}
	})

	resp, _ := doProxyGet(t, addr, "/x")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if sawInjected.Load() {
		t.Fatal("a hook-supplied CRLF value forged a header upstream")
	}
}

// The client's connection preference is its own; relaying "close" upstream
// would retire a pooled backend connection on every request.
func TestInLoopProxyDoesNotRelayConnectionClose(t *testing.T) {
	var upstreamConnHeader atomic.Value
	upstreamConnHeader.Store("")
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		upstreamConnHeader.Store(req.Header.Get("Connection"))
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /x HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	io.ReadAll(conn)

	if got := upstreamConnHeader.Load().(string); strings.EqualFold(got, "close") {
		t.Fatalf("origin saw Connection: %q; the client's close must not be relayed", got)
	}
}

// OnResponse previously fired only for cache hits, so a live upstream response
// could not be observed or rewritten.
func TestInLoopProxyOnResponseFiresForLiveResponse(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("original"))
	var fired atomic.Bool
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, func(pe *ProxyEngine) {
		pe.OnResponse = func(pr *ProxyResponse) {
			fired.Store(true)
			pr.Headers = append(pr.Headers, [2]string{"X-Added-By-Hook", "yes"})
		}
	})

	resp, _ := doProxyGet(t, addr, "/hooked")
	if !fired.Load() {
		t.Fatal("OnResponse did not fire for a live upstream response")
	}
	if got := resp.Header.Get("X-Added-By-Hook"); got != "yes" {
		t.Fatalf("header added by OnResponse did not reach the client (got %q)", got)
	}
}

// An escaped path segment must survive the hop unchanged.
func TestInLoopProxyPreservesRawPath(t *testing.T) {
	var seenTarget atomic.Value
	seenTarget.Store("")
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		seenTarget.Store(req.RequestURI)
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /a%2Fb?x=1 HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = bufio.NewReader(conn).ReadString('\n')

	if got := seenTarget.Load().(string); got != "/a%2Fb?x=1" {
		t.Fatalf("origin saw target %q, want %q", got, "/a%2Fb?x=1")
	}
}

// A backend that refuses the connection must be retried against a healthy one.
func TestInLoopProxyRetriesFailedBackend(t *testing.T) {
	dead, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := dead.Addr().String()
	dead.Close() // nothing is listening now, so connects are refused

	o := newInloopOrigin(t, echoBodyOrigin("from healthy"))
	var errCount atomic.Int64
	addr := startInloopProxy(t, DomainConfig{
		Domain:     "origin.test",
		Backends:   []BackendConfig{{Addr: deadAddr}, {Addr: o.addr()}},
		MaxRetries: 2,
	}, func(pe *ProxyEngine) {
		pe.OnError = func(ProxyError) { errCount.Add(1) }
	})

	resp, body := doProxyGet(t, addr, "/retry")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body != "from healthy" {
		t.Fatalf("body = %q", body)
	}
	if errCount.Load() == 0 {
		t.Error("OnError should have fired for the refused backend")
	}
}

// contextWithTimeout returns a bounded shutdown context; Shutdown blocks until
// its context is done, so an unbounded one hangs the test binary.
func contextWithTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// waitForPort blocks until addr accepts connections.
func waitForPort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never accepted connections", addr)
}

// contextWithCancel is the non-testing.T variant used by benchmarks.
func contextWithCancel() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 2*time.Second)
}
