//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- backend misbehaviour ----------

func TestDeepBackendClosesBeforeResponding(t *testing.T) {
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		conn.Close()
	})
	resp, _ := doProxyGet(t, addr, "/x")
	if resp.StatusCode < 500 {
		t.Fatalf("status = %d, want a 5xx when the backend hangs up", resp.StatusCode)
	}
}

func TestDeepBackendSendsGarbage(t *testing.T) {
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		io.WriteString(conn, "this is not http at all\r\n\r\n")
	})
	resp, _ := doProxyGet(t, addr, "/x")
	if resp.StatusCode < 500 {
		t.Fatalf("status = %d, want a 5xx for a malformed upstream response", resp.StatusCode)
	}
}

// A backend that dies mid-body must end the client's connection promptly. The
// client legitimately sees a truncated response, so this reads raw bytes rather
// than going through a helper that treats a short read as a fatal error.
func TestDeepBackendSendsHeadersThenDies(t *testing.T) {
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial")
		conn.Close()
	})

	done := make(chan int, 1)
	go func() {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			done <- -1
			return
		}
		defer c.Close()
		io.WriteString(c, "GET /x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
		c.SetReadDeadline(time.Now().Add(8 * time.Second))
		out, _ := io.ReadAll(c)
		done <- len(out)
	}()

	select {
	case n := <-done:
		if n <= 0 {
			t.Fatalf("client received %d bytes from a backend that died mid-body", n)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("a backend that died mid-body hung the request")
	}
}

// A backend that declares far more than it sends must fail promptly rather than
// hang. The client legitimately sees a truncated response: the missing bytes
// must not be invented, so a read error here is the correct outcome.
func TestDeepBackendSendsOversizedBody(t *testing.T) {
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\nshort")
		conn.Close()
	})

	done := make(chan int, 1)
	go func() {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			done <- -1
			return
		}
		defer c.Close()
		io.WriteString(c, "GET /x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		out, _ := io.ReadAll(c)
		done <- len(out)
	}()

	select {
	case n := <-done:
		if n <= 0 {
			t.Fatalf("client received %d bytes for an over-declared response", n)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("an over-declared Content-Length hung the request")
	}
}

func TestDeepBackendSlowHeadersStillCompletes(t *testing.T) {
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		io.WriteString(conn, "HTTP/1.1 ")
		time.Sleep(60 * time.Millisecond)
		io.WriteString(conn, "200 OK\r\nContent-Le")
		time.Sleep(60 * time.Millisecond)
		io.WriteString(conn, "ngth: 5\r\n\r\ndrip!")
	})
	resp, body := doProxyGet(t, addr, "/x")
	if resp.StatusCode != 200 || body != "drip!" {
		t.Fatalf("status=%d body=%q for a byte-dribbled response head", resp.StatusCode, body)
	}
}

func TestDeepBackendRepeatedFailuresDoNotWedgeProxy(t *testing.T) {
	var n atomic.Int64
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		if n.Add(1) <= 10 {
			conn.Close()
			return
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nalive")
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	for i := 0; i < 10; i++ {
		doProxyGet(t, addr, "/fail")
	}
	// After a run of failures the proxy must still serve normally.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resp, body := doProxyGet(t, addr, "/ok"); resp.StatusCode == 200 && body == "alive" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the proxy never recovered after a run of backend failures")
}

// ---------- client misbehaviour ----------

func TestDeepClientDisconnectsMidStream(t *testing.T) {
	const size = 32 << 20
	var served atomic.Int64
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		served.Add(1)
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size)
		chunk := make([]byte, 64<<10)
		for w := 0; w < size; w += len(chunk) {
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	for i := 0; i < 10; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		io.WriteString(conn, "GET /big HTTP/1.1\r\nHost: origin.test\r\n\r\n")
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(buf)
		_ = conn.Close() // abandon mid-stream
	}

	// The proxy must still serve after ten abandoned streams.
	small := newInloopOrigin(t, dpFixed("fine"))
	addr2 := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: small.addr()}},
	}, nil)
	if resp, body := doProxyGet(t, addr2, "/x"); resp.StatusCode != 200 || body != "fine" {
		t.Fatalf("proxy unhealthy after abandoned streams: status=%d body=%q", resp.StatusCode, body)
	}
}

func TestDeepClientSendsPartialRequestThenLeaves(t *testing.T) {
	addr := dpProxy(t, dpFixed("ok"))
	for i := 0; i < 20; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		io.WriteString(conn, "GET /partial HTTP/1.1\r\nHost: origin")
		_ = conn.Close()
	}
	if resp, body := doProxyGet(t, addr, "/x"); resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("proxy unhealthy after truncated requests: status=%d body=%q", resp.StatusCode, body)
	}
}

func TestDeepClientOpensAndClosesWithoutRequest(t *testing.T) {
	addr := dpProxy(t, dpFixed("ok"))
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			_ = c.Close()
		}
	}
	if resp, body := doProxyGet(t, addr, "/x"); resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("proxy unhealthy after bare connects: status=%d body=%q", resp.StatusCode, body)
	}
}

// ---------- concurrency ----------

func TestDeepConcurrentRequestsAllSucceed(t *testing.T) {
	addr := dpProxy(t, dpFixed("concurrent"))
	var wg sync.WaitGroup
	var fails atomic.Int64
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "http://"+addr+"/c", nil)
			req.Host = "origin.test"
			resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
			if err != nil {
				fails.Add(1)
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(b) != "concurrent" {
				fails.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := fails.Load(); n != 0 {
		t.Fatalf("%d of 200 concurrent requests failed", n)
	}
}

func TestDeepConcurrentMixedSizes(t *testing.T) {
	sizes := []int{64, 4096, 100 << 10, 1 << 20}
	origins := make([]string, len(sizes))
	for i, s := range sizes {
		body := strings.Repeat("x", s)
		origins[i] = newInloopOrigin(t, dpFixed(body)).addr()
	}
	addrs := make([]string, len(sizes))
	for i := range sizes {
		addrs[i] = startInloopProxy(t, DomainConfig{
			Domain:   "origin.test",
			Backends: []BackendConfig{{Addr: origins[i]}},
		}, nil)
	}

	var wg sync.WaitGroup
	var fails atomic.Int64
	for round := 0; round < 25; round++ {
		for i, want := range sizes {
			wg.Add(1)
			go func(addr string, want int) {
				defer wg.Done()
				req, _ := http.NewRequest("GET", "http://"+addr+"/m", nil)
				req.Host = "origin.test"
				resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
				if err != nil {
					fails.Add(1)
					return
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if len(b) != want {
					fails.Add(1)
				}
			}(addrs[i], want)
		}
	}
	wg.Wait()
	if n := fails.Load(); n != 0 {
		t.Fatalf("%d of 100 mixed-size concurrent requests failed", n)
	}
}

func TestDeepConcurrentAcrossManyDomains(t *testing.T) {
	const domains = 12
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	srv := New(Config{Addr: addr, PlainHTTP: true, HTTPAddr: "-", LogRequests: false, MaxConnsPerIP: -1})
	for i := 0; i < domains; i++ {
		body := fmt.Sprintf("domain-%d", i)
		o := newInloopOrigin(t, dpFixed(body))
		srv.AddProxyDomain(DomainConfig{
			Domain:   fmt.Sprintf("d%d.test", i),
			Backends: []BackendConfig{{Addr: o.addr()}},
		})
	}
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown(contextWithTimeout(t)) })
	waitForPort(t, addr)

	var wg sync.WaitGroup
	var fails atomic.Int64
	for r := 0; r < 10; r++ {
		for i := 0; i < domains; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				req, _ := http.NewRequest("GET", "http://"+addr+"/x", nil)
				req.Host = fmt.Sprintf("d%d.test", i)
				resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
				if err != nil {
					fails.Add(1)
					return
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if string(b) != fmt.Sprintf("domain-%d", i) {
					fails.Add(1)
				}
			}(i)
		}
	}
	wg.Wait()
	if n := fails.Load(); n != 0 {
		t.Fatalf("%d of %d cross-domain requests were wrong or failed", n, 10*domains)
	}
}

// ---------- leaks ----------

func TestDeepNoGoroutineGrowthUnderLoad(t *testing.T) {
	addr := dpProxy(t, dpFixed("leak-check"))
	client := &http.Client{Timeout: 10 * time.Second}
	do := func(n int) {
		for i := 0; i < n; i++ {
			req, _ := http.NewRequest("GET", "http://"+addr+"/g", nil)
			req.Host = "origin.test"
			if resp, err := client.Do(req); err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}
	do(50)
	runtime.GC()
	time.Sleep(150 * time.Millisecond)
	before := runtime.NumGoroutine()

	do(500)
	runtime.GC()
	time.Sleep(150 * time.Millisecond)
	after := runtime.NumGoroutine()

	if after-before > 25 {
		t.Fatalf("500 proxied requests grew goroutines from %d to %d", before, after)
	}
}

func TestDeepConnectionChurnDoesNotLeak(t *testing.T) {
	addr := dpProxy(t, dpFixed("churn"))
	runtime.GC()
	time.Sleep(150 * time.Millisecond)
	before := runtime.NumGoroutine()

	for i := 0; i < 300; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		io.WriteString(conn, "GET /x HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n")
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		io.ReadAll(conn)
		conn.Close()
	}
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after-before > 25 {
		t.Fatalf("300 connection open/close cycles grew goroutines from %d to %d", before, after)
	}
}

// ---------- pool behaviour ----------

func TestDeepPoolIsolatedPerOrigin(t *testing.T) {
	var a, b atomic.Int64
	oa := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		a.Add(1)
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA")
	})
	ob := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		b.Add(1)
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB")
	})
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	srv := New(Config{Addr: addr, PlainHTTP: true, HTTPAddr: "-", LogRequests: false, MaxConnsPerIP: -1})
	srv.AddProxyDomain(DomainConfig{Domain: "a.test", Backends: []BackendConfig{{Addr: oa.addr()}}})
	srv.AddProxyDomain(DomainConfig{Domain: "b.test", Backends: []BackendConfig{{Addr: ob.addr()}}})
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown(contextWithTimeout(t)) })
	waitForPort(t, addr)

	client := &http.Client{Timeout: 10 * time.Second}
	for i := 0; i < 20; i++ {
		for _, host := range []string{"a.test", "b.test"} {
			req, _ := http.NewRequest("GET", "http://"+addr+"/x", nil)
			req.Host = host
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("%s request %d: %v", host, i, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			want := strings.ToUpper(host[:1])
			if string(body) != want {
				t.Fatalf("host %s returned %q, want %q — origins are crossed", host, body, want)
			}
		}
	}
	if a.Load() == 0 || b.Load() == 0 {
		t.Fatalf("one origin never received traffic: a=%d b=%d", a.Load(), b.Load())
	}
}

func TestDeepPoolSurvivesIdlePeriod(t *testing.T) {
	o := newInloopOrigin(t, dpFixed("still-here"))
	addr := startInloopProxy(t, DomainConfig{
		Domain:      "origin.test",
		Backends:    []BackendConfig{{Addr: o.addr()}},
		IdleTimeout: 5 * time.Second,
	}, nil)

	if resp, body := doProxyGet(t, addr, "/1"); resp.StatusCode != 200 || body != "still-here" {
		t.Fatalf("first request failed: %d %q", resp.StatusCode, body)
	}
	time.Sleep(400 * time.Millisecond) // well inside IdleTimeout
	if resp, body := doProxyGet(t, addr, "/2"); resp.StatusCode != 200 || body != "still-here" {
		t.Fatalf("request after an idle gap failed: %d %q", resp.StatusCode, body)
	}
}

func TestDeepPoolRecoversAfterBackendRestart(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	backendAddr := ln.Addr().String()
	serve := func(l net.Listener) {
		for {
			c, aerr := l.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					if _, rerr := http.ReadRequest(br); rerr != nil {
						return
					}
					io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				}
			}(c)
		}
	}
	go serve(ln)
	addr := startInloopProxy(t, DomainConfig{
		Domain:     "origin.test",
		Backends:   []BackendConfig{{Addr: backendAddr}},
		MaxRetries: 2,
	}, nil)

	if resp, _ := doProxyGet(t, addr, "/before"); resp.StatusCode != 200 {
		t.Fatalf("pre-restart request failed: %d", resp.StatusCode)
	}
	_ = ln.Close()
	time.Sleep(150 * time.Millisecond)

	revived, err := net.Listen("tcp4", backendAddr)
	if err != nil {
		t.Skipf("could not rebind %s: %v", backendAddr, err)
	}
	defer revived.Close()
	go serve(revived)

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if resp, _ := doProxyGet(t, addr, "/after"); resp.StatusCode == 200 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the proxy never recovered after the backend restarted on the same port")
}
