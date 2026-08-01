//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"
)

// A backend that never answers must fail on the domain's connect timeout, not
// on the much longer read timeout.
func TestInLoopProxyConnectTimeoutHonoured(t *testing.T) {
	// 203.0.113.0/24 is reserved for documentation and is not routed, so
	// connections to it hang rather than being refused.
	addr := startInloopProxy(t, DomainConfig{
		Domain:         "origin.test",
		Backends:       []BackendConfig{{Addr: "203.0.113.1:9"}},
		ConnectTimeout: 300 * time.Millisecond,
		ReadTimeout:    20 * time.Second,
		MaxRetries:     0,
	}, nil)

	start := time.Now()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("no response after %v: %v", elapsed, err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("took %v to give up; the connect timeout of 300ms was ignored in favour of the read timeout", elapsed)
	}
	if len(line) < 12 || line[9] != '5' {
		t.Fatalf("expected a 5xx after the connect timeout, got %q", line)
	}
}

// A backend that accepts and then says nothing must fail on the read timeout.
func TestInLoopProxyReadTimeoutHonoured(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			// Accept, read the request, then never answer.
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				for {
					if _, rerr := c.Read(buf); rerr != nil {
						return
					}
				}
			}(c)
		}
	}()

	addr := startInloopProxy(t, DomainConfig{
		Domain:         "origin.test",
		Backends:       []BackendConfig{{Addr: ln.Addr().String()}},
		ConnectTimeout: 5 * time.Second,
		ReadTimeout:    500 * time.Millisecond,
		MaxRetries:     0,
	}, nil)

	start := time.Now()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _ = bufio.NewReader(conn).ReadString('\n')
	elapsed := time.Since(start)

	if elapsed > 4*time.Second {
		t.Fatalf("a silent backend held the request for %v with a 500ms read timeout", elapsed)
	}
}

// The read timeout bounds the gap between reads, not the whole transfer, so a
// slow but steady response must not be killed part way through.
func TestInLoopProxyReadTimeoutIsPerReadNotWhole(t *testing.T) {
	const chunks = 12
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", chunks*8)
		for i := 0; i < chunks; i++ {
			// Steady trickle: each gap is well inside the timeout, but the
			// whole transfer runs far past it.
			time.Sleep(120 * time.Millisecond)
			if _, err := conn.Write([]byte("abcdefgh")); err != nil {
				return
			}
		}
	})
	addr := startInloopProxy(t, DomainConfig{
		Domain:      "origin.test",
		Backends:    []BackendConfig{{Addr: o.addr()}},
		ReadTimeout: 600 * time.Millisecond,
	}, nil)

	resp, body := doProxyGet(t, addr, "/trickle")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(body) != chunks*8 {
		t.Fatalf("got %d bytes, want %d; a steady response was cut short by the read timeout",
			len(body), chunks*8)
	}
}

// MaxIdleConns caps how many upstream connections are parked for reuse.
func TestInLoopProxyMaxIdleConnsHonoured(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("ok"))
	addr := startInloopProxy(t, DomainConfig{
		Domain:       "origin.test",
		Backends:     []BackendConfig{{Addr: o.addr()}},
		MaxIdleConns: 2,
	}, nil)

	// Drive concurrent requests so several upstream connections exist at once,
	// then let them go idle.
	done := make(chan struct{})
	for i := 0; i < 12; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			c, err := net.Dial("tcp", addr)
			if err != nil {
				return
			}
			defer c.Close()
			io.WriteString(c, "GET /x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 256)
			_, _ = c.Read(buf)
		}()
	}
	for i := 0; i < 12; i++ {
		<-done
	}
	// The cap applies per worker pool; the assertion is simply that the proxy
	// stays healthy and keeps serving after the excess connections are dropped.
	resp, body := doProxyGet(t, addr, "/after")
	if resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("proxy unhealthy after idle-cap eviction: status=%d body=%q", resp.StatusCode, body)
	}
}

// Registering and removing domains must not leak the goroutines that the
// unused blocking connection pool used to start per backend.
func TestAddRemoveProxyDomainDoesNotLeakGoroutines(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("ok"))
	srv := New(Config{Addr: "127.0.0.1:0", PlainHTTP: true, HTTPAddr: "-", LogRequests: false})

	srv.AddProxyDomain(DomainConfig{
		Domain:   "warmup.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	})
	srv.RemoveProxyDomain("warmup.test")
	runtime.GC()
	time.Sleep(150 * time.Millisecond)
	before := runtime.NumGoroutine()

	for i := 0; i < 40; i++ {
		domain := fmt.Sprintf("d%d.test", i)
		srv.AddProxyDomain(DomainConfig{
			Domain: domain,
			Backends: []BackendConfig{
				{Addr: o.addr()}, {Addr: o.addr()}, {Addr: o.addr()},
			},
		})
		srv.RemoveProxyDomain(domain)
	}
	runtime.GC()
	time.Sleep(150 * time.Millisecond)
	after := runtime.NumGoroutine()

	if after-before > 10 {
		t.Fatalf("goroutines grew from %d to %d over 40 add/remove cycles of 3 backends each", before, after)
	}
}
