//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// startInloopTLSProxy brings up a TLS-terminating proxy for one domain, using a
// self-signed certificate generated for that domain.
func startInloopTLSProxy(t *testing.T, cfg DomainConfig, tune func(*ProxyEngine)) string {
	return startInloopTLSProxyMulti(t, []DomainConfig{cfg}, tune)
}

// startInloopTLSProxyMulti serves several proxy domains from one server, so
// tests can observe whether traffic for one domain interferes with another on
// the workers they share.
func startInloopTLSProxyMulti(t *testing.T, cfgs []DomainConfig, tune func(*ProxyEngine)) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	certs := make([]CertConfig, 0, len(cfgs))
	for _, cfg := range cfgs {
		certs = append(certs, CertConfig{Domain: cfg.Domain, Source: CertSelfSigned})
	}
	srv := New(Config{
		Addr:          addr,
		HTTPAddr:      "-",
		LogRequests:   false,
		MaxConnsPerIP: -1,
		Certs:         certs,
	})
	for _, cfg := range cfgs {
		srv.AddProxyDomain(cfg)
	}
	if tune != nil {
		tune(srv.proxy.Load())
	}
	go func() { _ = srv.ListenAndServeTLS() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := tls.DialWithDialer(
			&net.Dialer{Timeout: 200 * time.Millisecond}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true, ServerName: cfgs[0].Domain},
		)
		if derr == nil {
			_ = c.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("TLS proxy never came up")
	return ""
}

func tlsProxyClient(domain string) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: domain},
			ForceAttemptHTTP2: false,
		},
	}
}

// TLS-terminated proxying must produce the same bytes as the plaintext path.
func TestInLoopProxyOverTLS(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("hello over tls"))
	addr := startInloopTLSProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	client := tlsProxyClient("origin.test")
	req, _ := http.NewRequest("GET", "https://"+addr+"/hello", nil)
	req.Host = "origin.test"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("tls proxy request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "hello over tls" {
		t.Fatalf("body = %q", string(body))
	}
}

// Keep-alive must survive TLS proxying, and the upstream pool must be reused.
func TestInLoopProxyOverTLSKeepAlive(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("ok"))
	addr := startInloopTLSProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	client := tlsProxyClient("origin.test")
	for i := 0; i < 30; i++ {
		req, _ := http.NewRequest("GET", "https://"+addr+"/x", nil)
		req.Host = "origin.test"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if got := o.accepted.Load(); got > 4 {
		t.Fatalf("origin accepted %d connections for 30 TLS requests; pooling is not working", got)
	}
}

// A response larger than the buffered limit is relayed and sealed in pieces, so
// it exercises the streaming path through the record layer.
func TestInLoopProxyOverTLSStreamsLargeResponse(t *testing.T) {
	const size = 3 << 20
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size)
		chunk := make([]byte, 8192)
		for i := range chunk {
			chunk[i] = byte('a' + i%26)
		}
		for written := 0; written < size; written += len(chunk) {
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	})
	addr := startInloopTLSProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	client := tlsProxyClient("origin.test")
	req, _ := http.NewRequest("GET", "https://"+addr+"/big", nil)
	req.Host = "origin.test"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("tls request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) != size {
		t.Fatalf("body length = %d, want %d", len(body), size)
	}
	for i := 0; i < len(body); i++ {
		if body[i] != byte('a'+(i%8192)%26) {
			t.Fatalf("body corrupted at offset %d", i)
		}
	}
}

// The old TLS path called dispatch synchronously and blocked the worker on the
// backend, so one slow upstream stalled every other TLS connection that worker
// owned. Requests against a slow backend must no longer hold up a fast one.
func TestInLoopProxyOverTLSSlowBackendDoesNotBlockOthers(t *testing.T) {
	slow := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		time.Sleep(300 * time.Millisecond)
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow")
	})
	fast := newInloopOrigin(t, echoBodyOrigin("fast"))

	// Both domains are served by one server so they share the same workers;
	// separate servers could not block each other regardless of the fix.
	addr := startInloopTLSProxyMulti(t, []DomainConfig{
		{Domain: "slow.test", Backends: []BackendConfig{{Addr: slow.addr()}}},
		{Domain: "fast.test", Backends: []BackendConfig{{Addr: fast.addr()}}},
	}, nil)
	slowAddr, fastAddr := addr, addr

	// Saturate the slow proxy so every worker has a stalled exchange in flight.
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := tlsProxyClient("slow.test")
			req, _ := http.NewRequest("GET", "https://"+slowAddr+"/s", nil)
			req.Host = "slow.test"
			resp, err := c.Do(req)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
	time.Sleep(150 * time.Millisecond)

	// A request to the fast proxy must complete well inside the slow backend's
	// delay rather than queueing behind it.
	var slowest time.Duration
	for i := 0; i < 5; i++ {
		c := tlsProxyClient("fast.test")
		req, _ := http.NewRequest("GET", "https://"+fastAddr+"/f", nil)
		req.Host = "fast.test"
		start := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("fast request %d failed while a slow backend was busy: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "fast" {
			t.Fatalf("fast body = %q", string(body))
		}
		if d := time.Since(start); d > slowest {
			slowest = d
		}
	}
	if slowest > 200*time.Millisecond {
		t.Fatalf("a fast TLS request took %v while a slow backend was in flight; the worker is still being blocked", slowest)
	}
}
