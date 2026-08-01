//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// startCachingProxy brings up a proxy with a response cache configured.
func startCachingProxy(t *testing.T, cfg DomainConfig, cache ProxyCacheConfig, tune func(*ProxyEngine)) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := New(Config{
		Addr: addr, PlainHTTP: true, HTTPAddr: "-",
		LogRequests: false, MaxConnsPerIP: -1,
	})
	srv.AddProxyDomain(cfg)
	srv.SetProxyCache(cache)
	if tune != nil {
		tune(srv.proxy.Load())
	}
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, derr := net.DialTimeout("tcp", addr, 200*time.Millisecond); derr == nil {
			_ = c.Close()
			return addr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("caching proxy never came up")
	return ""
}

// cacheCountingOrigin serves a body and counts how many requests actually reached it.
func cacheCountingOrigin(t *testing.T, body string, hits *atomic.Int64) *inloopOrigin {
	return newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		hits.Add(1)
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s",
			len(body), body)
	})
}

// The whole point of the cache: a second identical request must be served
// without the backend being contacted again.
func TestInLoopProxyCacheServesSecondRequestFromCache(t *testing.T) {
	var hits atomic.Int64
	o := cacheCountingOrigin(t, "cached-payload", &hits)
	addr := startCachingProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, ProxyCacheConfig{
		Rules:         []CacheRule{{PathPrefix: "/", MaxAge: 30 * time.Second}},
		MaxEntrySize:  1 << 20,
		DefaultMaxAge: 30 * time.Second,
	}, nil)

	for i := 0; i < 5; i++ {
		resp, body := doProxyGet(t, addr, "/cacheable")
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: status = %d", i, resp.StatusCode)
		}
		if body != "cached-payload" {
			t.Fatalf("request %d: body = %q", i, body)
		}
	}

	if got := hits.Load(); got != 1 {
		t.Fatalf("backend was contacted %d times for 5 identical cacheable requests; want 1 — the cache is not storing or not being consulted", got)
	}
}

// Cache statistics must reflect the hits and misses.
func TestInLoopProxyCacheReportsStats(t *testing.T) {
	var hits atomic.Int64
	o := cacheCountingOrigin(t, "ok", &hits)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := New(Config{
		Addr: addr, PlainHTTP: true, HTTPAddr: "-",
		LogRequests: false, MaxConnsPerIP: -1,
	})
	srv.AddProxyDomain(DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	})
	srv.SetProxyCache(ProxyCacheConfig{
		Rules:         []CacheRule{{PathPrefix: "/", MaxAge: 30 * time.Second}},
		MaxEntrySize:  1 << 20,
		DefaultMaxAge: 30 * time.Second,
	})
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, derr := net.DialTimeout("tcp", addr, 200*time.Millisecond); derr == nil {
			_ = c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	for i := 0; i < 4; i++ {
		doProxyGet(t, addr, "/stats")
	}
	entries, _, cacheHits, misses := srv.ProxyCacheStats()
	if entries == 0 {
		t.Fatalf("cache holds %d entries after 4 cacheable requests", entries)
	}
	if cacheHits == 0 {
		t.Fatalf("cache reported %d hits and %d misses after 4 identical requests", cacheHits, misses)
	}
}

// A non-cacheable method must always reach the backend.
func TestInLoopProxyCacheSkipsNonCacheableMethods(t *testing.T) {
	var hits atomic.Int64
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		hits.Add(1)
		if req.ContentLength > 0 {
			io.CopyN(io.Discard, req.Body, req.ContentLength)
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := startCachingProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, ProxyCacheConfig{
		Rules:         []CacheRule{{PathPrefix: "/", MaxAge: 30 * time.Second}},
		MaxEntrySize:  1 << 20,
		DefaultMaxAge: 30 * time.Second,
	}, nil)

	client := &http.Client{Timeout: 10 * time.Second}
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("POST", "http://"+addr+"/write", nil)
		req.Host = "origin.test"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("post %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("backend saw %d of 3 POSTs; POSTs must never be served from cache", got)
	}
}

// A path outside the configured rules must not be cached.
func TestInLoopProxyCacheHonoursPathRules(t *testing.T) {
	var hits atomic.Int64
	o := cacheCountingOrigin(t, "ok", &hits)
	addr := startCachingProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, ProxyCacheConfig{
		Rules:         []CacheRule{{PathPrefix: "/static/", MaxAge: 30 * time.Second}},
		MaxEntrySize:  1 << 20,
		DefaultMaxAge: 30 * time.Second,
	}, nil)

	for i := 0; i < 3; i++ {
		doProxyGet(t, addr, "/dynamic/thing")
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("backend saw %d of 3 requests to an uncached path; want 3", got)
	}

	before := hits.Load()
	for i := 0; i < 3; i++ {
		doProxyGet(t, addr, "/static/thing")
	}
	if got := hits.Load() - before; got != 1 {
		t.Fatalf("backend saw %d of 3 requests to a cached path; want 1", got)
	}
}

// A cached response must keep its status, body and content type.
func TestInLoopProxyCachePreservesResponse(t *testing.T) {
	var hits atomic.Int64
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		hits.Add(1)
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Type: application/json\r\nX-Origin: yes\r\n\r\n{\"a\"}")
	})
	addr := startCachingProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, ProxyCacheConfig{
		Rules:         []CacheRule{{PathPrefix: "/", MaxAge: 30 * time.Second}},
		MaxEntrySize:  1 << 20,
		DefaultMaxAge: 30 * time.Second,
	}, nil)

	first, firstBody := doProxyGet(t, addr, "/json")
	second, secondBody := doProxyGet(t, addr, "/json")

	if hits.Load() != 1 {
		t.Fatalf("backend contacted %d times; the second request was not a cache hit", hits.Load())
	}
	if second.StatusCode != first.StatusCode {
		t.Errorf("cached status %d != live status %d", second.StatusCode, first.StatusCode)
	}
	if secondBody != firstBody {
		t.Errorf("cached body %q != live body %q", secondBody, firstBody)
	}
	if got := second.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("cached Content-Type = %q, want application/json", got)
	}
}

// DontCache is a documented public method; a response marked with it must not
// be served from cache afterwards.
func TestInLoopProxyCacheHonoursDontCache(t *testing.T) {
	var hits atomic.Int64
	o := cacheCountingOrigin(t, "secret", &hits)
	addr := startCachingProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, ProxyCacheConfig{
		Rules:         []CacheRule{{PathPrefix: "/", MaxAge: 30 * time.Second}},
		MaxEntrySize:  1 << 20,
		DefaultMaxAge: 30 * time.Second,
	}, func(pe *ProxyEngine) {
		pe.OnResponse = func(pr *ProxyResponse) { pr.DontCache() }
	})

	for i := 0; i < 3; i++ {
		doProxyGet(t, addr, "/private")
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("backend saw %d of 3 requests; DontCache() did not prevent caching", got)
	}
}

// A CDN's whole purpose is caching large static assets. The buffer/stream
// decision must therefore respect MaxEntrySize rather than a fixed threshold:
// before this was wired up, anything over 64 KiB streamed and was silently
// never cached, however large MaxEntrySize was set.
func TestInLoopProxyCacheStoresLargeObjects(t *testing.T) {
	for _, size := range []int{1 << 10, 60 << 10, 200 << 10, 2 << 20} {
		var hits atomic.Int64
		body := make([]byte, size)
		for i := range body {
			body[i] = byte('a' + i%26)
		}
		o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
			hits.Add(1)
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))
			conn.Write(body)
		})
		addr := startCachingProxy(t, DomainConfig{
			Domain:   "origin.test",
			Backends: []BackendConfig{{Addr: o.addr()}},
		}, ProxyCacheConfig{
			Rules:         []CacheRule{{PathPrefix: "/", MaxAge: 60 * time.Second}},
			MaxEntrySize:  16 << 20,
			MaxTotalBytes: 256 << 20,
			DefaultMaxAge: 60 * time.Second,
		}, nil)

		for i := 0; i < 3; i++ {
			resp, got := doProxyGet(t, addr, "/asset")
			if resp.StatusCode != 200 {
				t.Fatalf("size %d request %d: status = %d", size, i, resp.StatusCode)
			}
			if len(got) != size {
				t.Fatalf("size %d request %d: got %d bytes", size, i, len(got))
			}
		}
		if got := hits.Load(); got != 1 {
			t.Errorf("a %d byte object caused %d backend hits for 3 requests; want 1 (MaxEntrySize is 16 MiB)",
				size, got)
		}
	}
}

// An object larger than MaxEntrySize must still stream, so a huge asset cannot
// be pulled into memory just because caching is enabled.
func TestInLoopProxyStreamsObjectsAboveCacheLimit(t *testing.T) {
	const size = 4 << 20
	var hits atomic.Int64
	body := make([]byte, size)
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		hits.Add(1)
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))
		conn.Write(body)
	})
	addr := startCachingProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, ProxyCacheConfig{
		Rules:         []CacheRule{{PathPrefix: "/", MaxAge: 60 * time.Second}},
		MaxEntrySize:  256 << 10, // smaller than the object
		MaxTotalBytes: 64 << 20,
		DefaultMaxAge: 60 * time.Second,
	}, nil)

	for i := 0; i < 2; i++ {
		resp, got := doProxyGet(t, addr, "/huge")
		if resp.StatusCode != 200 || len(got) != size {
			t.Fatalf("request %d: status=%d len=%d", i, resp.StatusCode, len(got))
		}
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("an object above MaxEntrySize was cached (%d backend hits for 2 requests); it must stream instead", got)
	}
}
