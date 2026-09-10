//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func privacyCacheConfig() ProxyCacheConfig {
	return ProxyCacheConfig{
		Rules:         []CacheRule{{PathPrefix: "/", MaxAge: 30 * time.Second}},
		MaxEntrySize:  1 << 20,
		DefaultMaxAge: 30 * time.Second,
	}
}

func doProxyGetWithHeader(t *testing.T, addr, path, name, value string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest("GET", "http://"+addr+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = "origin.test"
	if name != "" {
		req.Header.Set(name, value)
	}
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

func perUserOrigin(t *testing.T, hits *atomic.Int64, extraHeader string) *inloopOrigin {
	return newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		hits.Add(1)
		user := req.Header.Get("Authorization")
		if user == "" {
			user = "anonymous"
		}
		body := "hello " + user
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n%s\r\n%s",
			len(body), extraHeader, body)
	})
}

func TestInLoopProxyCacheDoesNotStoreAuthorizedResponse(t *testing.T) {
	var hits atomic.Int64
	o := perUserOrigin(t, &hits, "")
	addr := startCachingProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, privacyCacheConfig(), nil)

	_, first := doProxyGetWithHeader(t, addr, "/account", "Authorization", "Bearer alice")
	if first != "hello Bearer alice" {
		t.Fatalf("authorized body = %q", first)
	}
	_, second := doProxyGetWithHeader(t, addr, "/account", "", "")
	if second != "hello anonymous" {
		t.Fatalf("anonymous client received %q: the authorized response was stored in the shared cache", second)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("backend saw %d requests, want 2", got)
	}
}

func TestInLoopProxyCacheDoesNotStoreSetCookieResponse(t *testing.T) {
	var hits atomic.Int64
	o := perUserOrigin(t, &hits, "Set-Cookie: session=abc; HttpOnly\r\n")
	addr := startCachingProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, privacyCacheConfig(), nil)

	for i := 0; i < 3; i++ {
		doProxyGetWithHeader(t, addr, "/login", "", "")
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("backend saw %d of 3 requests; a Set-Cookie response was cached and replayed", got)
	}
}

func TestInLoopProxyCacheHonoursNoStoreFromOrigin(t *testing.T) {
	var hits atomic.Int64
	o := perUserOrigin(t, &hits, "Cache-Control: private, no-store\r\n")
	addr := startCachingProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, privacyCacheConfig(), nil)

	for i := 0; i < 3; i++ {
		doProxyGetWithHeader(t, addr, "/nostore", "", "")
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("backend saw %d of 3 requests; a Cache-Control: no-store response was cached", got)
	}
}
