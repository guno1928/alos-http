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

const outlierTestDomain = "outlier.test"

type outlierOrigin struct {
	*inloopOrigin
	hits atomic.Int64
}

func newOutlierOrigin(t *testing.T, status int, body string) *outlierOrigin {
	o := &outlierOrigin{}
	o.inloopOrigin = newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		_, _ = io.Copy(io.Discard, req.Body)
		o.hits.Add(1)
		fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n%s", status, http.StatusText(status), len(body), body)
	})
	return o
}

func closedBackendAddr(t *testing.T) string {
	t.Helper()
	return refusedLoopbackAddr(t)
}

func startOutlierProxy(t *testing.T, backends ...string) (string, *domainState, *fakeClock) {
	t.Helper()
	cfg := DomainConfig{Domain: outlierTestDomain}
	for _, addr := range backends {
		cfg.Backends = append(cfg.Backends, BackendConfig{Addr: addr})
	}
	clock := newFakeClock(outlierTestStart)
	var ds *domainState
	addr := startInloopProxy(t, cfg, func(pe *ProxyEngine) {
		ds, _ = pe.domains.Load(outlierTestDomain)
		ds.outlier.now = clock.now
	})
	return addr, ds, clock
}

func outlierGet(t *testing.T, client *http.Client, addr string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("GET", "http://"+addr+"/o", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = outlierTestDomain
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func outlierClient(t *testing.T) *http.Client {
	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: harnessIOTimeout}
}

func TestProxyOutlierEpoll(t *testing.T) {
	t.Run("5xx backend is ejected and re-admitted", func(t *testing.T) {
		bad := newOutlierOrigin(t, 502, "bad")
		good := newOutlierOrigin(t, 200, "good")
		addr, ds, clock := startOutlierProxy(t, bad.addr(), good.addr())
		client := outlierClient(t)

		for bad.hits.Load() < 5 {
			outlierGet(t, client, addr)
			if good.hits.Load() > 20 {
				t.Fatal("the failing backend never received five requests")
			}
		}
		if !ds.backends[0].ejected(clock.now()) {
			t.Fatal("backend not ejected after five 502 responses")
		}
		for i := 0; i < 20; i++ {
			if status, body := outlierGet(t, client, addr); status != 200 || body != "good" {
				t.Fatalf("request %d while ejected: %d %q", i, status, body)
			}
		}
		if got := bad.hits.Load(); got != 5 {
			t.Fatalf("ejected backend received %d requests, want 5", got)
		}

		clock.advance(30 * time.Second)
		for i := 0; i < 4; i++ {
			outlierGet(t, client, addr)
		}
		if bad.hits.Load() == 5 {
			t.Fatal("backend not re-admitted after 30s")
		}
	})

	t.Run("connect failures eject and retries stop paying for them", func(t *testing.T) {
		good := newOutlierOrigin(t, 200, "good")
		addr, ds, clock := startOutlierProxy(t, closedBackendAddr(t), good.addr())
		client := outlierClient(t)
		for i := 0; i < 12; i++ {
			if status, body := outlierGet(t, client, addr); status != 200 || body != "good" {
				t.Fatalf("request %d: %d %q", i, status, body)
			}
		}
		if !ds.backends[0].ejected(clock.now()) {
			t.Fatal("unreachable backend not ejected")
		}
	})

	t.Run("the last healthy share is never ejected", func(t *testing.T) {
		a := newOutlierOrigin(t, 503, "a")
		b := newOutlierOrigin(t, 503, "b")
		addr, ds, clock := startOutlierProxy(t, a.addr(), b.addr())
		client := outlierClient(t)
		for i := 0; i < 30; i++ {
			if status, _ := outlierGet(t, client, addr); status != 503 {
				t.Fatalf("request %d: status %d, want the backend's 503", i, status)
			}
		}
		if got := ejectedCount(ds, clock.now()); got != 1 {
			t.Fatalf("%d of 2 backends ejected, want 1", got)
		}
	})
}

func TestProxyOutlierEngine(t *testing.T) {
	bad := newOutlierOrigin(t, 500, "bad")
	good := newOutlierOrigin(t, 200, "good")
	pe := NewProxyEngine()
	t.Cleanup(pe.Stop)
	pe.AddDomain(DomainConfig{Domain: outlierTestDomain, Backends: []BackendConfig{{Addr: bad.addr()}, {Addr: good.addr()}}})
	ds, _ := pe.domains.Load(outlierTestDomain)
	clock := newFakeClock(outlierTestStart)
	ds.outlier.now = clock.now

	get := func() int {
		req := &Request{Method: "GET", Host: outlierTestDomain, Path: "/o", RemoteAddr: "127.0.0.1:40000"}
		resp := &Response{}
		resp.Reset()
		if !pe.Handle(req, resp) {
			t.Fatal("not handled")
		}
		return resp.StatusCode
	}
	for bad.hits.Load() < 5 {
		get()
		if good.hits.Load() > 20 {
			t.Fatal("the failing backend never received five requests")
		}
	}
	for i := 0; i < 10; i++ {
		if status := get(); status != 200 {
			t.Fatalf("request %d while ejected: status %d", i, status)
		}
	}
	if got := bad.hits.Load(); got != 5 {
		t.Fatalf("ejected backend received %d requests, want 5", got)
	}
}
