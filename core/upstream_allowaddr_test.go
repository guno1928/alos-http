//go:build linux && amd64

package core

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
)

func loopbackOrigin(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), &hits
}

func TestUpstreamAllowAddrBlocksDisallowedDestinations(t *testing.T) {
	addr, hits := loopbackOrigin(t)
	_, port, _ := net.SplitHostPort(addr)
	client, err := NewUpstreamClient(UpstreamConfig{Loops: 1, AllowAddr: func(ip netip.Addr) bool { return !ip.IsLoopback() }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	for _, authority := range []string{addr, "localhost:" + port} {
		_, err := client.Do(&UpstreamRequest{Scheme: "http", Authority: authority, Method: "GET", Path: "/"})
		if !errors.Is(err, ErrUpstreamDialBlocked) {
			t.Fatalf("%s: a blocked destination must fail with ErrUpstreamDialBlocked, got %v", authority, err)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the blocked origin was reached %d times", n)
	}
}

func TestUpstreamWithoutAllowAddrDialsAnyDestination(t *testing.T) {
	addr, hits := loopbackOrigin(t)
	client, err := NewUpstreamClient(UpstreamConfig{Loops: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	resp, err := client.Do(&UpstreamRequest{Scheme: "http", Authority: addr, Method: "GET", Path: "/"})
	if err != nil || resp.Status != 200 || hits.Load() != 1 {
		t.Fatalf("an unrestricted client must reach the origin: status=%v err=%v hits=%d", resp, err, hits.Load())
	}
}
