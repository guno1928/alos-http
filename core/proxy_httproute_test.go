//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// startRouteProxy brings up a plain-HTTP server carrying port-80 path routes,
// which is how ACME HTTP-01 challenges are forwarded.
func startRouteProxy(t *testing.T, routes []HTTPRoute) string {
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
	srv.SetHTTPRoutes(routes)
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() {
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
	t.Fatal("route proxy never came up")
	return ""
}

func getRoute(t *testing.T, addr, path string) (*http.Response, string) {
	t.Helper()
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://" + addr + path)
	if err != nil {
		t.Fatalf("request %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// An ACME HTTP-01 challenge must be forwarded to the configured backend.
func TestHTTPRouteForwardsACMEChallenge(t *testing.T) {
	const token = "tOkEn-abc123.keyAuthorization-xyz"
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		if req.URL.Path != "/.well-known/acme-challenge/tOkEn-abc123" {
			fmt.Fprintf(conn, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
			return
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s",
			len(token), token)
	})
	addr := startRouteProxy(t, []HTTPRoute{
		{PathPrefix: "/.well-known/acme-challenge/", Backend: o.addr()},
	})

	resp, body := getRoute(t, addr, "/.well-known/acme-challenge/tOkEn-abc123")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body != token {
		t.Fatalf("challenge body = %q, want %q", body, token)
	}
}

// The route previously dialled the backend on every request. Going through the
// unified engine means upstream connections are pooled.
func TestHTTPRoutePoolsUpstreamConnections(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("ok"))
	addr := startRouteProxy(t, []HTTPRoute{
		{PathPrefix: "/api/", Backend: o.addr()},
	})

	client := &http.Client{Timeout: 10 * time.Second}
	for i := 0; i < 40; i++ {
		resp, err := client.Get("http://" + addr + "/api/x")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if got := o.accepted.Load(); got > 4 {
		t.Fatalf("origin accepted %d connections for 40 routed requests; the route is still dialling per request", got)
	}
}

// A path that matches no route must fall through to the normal handler rather
// than being proxied.
func TestHTTPRouteUnmatchedPathFallsThrough(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("from backend"))
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
	srv.Router.GET("/local", func(req *Request, resp *Response) {
		resp.Status(200).String("served locally")
	})
	srv.SetHTTPRoutes([]HTTPRoute{{PathPrefix: "/api/", Backend: o.addr()}})
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

	if resp, body := getRoute(t, addr, "/local"); resp.StatusCode != 200 || body != "served locally" {
		t.Fatalf("unmatched path did not reach the local handler: status=%d body=%q", resp.StatusCode, body)
	}
	if resp, body := getRoute(t, addr, "/api/thing"); resp.StatusCode != 200 || body != "from backend" {
		t.Fatalf("matched path was not proxied: status=%d body=%q", resp.StatusCode, body)
	}
}

// HostHeader on a route must be what the backend sees.
func TestHTTPRouteAppliesHostHeader(t *testing.T) {
	seen := make(chan string, 1)
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		select {
		case seen <- req.Host:
		default:
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	addr := startRouteProxy(t, []HTTPRoute{
		{PathPrefix: "/api/", Backend: o.addr(), HostHeader: "internal.example"},
	})

	if resp, _ := getRoute(t, addr, "/api/x"); resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	select {
	case host := <-seen:
		if host != "internal.example" {
			t.Fatalf("backend saw Host %q, want internal.example", host)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend never received the request")
	}
}

// An unreachable route backend must produce a gateway error, not a hang.
func TestHTTPRouteDeadBackendFailsFast(t *testing.T) {
	addr := startRouteProxy(t, []HTTPRoute{
		{PathPrefix: "/api/", Backend: freeAddr(t)},
	})

	start := time.Now()
	resp, _ := getRoute(t, addr, "/api/x")
	if resp.StatusCode < 500 {
		t.Fatalf("status = %d, want a 5xx for an unreachable backend", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %v to report an unreachable route backend", elapsed)
	}
}

// Routes added after startup must take effect.
func TestHTTPRouteAddedAtRuntime(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("late"))
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
	srv.SetHTTPRoutes(nil)
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

	srv.AddHTTPRoute(HTTPRoute{PathPrefix: "/late/", Backend: o.addr()})
	if resp, body := getRoute(t, addr, "/late/x"); resp.StatusCode != 200 || body != "late" {
		t.Fatalf("runtime-added route not served: status=%d body=%q", resp.StatusCode, body)
	}
}
