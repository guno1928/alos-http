//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

const (
	retryTestDomain      = "origin.test"
	retryTestReadTimeout = 150 * time.Millisecond
	retryTestSlowDelay   = 3 * retryTestReadTimeout
	retryTestHealthyBody = "from healthy"
)

type retryOrigin struct {
	addr string
	hits *atomic.Int64
}

func startRetryOrigin(t *testing.T, kind string) retryOrigin {
	t.Helper()
	hits := &atomic.Int64{}
	if kind == "refused" {
		return retryOrigin{addr: refusedLoopbackAddr(t), hits: hits}
	}
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		_, _ = io.Copy(io.Discard, req.Body)
		hits.Add(1)
		switch kind {
		case "reset":
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			_ = conn.Close()
		case "slow":
			time.Sleep(retryTestSlowDelay)
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow")
		default:
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s",
				len(retryTestHealthyBody), retryTestHealthyBody)
		}
	})
	return retryOrigin{addr: o.addr(), hits: hits}
}

type retryCase struct {
	name       string
	method     string
	headers    [][2]string
	backends   []string
	wantStatus int
	wantHits   []int64
	trustKey   bool
}

var retryCases = []retryCase{
	{"post reset after read is not retried", "POST", nil, []string{"reset", "healthy"}, 502, []int64{1, 0}, false},
	{"put reset after read is not retried", "PUT", nil, []string{"reset", "healthy"}, 502, []int64{1, 0}, false},
	{"post with untrusted idempotency key is not retried", "POST", [][2]string{{"Idempotency-Key", "k1"}}, []string{"reset", "healthy"}, 502, []int64{1, 0}, false},
	{"post with trusted idempotency key is retried", "POST", [][2]string{{"Idempotency-Key", "k1"}}, []string{"reset", "healthy"}, 200, []int64{1, 1}, true},
	{"get reset after read is retried", "GET", nil, []string{"reset", "healthy"}, 200, []int64{1, 1}, false},
	{"post to refused backend fails over", "POST", nil, []string{"refused", "healthy"}, 200, []int64{0, 1}, false},
	{"get timeout on only backend is 504", "GET", nil, []string{"slow"}, 504, []int64{1}, false},
	{"post timeout is 504 and not retried", "POST", nil, []string{"slow", "healthy"}, 504, []int64{1, 0}, false},
}

func (c retryCase) domainConfig(origins []retryOrigin) DomainConfig {
	cfg := DomainConfig{Domain: retryTestDomain, ReadTimeout: retryTestReadTimeout, MaxRetries: len(origins), TrustIdempotencyKey: c.trustKey}
	for _, o := range origins {
		cfg.Backends = append(cfg.Backends, BackendConfig{Addr: o.addr})
	}
	return cfg
}

func (c retryCase) check(t *testing.T, origins []retryOrigin, status int, body []byte) {
	t.Helper()
	if status != c.wantStatus {
		t.Errorf("status %d, want %d (body %q)", status, c.wantStatus, body)
	}
	if c.wantStatus == 200 && string(body) != retryTestHealthyBody {
		t.Errorf("body %q, want %q", body, retryTestHealthyBody)
	}
	time.Sleep(retryTestReadTimeout)
	for i, o := range origins {
		if got := o.hits.Load(); got != c.wantHits[i] {
			t.Errorf("backend %d (%s) handled %d requests, want %d", i, c.backends[i], got, c.wantHits[i])
		}
	}
}

func (c retryCase) startOrigins(t *testing.T) []retryOrigin {
	origins := make([]retryOrigin, len(c.backends))
	for i, kind := range c.backends {
		origins[i] = startRetryOrigin(t, kind)
	}
	return origins
}

func waitBackendsIdle(t *testing.T, pe *ProxyEngine) {
	t.Helper()
	ds := pe.Lookup(retryTestDomain)
	waitFor(t, harnessIOTimeout, func() bool {
		for _, b := range ds.backends {
			if b.ActiveConns.Load() != 0 {
				return false
			}
		}
		return true
	})
}

func TestProxyRetryEngine(t *testing.T) {
	for _, c := range retryCases {
		t.Run(c.name, func(t *testing.T) {
			origins := c.startOrigins(t)
			pe := NewProxyEngine()
			pe.AddDomain(c.domainConfig(origins))
			t.Cleanup(pe.Stop)
			req := &Request{
				Method:     c.method,
				Host:       retryTestDomain,
				Path:       "/r",
				Headers:    append([][2]string{{"Content-Length", "4"}}, c.headers...),
				Body:       []byte("body"),
				RemoteAddr: "127.0.0.1:40000",
			}
			resp := &Response{}
			resp.Reset()
			if !pe.Handle(req, resp) {
				t.Fatal("Handle did not claim the request")
			}
			c.check(t, origins, resp.StatusCode, resp.transmittedBodyBytes())
			waitBackendsIdle(t, pe)
		})
	}
}

func doRetryRequest(t *testing.T, client *http.Client, url string, c retryCase) (int, []byte, int) {
	t.Helper()
	req, err := http.NewRequest(c.method, url, bytes.NewReader([]byte("body")))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = retryTestDomain
	for _, h := range c.headers {
		req.Header.Set(h[0], h[1])
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, body, resp.ProtoMajor
}

func TestProxyRetryEpollH1(t *testing.T) {
	for _, c := range retryCases {
		t.Run(c.name, func(t *testing.T) {
			origins := c.startOrigins(t)
			var pe *ProxyEngine
			addr := startInloopProxy(t, c.domainConfig(origins), func(p *ProxyEngine) { pe = p })
			tr := &http.Transport{}
			t.Cleanup(tr.CloseIdleConnections)
			status, body, _ := doRetryRequest(t, &http.Client{Transport: tr, Timeout: harnessIOTimeout}, "http://"+addr+"/r", c)
			c.check(t, origins, status, body)
			waitBackendsIdle(t, pe)
		})
	}
}

func TestProxyRetryEpollH2(t *testing.T) {
	for _, c := range retryCases {
		t.Run(c.name, func(t *testing.T) {
			origins := c.startOrigins(t)
			ts := newTestServer(t, testServerOptions{
				TLS:    true,
				Domain: retryTestDomain,
				Setup:  func(s *Server) { s.AddProxyDomain(c.domainConfig(origins)) },
			})
			status, body, proto := doRetryRequest(t, ts.client(t, "h2"), ts.url("/r"), c)
			if proto != 2 {
				t.Fatalf("request used HTTP/%d, want HTTP/2", proto)
			}
			c.check(t, origins, status, body)
			waitBackendsIdle(t, ts.srv.proxy.Load())
		})
	}
}
