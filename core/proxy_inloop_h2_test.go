//go:build linux && amd64

package core

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// h2ProxyClient speaks HTTP/2 over TLS to the proxy. It uses the standard
// library's bundled HTTP/2 via ALPN rather than pulling in x/net/http2, so the
// tests add no dependency to the module.
func h2ProxyClient(domain string) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         domain,
				NextProtos:         []string{"h2"},
			},
		},
	}
}

func doH2ProxyGet(t *testing.T, addr, domain, path string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest("GET", "https://"+addr+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = domain
	resp, err := h2ProxyClient(domain).Do(req)
	if err != nil {
		t.Fatalf("h2 proxy request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("negotiated HTTP/%d.%d, want HTTP/2 — the test is not exercising the H2 path",
			resp.ProtoMajor, resp.ProtoMinor)
	}
	return resp, string(body)
}

// A proxied request over HTTP/2 must produce the same result as over HTTP/1.1.
func TestInLoopProxyOverH2(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("hello over h2"))
	addr := startInloopTLSProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	resp, body := doH2ProxyGet(t, addr, "origin.test", "/hello")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body != "hello over h2" {
		t.Fatalf("body = %q", body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
}

// Many streams on one HTTP/2 connection must all be served, and must share the
// upstream pool rather than opening a backend connection each.
func TestInLoopProxyOverH2ConcurrentStreams(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("ok"))
	addr := startInloopTLSProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	client := h2ProxyClient("origin.test")
	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s/s%d", addr, i), nil)
			req.Host = "origin.test"
			resp, err := client.Do(req)
			if err != nil {
				failures.Add(1)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.ProtoMajor != 2 || string(body) != "ok" {
				failures.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if n := failures.Load(); n != 0 {
		t.Fatalf("%d of 40 concurrent H2 streams failed", n)
	}
}

// HTTP/1.1 cannot multiplex, so N concurrent streams genuinely need N upstream
// connections. What the pool must deliver is reuse across successive rounds
// rather than a fresh dial per stream.
func TestInLoopProxyOverH2ReusesUpstreamAcrossRounds(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("ok"))
	addr := startInloopTLSProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	client := h2ProxyClient("origin.test")
	const rounds, perRound = 20, 4
	for r := 0; r < rounds; r++ {
		var wg sync.WaitGroup
		for i := 0; i < perRound; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, _ := http.NewRequest("GET", "https://"+addr+"/x", nil)
				req.Host = "origin.test"
				resp, err := client.Do(req)
				if err != nil {
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}()
		}
		wg.Wait()
	}

	total := rounds * perRound
	opened := o.accepted.Load()
	if opened >= int64(total) {
		t.Fatalf("origin accepted %d connections for %d requests; upstream connections are not being reused",
			opened, total)
	}
	t.Logf("%d requests over %d upstream connections (%.1f requests each)",
		total, opened, float64(total)/float64(opened))
}

// A POST body must reach the backend intact over HTTP/2.
func TestInLoopProxyOverH2PostBody(t *testing.T) {
	got := make(chan []byte, 1)
	backend := capturingOrigin(t, got)
	addr := startInloopTLSProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: backend}},
	}, nil)

	req, _ := http.NewRequest("POST", "https://"+addr+"/submit",
		strings.NewReader("h2-payload-9876"))
	req.Host = "origin.test"
	req.ContentLength = int64(len("h2-payload-9876"))
	resp, err := h2ProxyClient("origin.test").Do(req)
	if err != nil {
		t.Fatalf("h2 post: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	select {
	case body := <-got:
		if string(body) != "h2-payload-9876" {
			t.Fatalf("backend received %q", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend never received the H2 POST body")
	}
}

// A larger response must survive HTTP/2 framing and flow control intact.
func TestInLoopProxyOverH2LargeResponse(t *testing.T) {
	const size = 1 << 20
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

	resp, body := doH2ProxyGet(t, addr, "origin.test", "/big")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
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

// OnResponse must fire for a live H2-proxied response, as it does for H1.
func TestInLoopProxyOverH2FiresOnResponse(t *testing.T) {
	o := newInloopOrigin(t, echoBodyOrigin("original"))
	var fired atomic.Bool
	addr := startInloopTLSProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, func(pe *ProxyEngine) {
		pe.OnResponse = func(pr *ProxyResponse) {
			fired.Store(true)
			pr.Headers = append(pr.Headers, [2]string{"X-Added-By-Hook", "yes"})
		}
	})

	resp, _ := doH2ProxyGet(t, addr, "origin.test", "/hooked")
	if !fired.Load() {
		t.Fatal("OnResponse did not fire for a live H2 response")
	}
	if got := resp.Header.Get("X-Added-By-Hook"); got != "yes" {
		t.Fatalf("hook-added header did not reach the H2 client (got %q)", got)
	}
}

// A refused backend must be retried on another one over HTTP/2 too.
func TestInLoopProxyOverH2RetriesFailedBackend(t *testing.T) {
	deadAddr := freeAddr(t)
	o := newInloopOrigin(t, echoBodyOrigin("from healthy"))
	var errCount atomic.Int64
	addr := startInloopTLSProxy(t, DomainConfig{
		Domain:     "origin.test",
		Backends:   []BackendConfig{{Addr: deadAddr}, {Addr: o.addr()}},
		MaxRetries: 2,
	}, func(pe *ProxyEngine) {
		pe.OnError = func(ProxyError) { errCount.Add(1) }
	})

	resp, body := doH2ProxyGet(t, addr, "origin.test", "/retry")
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

// The point of the change: an H2-proxied request must not park a goroutine on
// the backend, so a slow upstream must not stall other streams or grow the
// goroutine count per in-flight request.
func TestInLoopProxyOverH2SlowBackendDoesNotBlockOthers(t *testing.T) {
	slow := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		time.Sleep(300 * time.Millisecond)
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow")
	})
	fast := newInloopOrigin(t, echoBodyOrigin("fast"))

	addr := startInloopTLSProxyMulti(t, []DomainConfig{
		{Domain: "slow.test", Backends: []BackendConfig{{Addr: slow.addr()}}},
		{Domain: "fast.test", Backends: []BackendConfig{{Addr: fast.addr()}}},
	}, nil)

	slowClient := h2ProxyClient("slow.test")
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "https://"+addr+"/s", nil)
			req.Host = "slow.test"
			if resp, err := slowClient.Do(req); err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
	time.Sleep(150 * time.Millisecond)

	var slowest time.Duration
	for i := 0; i < 5; i++ {
		start := time.Now()
		resp, body := doH2ProxyGet(t, addr, "fast.test", "/f")
		if resp.StatusCode != 200 || body != "fast" {
			t.Fatalf("fast request %d: status=%d body=%q", i, resp.StatusCode, body)
		}
		if d := time.Since(start); d > slowest {
			slowest = d
		}
	}
	wg.Wait()
	if slowest > 250*time.Millisecond {
		t.Fatalf("a fast H2 request took %v while a slow backend was in flight; the worker is still being blocked", slowest)
	}
}
