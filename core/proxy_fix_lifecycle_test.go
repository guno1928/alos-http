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

type proxyFixHeldOrigin struct {
	*inloopOrigin
	received atomic.Int64
	release  chan struct{}
}

func newProxyFixHeldOrigin(t *testing.T, streamed bool) *proxyFixHeldOrigin {
	t.Helper()
	h := &proxyFixHeldOrigin{release: make(chan struct{})}
	h.inloopOrigin = newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		h.received.Add(1)
		if streamed {
			fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n")
		}
		<-h.release
		if streamed {
			fmt.Fprint(conn, "4\r\nlast\r\n0\r\n\r\n")
			return
		}
		fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	t.Cleanup(h.releaseOnce)
	return h
}

func (h *proxyFixHeldOrigin) releaseOnce() {
	select {
	case <-h.release:
	default:
		close(h.release)
	}
}

func proxyFixSingleBackend(addr string) []DomainConfig {
	return []DomainConfig{{Domain: proxyFixDomain, Backends: []BackendConfig{{Addr: addr}}}}
}

func proxyFixReset(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}

func proxyFixAssertConnsDrain(t *testing.T, srv *Server, what string) {
	t.Helper()
	if !proxyFixWaitFor(func() bool { return srv.activeConns.Load() == 0 }) {
		t.Fatalf("%s: activeConns=%d after the client went away, want 0 (epollConn and MaxConns slot leaked)",
			what, srv.activeConns.Load())
	}
}

func proxyFixAssertStillServes(t *testing.T, addr string) {
	t.Helper()
	resp, body := proxyFixRoundTrip(t, addr, proxyFixGet(proxyFixDomain, "/after"))
	if resp.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("follow-up request: status=%d body=%q", resp.StatusCode, body)
	}
}

func TestProxyFixH2ClientAbortReleasesConn(t *testing.T) {
	o := newProxyFixHeldOrigin(t, false)
	srv, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), nil)

	c := proxyFixH2cDial(t, addr)
	if _, err := c.Write(proxyFixH2Request(1, "GET", proxyFixDomain, "/held")); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	proxyFixEventually(t, "origin received the proxied stream", func() bool { return o.received.Load() == 1 })
	_ = c.Close()
	time.Sleep(proxyFixStep)
	o.releaseOnce()

	proxyFixAssertConnsDrain(t, srv, "h2 abort")
	proxyFixAssertStillServes(t, addr)
}

func TestProxyFixH1BufferedClientAbortReleasesConn(t *testing.T) {
	o := newProxyFixHeldOrigin(t, false)
	srv, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), nil)

	c := proxyFixDial(t, addr)
	if _, err := io.WriteString(c, proxyFixGet(proxyFixDomain, "/held")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	proxyFixEventually(t, "origin received the proxied request", func() bool { return o.received.Load() == 1 })
	proxyFixReset(c)
	time.Sleep(proxyFixStep)
	o.releaseOnce()

	proxyFixAssertConnsDrain(t, srv, "h1 buffered abort")
	proxyFixAssertStillServes(t, addr)
}

func TestProxyFixH1StreamedClientAbortReleasesConn(t *testing.T) {
	o := newProxyFixHeldOrigin(t, true)
	srv, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), nil)

	c := proxyFixDial(t, addr)
	if _, err := io.WriteString(c, proxyFixGet(proxyFixDomain, "/stream")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read streamed head: %v", err)
	}
	first := make([]byte, len("first"))
	if _, err := io.ReadFull(resp.Body, first); err != nil || string(first) != "first" {
		t.Fatalf("first chunk = %q, %v", first, err)
	}
	proxyFixReset(c)
	time.Sleep(proxyFixStep)
	o.releaseOnce()

	proxyFixAssertConnsDrain(t, srv, "h1 streamed abort")
}

const proxyFixUnresolvableBackend = "127.0.0.1:99999"

type proxyFixFailureCase struct {
	name       string
	domains    func(t *testing.T) []DomainConfig
	wantStatus int
}

func proxyFixRefusedAddr(t *testing.T) string {
	t.Helper()
	return refusedLoopbackAddr(t)
}

func proxyFixFailureCases() []proxyFixFailureCase {
	return []proxyFixFailureCase{
		{"unresolvable", func(t *testing.T) []DomainConfig {
			return proxyFixSingleBackend(proxyFixUnresolvableBackend)
		}, http.StatusBadGateway},
		{"refused", func(t *testing.T) []DomainConfig {
			return proxyFixSingleBackend(proxyFixRefusedAddr(t))
		}, http.StatusBadGateway},
		{"unresolvable_then_healthy", func(t *testing.T) []DomainConfig {
			o := newInloopOrigin(t, echoBodyOrigin("ok"))
			return []DomainConfig{{Domain: proxyFixDomain, MaxRetries: 1, Backends: []BackendConfig{
				{Addr: proxyFixUnresolvableBackend}, {Addr: o.addr()},
			}}}
		}, http.StatusOK},
		{"refused_then_healthy", func(t *testing.T) []DomainConfig {
			o := newInloopOrigin(t, echoBodyOrigin("ok"))
			return []DomainConfig{{Domain: proxyFixDomain, MaxRetries: 1, Backends: []BackendConfig{
				{Addr: proxyFixRefusedAddr(t)}, {Addr: o.addr()},
			}}}
		}, http.StatusOK},
	}
}

const proxyFixKeepAliveRounds = 4

func TestProxyFixH1BackendFailureKeepsConnectionUsable(t *testing.T) {
	for _, tc := range proxyFixFailureCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv, addr := proxyFixStart(t, Config{}, tc.domains(t), nil)
			c := proxyFixDial(t, addr)
			br := bufio.NewReader(c)
			for i := 0; i < proxyFixKeepAliveRounds; i++ {
				if _, err := io.WriteString(c, "GET /x HTTP/1.1\r\nHost: "+proxyFixDomain+"\r\n\r\n"); err != nil {
					t.Fatalf("request %d: write: %v", i, err)
				}
				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					t.Fatalf("request %d on a keep-alive connection: %v", i, err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != tc.wantStatus {
					t.Fatalf("request %d: status=%d, want %d", i, resp.StatusCode, tc.wantStatus)
				}
			}
			_ = c.Close()
			proxyFixAssertConnsDrain(t, srv, tc.name+" over h1")
		})
	}
}

func TestProxyFixH2BackendFailureFinishesEachStreamOnce(t *testing.T) {
	for _, tc := range proxyFixFailureCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv, addr := proxyFixStart(t, Config{}, tc.domains(t), nil)
			c := proxyFixH2cDial(t, addr)
			defer c.Close()
			streams := []uint32{1, 3, 5, 7}
			ended := map[uint32]int{}
			headers := map[uint32]int{}
			for _, sid := range streams {
				if _, err := c.Write(proxyFixH2Request(sid, "GET", proxyFixDomain, "/x")); err != nil {
					t.Fatalf("write stream %d: %v", sid, err)
				}
			}
			for len(ended) < len(streams) {
				f := c.readFrame(t)
				if f.typ == h2FrameGoAway {
					t.Fatalf("GOAWAY before all streams ended: %v", ended)
				}
				if f.typ == h2FrameHeaders {
					headers[f.streamID]++
				}
				if (f.typ == h2FrameHeaders || f.typ == h2FrameData) && f.flags&h2FlagEndStream != 0 {
					ended[f.streamID]++
				}
			}
			for _, f := range c.framesUntilPingAck(t) {
				if f.typ == h2FrameHeaders {
					headers[f.streamID]++
				}
			}
			for _, sid := range streams {
				if headers[sid] != 1 {
					t.Fatalf("stream %d answered with %d HEADERS frames, want exactly 1 (all: %v)", sid, headers[sid], headers)
				}
			}
			_ = c.Close()
			proxyFixAssertConnsDrain(t, srv, tc.name+" over h2")
		})
	}
}

func TestProxyFixShutdownClosesIdleProxiedKeepAliveConn(t *testing.T) {
	o := newProxyFixLabelOrigin(t, "ORIGIN")
	srv, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), nil)
	c := proxyFixDial(t, addr)
	defer c.Close()
	if _, err := io.WriteString(c, "GET /idle HTTP/1.1\r\nHost: "+proxyFixDomain+"\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if resp, body := proxyFixReadResponse(t, bufio.NewReader(c)); resp.StatusCode != http.StatusOK || body != "ORIGIN:/idle" {
		t.Fatalf("proxied keep-alive request: %d %q", resp.StatusCode, body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*proxyFixStep)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown with one idle proxied keep-alive conn: %v (activeConns=%d); the conn was never treated as idle", err, srv.activeConns.Load())
	}
}
