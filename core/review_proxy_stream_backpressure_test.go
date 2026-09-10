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

	"golang.org/x/sys/unix"
)

const (
	backpressureBodySize     = 6 * proxyStreamHighWater
	backpressureClientRcvBuf = 32 << 10
	backpressureReadChunk    = 8 << 10
	backpressureStopStep     = 32 << 10
	backpressureStopFor      = 2 * time.Millisecond
	backpressureRequestLimit = 3 * time.Second
	backpressureFastRequests = 96
)

func slowProxyGet(t *testing.T, addr string, body []byte, stopAt int) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer raw.Close()
	c := raw.(*net.TCPConn)
	if err := c.SetReadBuffer(backpressureClientRcvBuf); err != nil {
		t.Fatalf("set read buffer: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(backpressureRequestLimit))
	fmt.Fprintf(c, "GET /big HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n")
	br := bufio.NewReaderSize(c, backpressureReadChunk)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("stop at %d: response head: %v", stopAt, err)
	}
	defer resp.Body.Close()
	got := 0
	stopped := stopAt < 0
	buf := make([]byte, backpressureReadChunk)
	for {
		n, rerr := resp.Body.Read(buf)
		got += n
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("stop at %d: body read after %d of %d bytes: %v", stopAt, got, len(body), rerr)
		}
		if !stopped && got >= stopAt {
			stopped = true
			time.Sleep(backpressureStopFor)
		}
	}
	if got != len(body) {
		t.Fatalf("stop at %d: body truncated: got %d of %d bytes", stopAt, got, len(body))
	}
}

func startSingleLoopProxy(t *testing.T, cfg DomainConfig) string {
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
		Listeners:     1,
	})
	srv.AddProxyDomain(cfg)
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	waitForProxy(t, addr)
	return addr
}

func waitForProxy(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, derr := net.DialTimeout("tcp", addr, 200*time.Millisecond); derr == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("proxy never came up")
}

func TestInLoopProxySlowClientKeepsBackendUsable(t *testing.T) {
	body := make([]byte, backpressureBodySize)
	o := newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))
		_, _ = conn.Write(body)
	})
	addr := startSingleLoopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	})

	for stopAt := backpressureBodySize - backpressureStopStep; stopAt > 0; stopAt -= backpressureStopStep {
		slowProxyGet(t, addr, body, stopAt)
	}
	for i := 0; i < backpressureFastRequests; i++ {
		slowProxyGet(t, addr, body, -1)
	}
	if o.accepted.Load() != 1 {
		t.Fatalf("expected every request to reuse one backend connection, origin accepted %d", o.accepted.Load())
	}
}

func TestBackendConnIdledWhilePausedRearmsReads(t *testing.T) {
	ep, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatalf("epoll_create: %v", err)
	}
	defer unix.Close(ep)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	l := &beLoop{}
	l.init(ep, &fpConfig{MaxIdlePerBackend: 4, IdleTimeout: time.Second, MaxResponseBody: 1 << 20}, nil)
	c := &backendConn{fd: fds[0], be: l, state: connReady, transport: &plainTransport{}, proto: &l.h1proto}
	l.ensureFD(c.fd)
	l.conns[c.fd] = c
	l.liveConns++
	ev := unix.EpollEvent{Events: unix.EPOLLIN | unix.EPOLLOUT | unix.EPOLLRDHUP | unix.EPOLLET, Fd: int32(c.fd), Pad: epollFDClassBackend}
	if err := unix.EpollCtl(ep, unix.EPOLL_CTL_ADD, c.fd, &ev); err != nil {
		t.Fatalf("epoll_ctl add: %v", err)
	}
	drainEpoll(t, ep)

	l.pauseBackendRead(c)
	if !c.readPaused {
		t.Fatal("pause did not take effect")
	}
	l.idlePut(c)
	if c.readPaused {
		t.Fatal("backend connection went idle with reads still paused")
	}
	if _, err := unix.Write(fds[1], []byte("HTTP/1.1 200 OK\r\n")); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	if !epollReportsIn(t, ep, c.fd) {
		t.Fatal("idle backend connection does not wake on readable data")
	}
}

func drainEpoll(t *testing.T, ep int) {
	t.Helper()
	var events [8]unix.EpollEvent
	for {
		n, err := unix.EpollWait(ep, events[:], 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			t.Fatalf("epoll_wait: %v", err)
		}
		if n == 0 {
			return
		}
	}
}

func epollReportsIn(t *testing.T, ep, fd int) bool {
	t.Helper()
	var events [8]unix.EpollEvent
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		n, err := unix.EpollWait(ep, events[:], 15)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			t.Fatalf("epoll_wait: %v", err)
		}
		for i := 0; i < n; i++ {
			if int(events[i].Fd) == fd && events[i].Events&unix.EPOLLIN != 0 {
				return true
			}
		}
	}
	return false
}
