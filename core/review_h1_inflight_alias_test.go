//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	inflightAliasHookHold  = 2 * 150 * time.Millisecond
	inflightAliasProbeConn = 48
)

func dialSmallRecvBuf(t *testing.T, addr string) net.Conn {
	t.Helper()
	d := net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

func resetConn(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = conn.Close()
}

func TestH1InFlightRequestSurvivesReadBufPoolReuse(t *testing.T) {
	addr := reserveLocalAddr(t)
	s := New(Config{
		Addr:          addr,
		PlainHTTP:     true,
		Listeners:     1,
		MaxConnsPerIP: 1 << 16,
		ReadTimeout:   30 * time.Second,
		IdleTimeout:   30 * time.Second,
	})
	bigBody := bytes.Repeat([]byte("x"), 8<<20)
	s.Router.GET("/ping", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	s.Router.GET("/big", func(req *Request, resp *Response) { resp.Status(200).Bytes(bigBody) })
	s.Router.GET("/slow/:id", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	s.Router.GET("/probe/:id", func(req *Request, resp *Response) { resp.Status(200).String("ok") })

	var mutated atomic.Int32
	var observed atomic.Int32
	var firstMutation atomic.Value
	hookDone := make(chan struct{}, 1)
	s.OnRequest(func(req *Request, resp *Response) bool {
		if !strings.HasPrefix(req.Path, "/slow/") {
			return true
		}
		before := strings.Clone(req.Path)
		observed.Add(1)
		time.Sleep(inflightAliasHookHold)
		after := strings.Clone(req.Path)
		if before != after {
			mutated.Add(1)
			firstMutation.CompareAndSwap(nil, before+" -> "+after)
		}
		select {
		case hookDone <- struct{}{}:
		default:
		}
		return true
	})

	go func() { _ = s.ListenAndServeEpollH2(addr) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	if !waitServerReady(addr) {
		t.Fatalf("server did not come up on %s", addr)
	}

	victim := dialSmallRecvBuf(t, addr)
	fmt.Fprint(victim, "GET /big HTTP/1.1\r\nHost: t\r\n\r\n")
	time.Sleep(150 * time.Millisecond)
	victimPath := "/slow/" + strings.Repeat("V", 200)
	fmt.Fprintf(victim, "GET %s HTTP/1.1\r\nHost: t\r\n\r\n", victimPath)
	time.Sleep(50 * time.Millisecond)
	if observed.Load() == 0 {
		t.Fatalf("hook never observed the in-flight request; test setup is wrong")
	}
	resetConn(victim)

	probePath := "/probe/" + strings.Repeat("P", 200)
	var wg sync.WaitGroup
	for i := 0; i < inflightAliasProbeConn; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", addr)
			if err != nil {
				return
			}
			defer c.Close()
			fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", probePath)
			_, _ = io.Copy(io.Discard, bufio.NewReader(c))
		}()
	}
	wg.Wait()

	select {
	case <-hookDone:
	case <-time.After(inflightAliasHookHold + 2*time.Second):
		t.Fatalf("hook did not finish")
	}
	if n := mutated.Load(); n != 0 {
		t.Fatalf("in-flight request strings changed underneath the handler after the connection was reset (%d mutation(s)); read buffer was recycled while the request was still dispatched: %v", n, firstMutation.Load())
	}
}
