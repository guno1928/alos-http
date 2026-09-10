//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const fastRootRaceDuration = 150 * time.Millisecond

func TestFastRootRecomputeWhileServing(t *testing.T) {
	addr := reserveLocalAddr(t)
	s := New(Config{Addr: addr, PlainHTTP: true, Listeners: 1, MaxConnsPerIP: -1, HTTPAddr: "-", LogRequests: false})
	s.Router.GET("/", func(req *Request, resp *Response) { resp.Status(200).String("root") })
	s.Router.GET("/ping", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	go func() { _ = s.ListenAndServeEpollH2(addr) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	if !waitServerReady(addr) {
		t.Fatal("server not ready")
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var bad atomic.Int64
	var served atomic.Int64
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				return
			}
			defer conn.Close()
			br := bufio.NewReader(conn)
			for {
				select {
				case <-stop:
					return
				default:
				}
				fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: t\r\n\r\n")
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					bad.Add(1)
					return
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				served.Add(1)
				if string(body) != "root" {
					bad.Add(1)
					return
				}
			}
		}()
	}
	deadline := time.Now().Add(fastRootRaceDuration)
	for time.Now().Before(deadline) {
		s.OnRequest(func(req *Request, resp *Response) bool { return true })
		s.hookMu.Lock()
		s.onRequestHooks.Store(nil)
		s.hookMu.Unlock()
		s.computeFastDispatch()
	}
	close(stop)
	wg.Wait()
	if served.Load() == 0 {
		t.Fatal("no request served")
	}
	if n := bad.Load(); n != 0 {
		t.Fatalf("%d root requests failed or returned a wrong body while the fast-root response was being recomputed", n)
	}
}
