//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ioWaitListening(addr string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// TestSplitPathKeepAliveVerify drives many sequential keep-alive requests for a
// LARGE (>16KB, split-send) response, byte-verifying every response body. This
// exercises split-send + the writingBody transition + the mid-send buffer
// release/re-acquire cycle repeatedly; any corruption shows up as bad>0.
func TestSplitPathKeepAliveVerify(t *testing.T) {
	if os.Getenv("ALOS_RUN_LOADTEST") == "" {
		t.Skip("io_uring load test; set ALOS_RUN_LOADTEST=1 (needs a real kernel, not WSL2)")
	}
	const (
		addr        = "127.0.0.1:18099"
		bodyLen     = 30 << 10
		conns       = 8
		reqsPerConn = 1500
	)
	body := strings.Repeat("A", bodyLen)

	srv := New(Config{Addr: addr, WorkerCount: 4})
	srv.Router.GET("/", func(req *Request, resp *Response) {
		resp.Status(200).HTML(body)
	})
	go func() { _ = srv.ListenAndServe() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	if !ioWaitListening(addr, 5*time.Second) {
		t.Fatal("server did not start")
	}

	var okReq, badReq int64
	runConn := func() {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for i := 0; i < reqsPerConn; i++ {
			c.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
				return
			}
			cl := -1
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimRight(line, "\r\n")
				if strings.HasPrefix(strings.ToLower(line), "content-length:") {
					fmt.Sscanf(strings.TrimSpace(line[len("content-length:"):]), "%d", &cl)
				}
				if line == "" {
					break
				}
			}
			if cl != bodyLen {
				atomic.AddInt64(&badReq, 1)
				return
			}
			buf := make([]byte, cl)
			read := 0
			for read < cl {
				n, err := br.Read(buf[read:])
				for j := 0; j < n; j++ {
					if buf[read+j] != 'A' {
						atomic.AddInt64(&badReq, 1)
						return
					}
				}
				read += n
				if err != nil {
					return
				}
			}
			atomic.AddInt64(&okReq, 1)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); runConn() }()
	}
	wg.Wait()

	t.Logf("split-path keep-alive: ok=%d bad=%d of %d", okReq, badReq, conns*reqsPerConn)
	if badReq > 0 {
		t.Fatalf("CORRUPTION: %d responses had wrong body/length (split-send + mid-send release bug)", badReq)
	}
	if okReq == 0 {
		t.Fatal("no request completed (env prevented validation)")
	}
}
