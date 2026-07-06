//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func osGetenvInt(key string) int {
	n, _ := strconv.Atoi(os.Getenv(key))
	return n
}

// TestKeepAliveThroughput isolates the request-serving path from the accept/close
// path: each client opens ONE connection and sends many sequential keep-alive
// requests. If this is fast and clean, the io_uring read/handle/write loop is
// healthy and any hang seen elsewhere is specific to accept-under-load (or WSL2).
func TestKeepAliveThroughput(t *testing.T) {
	if os.Getenv("ALOS_RUN_LOADTEST") == "" {
		t.Skip("load/throughput diagnostic; set ALOS_RUN_LOADTEST=1 to run (needs a real io_uring kernel, not WSL2)")
	}
	const (
		addr        = "127.0.0.1:18097"
		bodyLen     = 4 << 10
		conns       = 8
		reqsPerConn = 2000
	)
	body := strings.Repeat("A", bodyLen)

	workers := 4
	if v := osGetenvInt("ALOS_TEST_WORKERS"); v > 0 {
		workers = v
	}
	t.Logf("WorkerCount = %d", workers)
	srv := New(Config{Addr: addr, WorkerCount: workers})
	srv.Router.GET("/", func(req *Request, resp *Response) {
		resp.Status(200).Bytes([]byte(body))
	})
	go func() { _ = srv.ListenAndServe() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	if !waitListening(addr, 5*time.Second) {
		t.Fatal("server did not start listening")
	}

	var okReq, badReq int64
	runConn := func() error {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for i := 0; i < reqsPerConn; i++ {
			c.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
				return fmt.Errorf("write req %d: %w", i, err)
			}
			contentLen := -1
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return fmt.Errorf("read header req %d: %w", i, err)
				}
				line = strings.TrimRight(line, "\r\n")
				if strings.HasPrefix(strings.ToLower(line), "content-length:") {
					fmt.Sscanf(strings.TrimSpace(line[len("content-length:"):]), "%d", &contentLen)
				}
				if line == "" {
					break
				}
			}
			if contentLen != bodyLen {
				atomic.AddInt64(&badReq, 1)
				return fmt.Errorf("req %d wrong content-length %d", i, contentLen)
			}
			buf := make([]byte, contentLen)
			read := 0
			for read < contentLen {
				n, err := br.Read(buf[read:])
				for j := 0; j < n; j++ {
					if buf[read+j] != 'A' {
						atomic.AddInt64(&badReq, 1)
						return fmt.Errorf("req %d body corruption at %d", i, read+j)
					}
				}
				read += n
				if err != nil {
					return fmt.Errorf("read body req %d: %w", i, err)
				}
			}
			atomic.AddInt64(&okReq, 1)
		}
		return nil
	}

	start := time.Now()
	var wg sync.WaitGroup
	var firstErr atomic.Value
	for c := 0; c < conns; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runConn(); err != nil {
				firstErr.CompareAndSwap(nil, err.Error())
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	total := int64(conns * reqsPerConn)
	t.Logf("keep-alive requests: ok=%d bad=%d of %d in %v", okReq, badReq, total, elapsed.Round(time.Millisecond))
	if okReq > 0 {
		t.Logf("throughput = %.0f req/s over %d conns", float64(okReq)/elapsed.Seconds(), conns)
	}
	if e := firstErr.Load(); e != nil {
		t.Logf("first error: %s", e)
	}

	if badReq > 0 {
		t.Fatalf("CORRUPTION: %d keep-alive responses had wrong body/length", badReq)
	}
	if okReq < total {
		t.Fatalf("keep-alive stalled: only %d/%d requests completed (serving-path hang)", okReq, total)
	}
}
