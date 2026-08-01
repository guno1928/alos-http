//go:build linux

package core

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// minimalOrigin answers with a canned HTTP/1.1 response and does no routing,
// header allocation or handler dispatch. A Go net/http server has its own
// throughput ceiling, so benchmarking a client against one measures whichever
// side saturates first. This isolates the client.
func minimalOrigin(t *testing.T, bodySize int) (string, *atomic.Int64, func()) {
	t.Helper()
	body := bytes.Repeat([]byte("x"), bodySize)
	resp := []byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s",
		len(body), body))

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int64
	var closed atomic.Bool
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if closed.Load() {
					return
				}
				continue
			}
			accepted.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 16<<10)
				pending := 0
				for {
					n, err := c.Read(buf)
					if n > 0 {
						pending += bytes.Count(buf[:n], []byte("\r\n\r\n"))
						for pending > 0 {
							if _, werr := c.Write(resp); werr != nil {
								return
							}
							pending--
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), &accepted, func() { closed.Store(true); ln.Close() }
}

func drive(concurrency, total int, fn func(i int) error) (time.Duration, error) {
	var wg sync.WaitGroup
	work := make(chan int, concurrency)
	errCh := make(chan error, concurrency)
	start := time.Now()
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				if err := fn(i); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
			}
		}()
	}
	for i := range total {
		work <- i
	}
	close(work)
	wg.Wait()
	elapsed := time.Since(start)
	close(errCh)
	return elapsed, <-errCh
}

func TestUpstreamCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("ceiling probe")
	}
	const total = 50000
	t.Logf("GOMAXPROCS=%d NumCPU=%d", runtime.GOMAXPROCS(0), runtime.NumCPU())

	for _, concurrency := range []int{64, 256, 1024} {
		addr, accepted, stop := minimalOrigin(t, 1024)
		client, err := NewUpstreamClient(UpstreamConfig{})
		if err != nil {
			t.Fatal(err)
		}
		elapsed, err := drive(concurrency, total, func(i int) error {
			r, err := client.Do(&UpstreamRequest{
				Scheme: "http", Authority: addr, Method: "GET", Path: "/",
			})
			if err != nil {
				return err
			}
			if r.Status != 200 {
				return fmt.Errorf("status %d", r.Status)
			}
			return nil
		})
		conns := accepted.Load()
		client.Close()
		stop()
		if err != nil {
			t.Fatalf("epoll c=%d: %v", concurrency, err)
		}
		t.Logf("epoll  c=%-5d %8s %10.0f req/s  conns=%d",
			concurrency, elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds(), conns)
	}

	for _, concurrency := range []int{64, 256, 1024} {
		addr, accepted, stop := minimalOrigin(t, 1024)
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.MaxIdleConns = 4096
		tr.MaxIdleConnsPerHost = 4096
		client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
		url := "http://" + addr + "/"
		elapsed, err := drive(concurrency, total, func(i int) error {
			resp, err := client.Get(url)
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			return resp.Body.Close()
		})
		conns := accepted.Load()
		client.CloseIdleConnections()
		stop()
		if err != nil {
			t.Fatalf("stdlib c=%d: %v", concurrency, err)
		}
		t.Logf("stdlib c=%-5d %8s %10.0f req/s  conns=%d",
			concurrency, elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds(), conns)
	}
}

func TestLoopsPerOriginSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("sweep")
	}
	const total = 50000
	const concurrency = 256
	t.Logf("GOMAXPROCS=%d, %d requests, concurrency %d, single origin",
		runtime.GOMAXPROCS(0), total, concurrency)
	for _, shards := range []int{1, 2, 4, 8, 16} {
		addr, accepted, stop := minimalOrigin(t, 1024)
		client, err := NewUpstreamClient(UpstreamConfig{LoopsPerOrigin: shards})
		if err != nil {
			t.Fatal(err)
		}
		elapsed, err := drive(concurrency, total, func(i int) error {
			r, derr := client.Do(&UpstreamRequest{
				Scheme: "http", Authority: addr, Method: "GET", Path: "/",
			})
			if derr != nil {
				return derr
			}
			if r.Status != 200 {
				return fmt.Errorf("status %d", r.Status)
			}
			return nil
		})
		conns := accepted.Load()
		client.Close()
		stop()
		if err != nil {
			t.Fatalf("shards=%d: %v", shards, err)
		}
		t.Logf("LoopsPerOrigin=%-3d %8s %10.0f req/s  conns=%d",
			shards, elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds(), conns)
	}
}

func TestLoopsPerOriginPeak(t *testing.T) {
	if testing.Short() {
		t.Skip("peak")
	}
	const total = 100000
	for _, cfg := range []struct{ shards, concurrency int }{
		{6, 512}, {8, 512}, {10, 512}, {12, 512}, {8, 1024}, {8, 2048},
	} {
		addr, accepted, stop := minimalOrigin(t, 1024)
		client, err := NewUpstreamClient(UpstreamConfig{LoopsPerOrigin: cfg.shards})
		if err != nil {
			t.Fatal(err)
		}
		elapsed, err := drive(cfg.concurrency, total, func(i int) error {
			r, derr := client.Do(&UpstreamRequest{
				Scheme: "http", Authority: addr, Method: "GET", Path: "/",
			})
			if derr != nil {
				return derr
			}
			if r.Status != 200 {
				return fmt.Errorf("status %d", r.Status)
			}
			return nil
		})
		conns := accepted.Load()
		client.Close()
		stop()
		if err != nil {
			t.Fatalf("shards=%d c=%d: %v", cfg.shards, cfg.concurrency, err)
		}
		rps := float64(total) / elapsed.Seconds()
		t.Logf("shards=%-3d c=%-5d %8s %10.0f req/s  conns=%-6d %.0f reqs/conn",
			cfg.shards, cfg.concurrency, elapsed.Round(time.Millisecond), rps, conns, float64(total)/float64(conns))
	}
}
