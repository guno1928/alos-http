//go:build linux

package core

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	benchRequests   = 4000
	benchConcurrent = 64
)

func benchOrigin(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var accepted atomic.Int64
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &accepted
}

func driveConcurrent(fn func(i int) error) (time.Duration, error) {
	var wg sync.WaitGroup
	work := make(chan int, benchConcurrent)
	errCh := make(chan error, benchConcurrent)
	start := time.Now()
	for range benchConcurrent {
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
	for i := range benchRequests {
		work <- i
	}
	close(work)
	wg.Wait()
	elapsed := time.Since(start)
	close(errCh)
	if err := <-errCh; err != nil {
		return elapsed, err
	}
	return elapsed, nil
}

func TestUpstreamThroughputVersusStdlib(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput comparison")
	}

	type result struct {
		name    string
		elapsed time.Duration
		conns   int64
	}
	var results []result

	{
		srv, accepted := benchOrigin(t)
		client := &http.Client{Timeout: 30 * time.Second}
		elapsed, err := driveConcurrent(func(i int) error {
			resp, err := client.Get(fmt.Sprintf("%s/r%d", srv.URL, i))
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			return resp.Body.Close()
		})
		if err != nil {
			t.Fatalf("stdlib default: %v", err)
		}
		results = append(results, result{"stdlib http.Client (DefaultTransport)", elapsed, accepted.Load()})
	}

	{
		srv, accepted := benchOrigin(t)
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.MaxIdleConns = 512
		tr.MaxIdleConnsPerHost = 256
		tr.IdleConnTimeout = 90 * time.Second
		client := &http.Client{Timeout: 30 * time.Second, Transport: tr}
		elapsed, err := driveConcurrent(func(i int) error {
			resp, err := client.Get(fmt.Sprintf("%s/r%d", srv.URL, i))
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			return resp.Body.Close()
		})
		if err != nil {
			t.Fatalf("stdlib tuned: %v", err)
		}
		results = append(results, result{"stdlib http.Client (tuned Transport)", elapsed, accepted.Load()})
	}

	{
		srv, accepted := benchOrigin(t)
		authority := srv.URL[len("http://"):]
		client, err := NewUpstreamClient(UpstreamConfig{})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		elapsed, err := driveConcurrent(func(i int) error {
			resp, err := client.Do(&UpstreamRequest{
				Scheme:    "http",
				Authority: authority,
				Method:    "GET",
				Path:      fmt.Sprintf("/r%d", i),
			})
			if err != nil {
				return err
			}
			if resp.Status != 200 {
				return fmt.Errorf("status %d", resp.Status)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("epoll upstream: %v", err)
		}
		results = append(results, result{"alos-http epoll UpstreamClient", elapsed, accepted.Load()})
	}

	t.Logf("%d requests, concurrency %d, 1 KiB responses", benchRequests, benchConcurrent)
	t.Logf("%-40s %12s %14s %10s", "client", "elapsed", "req/sec", "TCP conns")
	for _, r := range results {
		rps := float64(benchRequests) / r.elapsed.Seconds()
		t.Logf("%-40s %12s %14.0f %10d", r.name, r.elapsed.Round(time.Millisecond), rps, r.conns)
	}
}

// A CDN serves many origins. Origin affinity pins each origin to one event
// loop, so throughput should scale with the number of distinct origins even
// though a single origin is confined to one loop.
func TestUpstreamThroughputAcrossManyOrigins(t *testing.T) {
	if testing.Short() {
		t.Skip("throughput comparison")
	}
	const origins = 8
	var servers []*httptest.Server
	var counters []*atomic.Int64
	for range origins {
		srv, accepted := benchOrigin(t)
		servers = append(servers, srv)
		counters = append(counters, accepted)
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns = 512
	tr.MaxIdleConnsPerHost = 256
	stdClient := &http.Client{Timeout: 30 * time.Second, Transport: tr}
	stdElapsed, err := driveConcurrent(func(i int) error {
		srv := servers[i%origins]
		resp, err := stdClient.Get(fmt.Sprintf("%s/r%d", srv.URL, i))
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.Body.Close()
	})
	if err != nil {
		t.Fatalf("stdlib tuned: %v", err)
	}

	client, err := NewUpstreamClient(UpstreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	authorities := make([]string, origins)
	for i, srv := range servers {
		authorities[i] = srv.URL[len("http://"):]
	}
	epollElapsed, err := driveConcurrent(func(i int) error {
		resp, err := client.Do(&UpstreamRequest{
			Scheme:    "http",
			Authority: authorities[i%origins],
			Method:    "GET",
			Path:      fmt.Sprintf("/r%d", i),
		})
		if err != nil {
			return err
		}
		if resp.Status != 200 {
			return fmt.Errorf("status %d", resp.Status)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("epoll upstream: %v", err)
	}

	var totalConns int64
	for _, c := range counters {
		totalConns += c.Load()
	}
	t.Logf("%d requests across %d origins, concurrency %d", benchRequests, origins, benchConcurrent)
	t.Logf("stdlib tuned : %8s  %9.0f req/sec", stdElapsed.Round(time.Millisecond), float64(benchRequests)/stdElapsed.Seconds())
	t.Logf("epoll client : %8s  %9.0f req/sec", epollElapsed.Round(time.Millisecond), float64(benchRequests)/epollElapsed.Seconds())
	t.Logf("total TCP conns opened across both runs: %d", totalConns)
}
