//go:build linux

package core

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// countingOrigin reports how many distinct TCP connections it accepted, which
// is the only honest measure of whether the pool is reusing connections.
func countingOrigin(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var accepted atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
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

func authorityOf(t *testing.T, rawURL string) string {
	t.Helper()
	return rawURL[len("http://"):]
}

// Pinned to a single loop, a stream of requests must ride one connection.
func TestOriginPoolReusesConnectionsAcrossManyRequests(t *testing.T) {
	srv, accepted := countingOrigin(t)
	client, err := NewUpstreamClient(UpstreamConfig{LoopsPerOrigin: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	const requests = 200
	for i := range requests {
		resp, err := client.Do(&UpstreamRequest{
			Scheme:    "http",
			Authority: authorityOf(t, srv.URL),
			Method:    "GET",
			Path:      fmt.Sprintf("/visitor-%d", i),
		})
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if resp.Status != 200 {
			t.Fatalf("request %d: status %d", i, resp.Status)
		}
	}

	conns := accepted.Load()
	t.Logf("%d sequential requests opened %d TCP connections", requests, conns)
	if conns != 1 {
		t.Errorf("sequential requests to one origin should reuse a single connection, opened %d", conns)
	}
}

// Sharding an origin across several loops trades a bounded number of extra
// connections for parallelism, but each connection must still carry many
// requests rather than being dialled per request.
func TestShardedOriginStillReusesConnections(t *testing.T) {
	srv, accepted := countingOrigin(t)
	const shards = 4
	client, err := NewUpstreamClient(UpstreamConfig{LoopsPerOrigin: shards})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	const requests = 400
	for i := range requests {
		if _, err := client.Do(&UpstreamRequest{
			Scheme: "http", Authority: authorityOf(t, srv.URL), Method: "GET",
			Path: fmt.Sprintf("/r%d", i),
		}); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	conns := accepted.Load()
	t.Logf("%d sequential requests across %d shards opened %d connections (%.0f reqs/conn)",
		requests, shards, conns, float64(requests)/float64(conns))
	if conns > shards {
		t.Errorf("sequential requests opened %d connections, expected at most %d", conns, shards)
	}
}

// The pool must be keyed by origin, not by caller, so concurrent visitors
// share connections instead of each opening their own.
func TestOriginPoolIsSharedAcrossConcurrentVisitors(t *testing.T) {
	srv, accepted := countingOrigin(t)
	client, err := NewUpstreamClient(UpstreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	const visitors = 32
	const perVisitor = 20
	var wg sync.WaitGroup
	errs := make(chan error, visitors)
	for v := range visitors {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			for i := range perVisitor {
				resp, err := client.Do(&UpstreamRequest{
					Scheme:    "http",
					Authority: authorityOf(t, srv.URL),
					Method:    "GET",
					Path:      fmt.Sprintf("/v%d-r%d", v, i),
				})
				if err != nil {
					errs <- err
					return
				}
				if resp.Status != 200 {
					errs <- fmt.Errorf("status %d", resp.Status)
					return
				}
			}
		}(v)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("visitor request failed: %v", err)
	}

	total := visitors * perVisitor
	conns := accepted.Load()
	reqsPerConn := float64(total) / float64(conns)
	t.Logf("%d requests from %d concurrent visitors opened %d TCP connections (%.1f reqs/conn)",
		total, visitors, conns, reqsPerConn)

	// A connection can only serve one request at a time, so the floor is the
	// number of simultaneous visitors; sharding and churn allow some headroom
	// above that. What must never happen is a dial per request.
	if conns > int64(visitors)*3 {
		t.Errorf("opened %d connections for %d concurrent visitors; pool is not bounded", conns, visitors)
	}
	if reqsPerConn < 5 {
		t.Errorf("only %.1f requests per connection; connections are not being reused", reqsPerConn)
	}
}

// Distinct origins must not collide onto one pooled connection.
func TestSeparateOriginsDoNotShareConnections(t *testing.T) {
	a, acceptedA := countingOrigin(t)
	b, acceptedB := countingOrigin(t)
	client, err := NewUpstreamClient(UpstreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	for range 10 {
		for _, srv := range []*httptest.Server{a, b} {
			if _, err := client.Do(&UpstreamRequest{
				Scheme:    "http",
				Authority: authorityOf(t, srv.URL),
				Method:    "GET",
				Path:      "/",
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if acceptedA.Load() == 0 || acceptedB.Load() == 0 {
		t.Fatal("both origins should have been contacted")
	}
	t.Logf("origin A opened %d conns, origin B opened %d conns", acceptedA.Load(), acceptedB.Load())
}
