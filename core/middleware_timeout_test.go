package core

import (
	"sync"
	"testing"
	"time"
)

// TestTimeoutIsolatesRequestStore verifies the Timeout middleware gives the
// handler its own copy of the request store: upstream values are visible, but
// the handler's mutations do not leak back into the original request (which is
// pooled and reused — sharing the map would be a concurrent-map-write race).
func TestTimeoutIsolatesRequestStore(t *testing.T) {
	req := &Request{}
	req.Set("upstream", "v1") // as if set by an earlier middleware

	var sawUpstream any
	var sawOK bool
	handler := func(r *Request, _ *Response) {
		sawUpstream, sawOK = r.Get("upstream")
		r.Set("handler-only", "v2")
	}

	mw := Timeout(5 * time.Second)(handler)
	mw(req, &Response{})

	if !sawOK || sawUpstream != "v1" {
		t.Fatalf("handler did not see copied upstream store value: %v ok=%v", sawUpstream, sawOK)
	}
	if _, leaked := req.Get("handler-only"); leaked {
		t.Fatalf("handler store mutation leaked into the original (poolable) request")
	}
}

// TestTimeoutHandlerStoreNoRaceWithReusedReq exercises the original race: a
// handler that keeps running past the timeout while the caller resets and
// reuses the request. Run with -race.
func TestTimeoutHandlerStoreNoRaceWithReusedReq(t *testing.T) {
	req := &Request{}
	req.Set("seed", "x")

	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	handler := func(r *Request, _ *Response) {
		defer wg.Done()
		<-release // keep running until after the middleware returns
		for i := 0; i < 1000; i++ {
			r.Set("k", i) // must touch only tmpReq's own map
		}
	}

	mw := Timeout(time.Millisecond)(handler)
	mw(req, &Response{})

	// Middleware has timed out and returned; now hammer the original request
	// the way connection reuse would, concurrently with the still-running
	// handler. With shared maps this is a concurrent map write.
	close(release)
	for i := 0; i < 1000; i++ {
		req.Reset()
		req.Set("k", i)
	}
	wg.Wait()
}
