package core

import (
	"sync"
	"testing"
	"time"
)

// TestTimeoutIsolatesQueryFormCache ensures the Timeout middleware does not
// share the query/form caches with the detached handler goroutine (the owner's
// fix cloned store but left these aliased -> concurrent-map race).
func TestTimeoutIsolatesQueryFormCache(t *testing.T) {
	req := &Request{Query: "a=1", Body: []byte("b=2"), Method: "POST",
		Headers: [][2]string{{"content-type", "application/x-www-form-urlencoded"}}}
	_ = req.QueryParams() // populate req.queryCache

	var handlerQC map[string][]string
	handler := func(r *Request, _ *Response) {
		handlerQC = r.queryCache
	}
	Timeout(5*time.Second)(handler)(req, &Response{})

	req.queryCache["__sentinel__"] = []string{"x"}
	if _, shared := handlerQC["__sentinel__"]; shared {
		t.Fatal("Timeout handler shares queryCache map with the original request")
	}
}

// TestTimeoutHandlerCacheNoRace exercises the race directly: a handler that
// keeps running past the timeout while the original request is reset/reused.
// Run with -race.
func TestTimeoutHandlerCacheNoRace(t *testing.T) {
	req := &Request{Query: "a=1"}
	_ = req.QueryParams()

	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	handler := func(r *Request, _ *Response) {
		defer wg.Done()
		<-release
		for i := 0; i < 1000; i++ {
			_ = r.QueryParams() // touches only tmpReq's own (nil->reparsed) cache
		}
	}

	Timeout(time.Millisecond)(handler)(req, &Response{})

	close(release)
	for i := 0; i < 1000; i++ {
		req.Reset()
		req.Query = "a=1"
		_ = req.QueryParams()
	}
	wg.Wait()
}

// BenchmarkTimeoutMiddleware measures the per-request overhead of the Timeout
// wrapper (the request-copy + map handling path).
func BenchmarkTimeoutMiddleware(b *testing.B) {
	h := Timeout(5 * time.Second)(func(_ *Request, _ *Response) {})
	req := &Request{Query: "a=1", Headers: [][2]string{{"x", "y"}}}
	resp := &Response{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h(req, resp)
	}
}
