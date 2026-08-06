package memory_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/guno1928/alos-http/core"
)

var memorySinkHandler core.HandlerFunc
var memorySinkBytes []byte

func buildRouter(count int) *core.Router {
	router := core.NewRouter()
	for i := 0; i < count; i++ {
		router.GET(fmt.Sprintf("/route/%d/:id", i), func(_ *core.Request, _ *core.Response) {})
	}
	router.Build()
	return router
}

func TestHighCardinalityRoutingHasNoAdmissionCeiling(t *testing.T) {
	const routes = 20000
	router := buildRouter(routes)
	for _, index := range []int{0, 1, 255, 1024, 4095, 8191, 16383, routes - 1} {
		req := &core.Request{}
		handler := router.Lookup("GET", fmt.Sprintf("/route/%d/value-%d", index, index), req)
		if handler == nil || req.ParamValue("id") != fmt.Sprintf("value-%d", index) {
			t.Fatalf("route %d unavailable after high-cardinality build", index)
		}
	}
}

func TestRequestResetDropsOversizedRetainedBuffers(t *testing.T) {
	for i := 0; i < 24; i++ {
		t.Run(fmt.Sprintf("size_%02d", i), func(t *testing.T) {
			req := &core.Request{Body: make([]byte, 1<<20+i*4096), Headers: make([][2]string, 256)}
			req.Reset()
			if len(req.Body) != 0 || cap(req.Body) > 1024 {
				t.Fatalf("body retained len=%d cap=%d", len(req.Body), cap(req.Body))
			}
			if len(req.Headers) != 0 || cap(req.Headers) > 16 {
				t.Fatalf("headers retained len=%d cap=%d", len(req.Headers), cap(req.Headers))
			}
		})
	}
}

func TestHTTP2FrameReuseAllocationBudget(t *testing.T) {
	payload := []byte(strings.Repeat("p", 1024))
	dst := make([]byte, 0, 9+len(payload))
	allocs := testing.AllocsPerRun(1000, func() {
		memorySinkBytes = core.H2WriteFrame(dst, core.H2FrameData, 0, 1, payload)
	})
	if allocs != 0 {
		t.Fatalf("H2WriteFrame allocations/run = %.2f, want 0", allocs)
	}
}

func TestRouterLookupAllocationBudget(t *testing.T) {
	router := buildRouter(256)
	allocs := testing.AllocsPerRun(1000, func() {
		req := &core.Request{}
		memorySinkHandler = router.Lookup("GET", "/route/128/value", req)
	})
	if allocs > 1 {
		t.Fatalf("Router.Lookup allocations/run = %.2f, want <= 1", allocs)
	}
}

func TestHighCardinalityHeapRecovery(t *testing.T) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	func() {
		router := buildRouter(12000)
		for i := 0; i < 12000; i += 127 {
			memorySinkHandler = router.Lookup("GET", fmt.Sprintf("/route/%d/value", i), &core.Request{})
		}
	}()
	memorySinkHandler = nil
	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.HeapAlloc > before.HeapAlloc+32<<20 {
		t.Fatalf("heap did not recover: before=%d after=%d", before.HeapAlloc, after.HeapAlloc)
	}
}

func BenchmarkRouterLookup(b *testing.B) {
	router := buildRouter(4096)
	req := &core.Request{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.ParamCount = 0
		memorySinkHandler = router.Lookup("GET", "/route/2048/value", req)
	}
}

func BenchmarkHTTP2FrameWrite(b *testing.B) {
	payload := make([]byte, 4096)
	dst := make([]byte, 0, 9+len(payload))
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		memorySinkBytes = core.H2WriteFrame(dst, core.H2FrameData, 0, 1, payload)
	}
}

func BenchmarkRequestResetExpected(b *testing.B) {
	req := &core.Request{Headers: make([][2]string, 0, 16), Body: make([]byte, 0, 1024)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req.Headers = append(req.Headers, [2]string{"Content-Type", "application/json"})
		req.Body = append(req.Body, "payload"...)
		req.Reset()
	}
}

func BenchmarkRequestResetPeak(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := &core.Request{Headers: make([][2]string, 256), Body: make([]byte, 1<<20)}
		req.Reset()
		memorySinkBytes = req.Body
	}
}
