package concurrency_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/guno1928/alos-http/core"
)

func TestConcurrentRouterLookup(t *testing.T) {
	router := core.NewRouter()
	for i := 0; i < 256; i++ {
		id := i
		router.GET(fmt.Sprintf("/resource/%d/:value", i), func(req *core.Request, resp *core.Response) {
			resp.String(fmt.Sprintf("%d:%s", id, req.ParamValue("value")))
		})
	}
	router.Build()
	var failures atomic.Int64
	var wg sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 512; i++ {
				route := (worker*512 + i) % 256
				value := fmt.Sprintf("w%d-i%d", worker, i)
				req := &core.Request{}
				handler := router.Lookup("GET", fmt.Sprintf("/resource/%d/%s", route, value), req)
				if handler == nil || req.ParamValue("value") != value {
					failures.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("concurrent lookup failures = %d", failures.Load())
	}
}

func TestConcurrentRequestHeaderReads(t *testing.T) {
	for round := 0; round < 16; round++ {
		round := round
		t.Run(fmt.Sprintf("round_%02d", round), func(t *testing.T) {
			var failures atomic.Int64
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					req := &core.Request{Headers: [][2]string{{"Content-Type", "application/json"}, {"Authorization", "Bearer token"}, {"X-Request-ID", fmt.Sprint(round)}}}
					if req.Header("Content-Type") != "application/json" || req.Header("Authorization") != "Bearer token" || req.Header("X-Request-ID") != fmt.Sprint(round) {
						failures.Add(1)
					}
				}()
			}
			wg.Wait()
			if failures.Load() != 0 {
				t.Fatalf("header read failures = %d", failures.Load())
			}
		})
	}
}
