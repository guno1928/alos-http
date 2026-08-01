//go:build linux

package core

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

// TestUpstreamThreadScaling answers whether throughput grows with event loops.
// It requires an origin in a separate process, addressed by ORIGIN_ADDR, so
// the client is not competing with the origin inside one Go runtime.
func TestUpstreamThreadScaling(t *testing.T) {
	addr := os.Getenv("ORIGIN_ADDR")
	if addr == "" {
		t.Skip("set ORIGIN_ADDR to an out-of-process origin")
	}
	const total = 200000
	const concurrency = 512
	t.Logf("NumCPU=%d, origin=%s, %d requests, concurrency %d",
		runtime.NumCPU(), addr, total, concurrency)
	t.Logf("%-6s %-16s %10s %12s %10s", "loops", "loopsPerOrigin", "elapsed", "req/sec", "conns")

	var baseline float64
	for _, loops := range []int{1, 2, 4, 8, 12, 16} {
		client, err := NewUpstreamClient(UpstreamConfig{Loops: loops, LoopsPerOrigin: loops})
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
		client.Close()
		if err != nil {
			t.Fatalf("loops=%d: %v", loops, err)
		}
		rps := float64(total) / elapsed.Seconds()
		if loops == 1 {
			baseline = rps
		}
		t.Logf("%-6d %-16d %10s %12.0f  %5.2fx vs 1 loop",
			loops, loops, elapsed.Round(time.Millisecond), rps, rps/baseline)
	}
}
