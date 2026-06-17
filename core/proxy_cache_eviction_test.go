package core

import (
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestEvictionSingleFlight hammers the cache with many concurrent over-limit
// inserts and asserts that the single-flight guard keeps the number of
// eviction passes bounded (not one pass per over-limit insert) while still
// converging the cache under MaxTotalBytes (H8).
func TestEvictionSingleFlight(t *testing.T) {
	const (
		maxBytes  = 64 * 1024
		bodyLen   = 4 * 1024
		writers   = 32
		perWriter = 200
	)

	cfg := DefaultProxyCacheConfig()
	cfg.MaxTotalBytes = maxBytes
	cfg.MaxEntries = 1 << 30 // isolate the byte-pressure eviction path
	cfg.MaxEntrySize = bodyLen
	cfg.PreCompress = false // keep sizes deterministic
	pc := NewProxyCache(cfg)
	defer pc.Stop()

	body := make([]byte, bodyLen)
	headers := [][2]string{{"content-type", "application/octet-stream"}}

	totalInserts := writers * perWriter

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				path := "/obj/" + strconv.Itoa(id) + "/" + strconv.Itoa(i)
				pc.PutManual("GET", "example.com", path, 200, headers,
					"application/octet-stream", body, time.Minute, 0, false, -1)
			}
		}(w)
	}
	wg.Wait()

	// Let any in-flight eviction drain to completion.
	deadline := time.Now().Add(5 * time.Second)
	for pc.evicting.Load() && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if pc.evicting.Load() {
		t.Fatal("eviction flag still set after storm: eviction did not complete")
	}

	// Single-flight invariant: each over-limit insert spawned its own full
	// O(N log N) pass before the fix, so passes would track totalInserts
	// (thousands). With single-flight + a draining loop, passes are bounded by
	// flag transitions, which is a small constant regardless of insert volume.
	passes := pc.evictionPasses.Load()
	if passes >= uint64(totalInserts/2) {
		t.Fatalf("eviction not single-flighted: passes=%d for %d over-limit inserts", passes, totalInserts)
	}
	if passes == 0 {
		t.Fatal("expected at least one eviction pass under byte pressure")
	}

	_, totalBytes, _, _ := pc.Stats()
	if totalBytes > maxBytes {
		t.Fatalf("cache did not converge under limit: totalBytes=%d maxBytes=%d", totalBytes, maxBytes)
	}
}

// TestTriggerEvictionSingleFlight asserts triggerEviction spawns at most one
// eviction at a time: concurrent calls while one is in flight are no-ops.
func TestTriggerEvictionSingleFlight(t *testing.T) {
	cfg := DefaultProxyCacheConfig()
	cfg.MaxTotalBytes = 1 << 20
	pc := NewProxyCache(cfg)
	defer pc.Stop()

	// Simulate an eviction already running by holding the flag.
	if !pc.evicting.CompareAndSwap(false, true) {
		t.Fatal("evicting flag should start clear")
	}

	passesBefore := pc.evictionPasses.Load()
	for i := 0; i < 64; i++ {
		pc.triggerEviction() // must all be no-ops while flag is set
	}
	runtime.Gosched()
	time.Sleep(20 * time.Millisecond)

	if got := pc.evictionPasses.Load(); got != passesBefore {
		t.Fatalf("triggerEviction ran an eviction while one was in flight: passes %d -> %d", passesBefore, got)
	}

	pc.evicting.Store(false)
}

// TestEvictionConvergesUnderConcurrentInserts verifies the drain loop inside a
// single eviction pass keeps reducing the cache even when inserts continue to
// arrive during eviction.
func TestEvictionConvergesUnderConcurrentInserts(t *testing.T) {
	const (
		maxBytes = 32 * 1024
		bodyLen  = 2 * 1024
	)

	cfg := DefaultProxyCacheConfig()
	cfg.MaxTotalBytes = maxBytes
	cfg.MaxEntries = 1 << 30
	cfg.MaxEntrySize = bodyLen
	cfg.PreCompress = false
	pc := NewProxyCache(cfg)
	defer pc.Stop()

	body := make([]byte, bodyLen)
	headers := [][2]string{{"content-type", "application/octet-stream"}}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			i := 0
			for {
				select {
				case <-stop:
					return
				default:
					path := "/c/" + strconv.Itoa(id) + "/" + strconv.Itoa(i)
					pc.PutManual("GET", "example.com", path, 200, headers,
						"application/octet-stream", body, time.Minute, 0, false, -1)
					i++
				}
			}
		}(w)
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for pc.evicting.Load() && time.Now().Before(deadline) {
		runtime.Gosched()
	}

	_, totalBytes, _, _ := pc.Stats()
	if totalBytes > maxBytes {
		t.Fatalf("cache did not converge under sustained load: totalBytes=%d maxBytes=%d", totalBytes, maxBytes)
	}
}
