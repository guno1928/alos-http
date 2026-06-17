package core

import (
	"sync"
	"testing"
	"time"
)

// TestEvictOldestSingleFlight verifies the eviction pass is single-flight: while
// one pass is in flight, concurrent calls return immediately and do not clear
// the in-flight flag they don't own.
func TestEvictOldestSingleFlight(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{MaxTotalBytes: 1, MaxEntrySize: 1 << 20})

	pc.evicting.Store(true) // simulate an eviction pass already running
	done := make(chan struct{})
	go func() { pc.evictOldest(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("evictOldest blocked while another pass was in flight")
	}
	if !pc.evicting.Load() {
		t.Fatal("a no-op evictOldest cleared the in-flight flag it did not own")
	}

	pc.evicting.Store(false)
	pc.evictOldest()
	if pc.evicting.Load() {
		t.Fatal("evictOldest did not clear the flag after running")
	}
}

// TestEvictOldestConcurrent runs many eviction passes concurrently; with the
// single-flight guard this must be race-free and leave the flag cleared. Run -race.
func TestEvictOldestConcurrent(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{MaxTotalBytes: 1, MaxEntrySize: 1 << 20})
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); pc.evictOldest() }()
	}
	wg.Wait()
	if pc.evicting.Load() {
		t.Fatal("evicting flag left set after concurrent passes")
	}
}

func BenchmarkEvictOldestGuard(b *testing.B) {
	pc := NewProxyCache(ProxyCacheConfig{MaxTotalBytes: 1 << 30, MaxEntrySize: 1 << 20})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pc.evictOldest()
	}
}
