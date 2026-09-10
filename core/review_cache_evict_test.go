package core

import (
	"strconv"
	"testing"
	"time"
)

func TestResponseCacheOverflowEvictionScales(t *testing.T) {
	rc := NewResponseCache(CacheConfig{MaxEntries: 1000, SweepInterval: time.Hour})
	defer rc.Stop()
	const entries = 60000
	for i := 0; i < entries; i++ {
		rc.store.Store("k"+strconv.Itoa(i), &cachedResponse{storedAtNs: int64(entries - i), expiresAtNs: 1 << 62})
	}
	start := time.Now()
	rc.evictOverflow()
	elapsed := time.Since(start)
	if rc.Len() != 1000 {
		t.Fatalf("len after eviction = %d, want 1000", rc.Len())
	}
	if _, ok := rc.store.Load("k0"); !ok {
		t.Fatal("newest entry was evicted instead of the oldest")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("evicting %d entries took %v (quadratic sort)", entries, elapsed)
	}
}
