package core

import (
	"strconv"
	"testing"
)

// TestSeededShardIndexRange ensures the index stays within bounds.
func TestSeededShardIndexRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		if idx := seededShardIndex(uint64(i) * 0x100000001b3); idx >= shardCount {
			t.Fatalf("seededShardIndex out of range: %d", idx)
		}
	}
}

// TestSeededShardIndexSpread confirms many distinct keys spread across shards
// rather than funneling into one (the M1 DoS). A set of keys an attacker would
// pick to collide modulo shardCount under the raw FNV hash must not collide
// once the per-process seed + finalizer are applied.
func TestSeededShardIndexSpread(t *testing.T) {
	hits := make(map[uint64]int)
	for i := 0; i < 10000; i++ {
		hits[seededShardIndex(StringHash(strconv.Itoa(i)))]++
	}
	if len(hits) < shardCount*3/4 {
		t.Fatalf("keys funneled into %d/%d shards", len(hits), shardCount)
	}
	// Raw multiples of shardCount would all map to shard 0 without the seed.
	raw := make(map[uint64]int)
	for i := 0; i < 2048; i++ {
		raw[seededShardIndex(uint64(i)*shardCount)]++
	}
	if len(raw) < shardCount/2 {
		t.Fatalf("multiples-of-shardCount funneled into %d/%d shards", len(raw), shardCount)
	}
}

// TestShardedMapStoreLoadConsistent ensures seeding keeps Store/Load on the
// same shard within the process.
func TestShardedMapStoreLoadConsistent(t *testing.T) {
	m := NewShardedMap[string, int](StringHash)
	for i := 0; i < 500; i++ {
		m.Store(strconv.Itoa(i), i)
	}
	for i := 0; i < 500; i++ {
		if v, ok := m.Load(strconv.Itoa(i)); !ok || v != i {
			t.Fatalf("Load(%d) = %d,%v", i, v, ok)
		}
	}
}

func BenchmarkSeededShardIndex(b *testing.B) {
	h := StringHash("198.51.100.23")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = seededShardIndex(h)
	}
}
