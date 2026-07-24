package core

import (
	"sync"

	"github.com/zeebo/xxh3"
)

const shardCount = 64

type mapShard[K comparable, V any] struct {
	mu sync.RWMutex
	m  map[K]V
	_  [CacheLineSize - 32]byte
}

// ShardedMap is a concurrent map[K]V split across a fixed number of shards,
// each guarded by its own RWMutex, to reduce lock contention under
// concurrent access. Keys are routed to shards using the hasher supplied to
// NewShardedMap. The zero value is not usable; construct one with
// NewShardedMap.
type ShardedMap[K comparable, V any] struct {
	shards [shardCount]mapShard[K, V]
	hasher func(K) uint64
}

// NewShardedMap returns an empty ShardedMap that routes keys to shards using
// hasher.
//
// Example: m := NewShardedMap[string, int](StringHash)
func NewShardedMap[K comparable, V any](hasher func(K) uint64) *ShardedMap[K, V] {
	sm := &ShardedMap[K, V]{hasher: hasher}
	for i := range sm.shards {
		sm.shards[i].m = make(map[K]V)
	}
	return sm
}

func (s *ShardedMap[K, V]) shard(key K) *mapShard[K, V] {
	return &s.shards[s.hasher(key)%shardCount]
}

// Store sets the value for key, overwriting any existing value.
func (s *ShardedMap[K, V]) Store(key K, val V) {
	sh := s.shard(key)
	sh.mu.Lock()
	sh.m[key] = val
	sh.mu.Unlock()
}

// Load returns the value stored for key and whether it was present.
func (s *ShardedMap[K, V]) Load(key K) (V, bool) {
	sh := s.shard(key)
	sh.mu.RLock()
	v, ok := sh.m[key]
	sh.mu.RUnlock()
	return v, ok
}

// LoadOrStore returns the existing value for key if present. Otherwise it
// stores val and returns it. The second return value reports whether the
// value already existed.
func (s *ShardedMap[K, V]) LoadOrStore(key K, val V) (V, bool) {
	sh := s.shard(key)
	sh.mu.Lock()
	if existing, ok := sh.m[key]; ok {
		sh.mu.Unlock()
		return existing, true
	}
	sh.m[key] = val
	sh.mu.Unlock()
	return val, false
}

// Delete removes key from the map, if present.
func (s *ShardedMap[K, V]) Delete(key K) {
	sh := s.shard(key)
	sh.mu.Lock()
	delete(sh.m, key)
	sh.mu.Unlock()
}

// Range calls fn for each key/value pair in the map, stopping early if fn
// returns false. The traversal is not a consistent snapshot: each shard is
// locked and iterated independently, so concurrent writes may be reflected
// in one shard but not another.
func (s *ShardedMap[K, V]) Range(fn func(K, V) bool) {
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.RLock()
		for k, v := range sh.m {
			if !fn(k, v) {
				sh.mu.RUnlock()
				return
			}
		}
		sh.mu.RUnlock()
	}
}

// StringHash returns a fast, non-cryptographic hash of s, suitable for use
// as the hasher passed to NewShardedMap.
func StringHash(s string) uint64 {
	return xxh3.HashString(s)
}

// Uint32Hash returns a fast, non-cryptographic hash of v, suitable for use
// as the hasher passed to NewShardedMap.
func Uint32Hash(v uint32) uint64 {
	x := uint64(v)
	x = ((x >> 16) ^ x) * 0x45d9f3b
	x = ((x >> 16) ^ x) * 0x45d9f3b
	x = (x >> 16) ^ x
	return x
}
