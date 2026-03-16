package core

import "sync"

const shardCount = 64

type mapShard[K comparable, V any] struct {
	mu sync.RWMutex
	m  map[K]V
	_  [CacheLineSize - 32]byte
}

type ShardedMap[K comparable, V any] struct {
	shards [shardCount]mapShard[K, V]
	hasher func(K) uint64
}

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

func (s *ShardedMap[K, V]) Store(key K, val V) {
	sh := s.shard(key)
	sh.mu.Lock()
	sh.m[key] = val
	sh.mu.Unlock()
}

func (s *ShardedMap[K, V]) Load(key K) (V, bool) {
	sh := s.shard(key)
	sh.mu.RLock()
	v, ok := sh.m[key]
	sh.mu.RUnlock()
	return v, ok
}

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

func (s *ShardedMap[K, V]) Delete(key K) {
	sh := s.shard(key)
	sh.mu.Lock()
	delete(sh.m, key)
	sh.mu.Unlock()
}

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

func StringHash(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

func Uint32Hash(v uint32) uint64 {
	x := uint64(v)
	x = ((x >> 16) ^ x) * 0x45d9f3b
	x = ((x >> 16) ^ x) * 0x45d9f3b
	x = (x >> 16) ^ x
	return x
}
