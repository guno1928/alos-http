package core

import (
	crand "crypto/rand"
	"encoding/binary"
	"sync"
)

const shardCount = 64

// hashSeed randomizes shard/slot selection per process. The shards are native
// (runtime-seeded) Go maps, so there is no intra-map bucket blowup; the risk is
// an attacker precomputing keys that all collide mod shardCount, funneling every
// entry into one shard's lock and collapsing the 64-way sharding to a single
// mutex (contention DoS). Mixing an unpredictable per-process seed into the
// FNV-1a accumulator makes the shard index unguessable. This is in-memory shard
// selection only; the seed must NOT leak into anything persisted or on the wire.
var hashSeed = func() uint64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		// Fail closed: a predictable seed reintroduces the funneling vector, so
		// refuse to start rather than serve with a guessable shard mapping.
		panic("core: failed to read crypto/rand for hash seed: " + err.Error())
	}
	return binary.LittleEndian.Uint64(b[:])
}()

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
	h := 14695981039346656037 ^ hashSeed
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	// FNV-1a alone has weak low bits: keys forged to collide mod shardCount stay
	// collided even after XORing a seed into the accumulator, because the prime
	// multiply only propagates low bits upward. Fold the seed back in and run a
	// splitmix64 finalizer so every output bit (including the low 6 used for the
	// shard index) avalanches over all input bits and the seed.
	h ^= hashSeed
	h ^= h >> 30
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 27
	h *= 0x94d049bb133111eb
	h ^= h >> 31
	return h
}

func Uint32Hash(v uint32) uint64 {
	x := uint64(v)
	x = ((x >> 16) ^ x) * 0x45d9f3b
	x = ((x >> 16) ^ x) * 0x45d9f3b
	x = (x >> 16) ^ x
	return x
}
