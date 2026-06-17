package core

import (
	"strconv"
	"testing"
)

// unseededFNV is the original (pre-fix) shard-selection hash. The test uses it
// to forge an adversarial key set that all collides into one shard mod
// shardCount, exactly the funneling attack the seed is meant to defeat.
func unseededFNV(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// seededFNV mirrors StringHash but with an explicit seed, so the test can model
// two independent process seeds without depending on the package-global one.
func seededFNV(s string, seed uint64) uint64 {
	h := 14695981039346656037 ^ seed
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	h ^= seed
	h ^= h >> 30
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 27
	h *= 0x94d049bb133111eb
	h ^= h >> 31
	return h
}

// adversarialKeys returns keys whose unseeded FNV all land on the same shard,
// i.e. the worst case an attacker would aim for against the old hash.
func adversarialKeys(t *testing.T, target, count int) []string {
	t.Helper()
	keys := make([]string, 0, count)
	for i := 0; len(keys) < count; i++ {
		k := "atk-" + strconv.Itoa(i)
		if int(unseededFNV(k)%shardCount) == target {
			keys = append(keys, k)
		}
		if i > 1<<22 {
			t.Fatalf("could not forge %d colliding keys", count)
		}
	}
	return keys
}

func TestStringHashSeedDefeatsFunneling(t *testing.T) {
	const target = 0
	keys := adversarialKeys(t, target, 256)

	// Sanity: these keys really do all funnel to one shard under the old hash.
	for _, k := range keys {
		if got := int(unseededFNV(k) % shardCount); got != target {
			t.Fatalf("forged key %q maps to shard %d, want %d", k, got, target)
		}
	}

	// Under the seeded production hash they must spread across many shards.
	hits := make(map[int]int)
	for _, k := range keys {
		hits[int(StringHash(k)%shardCount)]++
	}
	if len(hits) < shardCount/4 {
		t.Fatalf("seeded hash funneled adversarial keys into %d/%d shards (max one shard %d hits)",
			len(hits), shardCount, maxCount(hits))
	}
	if hits[target] == len(keys) {
		t.Fatalf("seeded hash still funnels every adversarial key into shard %d", target)
	}
}

func TestStringHashDistinctSeedsDistributeDifferently(t *testing.T) {
	const seedA, seedB = 0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321
	keys := adversarialKeys(t, 0, 256)

	differing := 0
	for _, k := range keys {
		if seededFNV(k, seedA)%shardCount != seededFNV(k, seedB)%shardCount {
			differing++
		}
	}

	// Two independent process seeds must not produce identical shard mappings,
	// so an attacker cannot precompute a single funneling key set for all hosts.
	if differing == 0 {
		t.Fatal("distinct seeds produced identical shard assignment for all keys")
	}
}

func TestShardedMapBasicOps(t *testing.T) {
	m := NewShardedMap[string, int](StringHash)

	if _, ok := m.Load("missing"); ok {
		t.Fatal("Load on empty map returned ok")
	}

	m.Store("a", 1)
	if v, ok := m.Load("a"); !ok || v != 1 {
		t.Fatalf("Load(a) = %d,%v want 1,true", v, ok)
	}

	if v, loaded := m.LoadOrStore("a", 99); !loaded || v != 1 {
		t.Fatalf("LoadOrStore existing = %d,%v want 1,true", v, loaded)
	}
	if v, loaded := m.LoadOrStore("b", 2); loaded || v != 2 {
		t.Fatalf("LoadOrStore new = %d,%v want 2,false", v, loaded)
	}

	seen := make(map[string]int)
	m.Range(func(k string, v int) bool {
		seen[k] = v
		return true
	})
	if seen["a"] != 1 || seen["b"] != 2 || len(seen) != 2 {
		t.Fatalf("Range saw %v want {a:1 b:2}", seen)
	}

	m.Delete("a")
	if _, ok := m.Load("a"); ok {
		t.Fatal("Load(a) after Delete returned ok")
	}
}

func maxCount(m map[int]int) int {
	best := 0
	for _, c := range m {
		if c > best {
			best = c
		}
	}
	return best
}
