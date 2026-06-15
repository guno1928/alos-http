package core

import (
	"math/rand"
	"sync/atomic"
)

type loadBalancer interface {
	pick(backends []*backend, clientIP string) int
}

func newBalancer(typ LoadBalancerType, backends []*backend) loadBalancer {
	switch typ {
	case LBWeightedRR:
		return newWeightedRR(backends)
	case LBLeastConn:
		return &leastConnBalancer{}
	case LBIPHash:
		return &ipHashBalancer{}
	case LBRandom:
		return &randomBalancer{}
	default:
		return &roundRobinBalancer{}
	}
}

type roundRobinBalancer struct {
	counter atomic.Uint64
}

func (b *roundRobinBalancer) pick(backends []*backend, _ string) int {
	n := len(backends)
	if n == 0 {
		return -1
	}
	start := int(b.counter.Add(1) - 1)
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		if backends[idx].Healthy.Load() {
			return idx
		}
	}
	return -1
}

type weightedRRBalancer struct {
	indices []int
	counter atomic.Uint64
}

func newWeightedRR(backends []*backend) *weightedRRBalancer {
	var indices []int
	for i, b := range backends {
		weight := b.Weight
		if weight > 100 {
			weight = 100
		}
		for j := 0; j < weight; j++ {
			indices = append(indices, i)
		}
	}
	return &weightedRRBalancer{indices: indices}
}

func (b *weightedRRBalancer) pick(backends []*backend, _ string) int {
	n := len(b.indices)
	if n == 0 {
		return -1
	}
	start := int(b.counter.Add(1) - 1)
	for i := 0; i < n; i++ {
		idx := b.indices[(start+i)%n]
		if backends[idx].Healthy.Load() {
			return idx
		}
	}
	return -1
}

type leastConnBalancer struct{}

func (b *leastConnBalancer) pick(backends []*backend, _ string) int {
	best := -1
	var bestCount int64 = 1<<63 - 1
	for i, be := range backends {
		if !be.Healthy.Load() {
			continue
		}
		c := be.ActiveConns.Load()
		if c < bestCount {
			bestCount = c
			best = i
		}
	}
	return best
}

type ipHashBalancer struct{}

func (b *ipHashBalancer) pick(backends []*backend, clientIP string) int {
	n := len(backends)
	if n == 0 {
		return -1
	}
	h := StringHash(clientIP)
	start := int(h % uint64(n))
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		if backends[idx].Healthy.Load() {
			return idx
		}
	}
	return -1
}

type randomBalancer struct{}

func (b *randomBalancer) pick(backends []*backend, _ string) int {
	n := len(backends)
	if n == 0 {
		return -1
	}
	count := 0
	for i := 0; i < n; i++ {
		if backends[i].Healthy.Load() {
			count++
		}
	}
	if count == 0 {
		return -1
	}
	target := rand.Intn(count)
	for i := 0; i < n; i++ {
		if backends[i].Healthy.Load() {
			if target == 0 {
				return i
			}
			target--
		}
	}
	return -1
}
