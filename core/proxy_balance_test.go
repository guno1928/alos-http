package core

import (
	"fmt"
	"testing"
)

// backendsForBalance builds n healthy backends with the given weights. A nil
// weights slice leaves Weight at zero, which is what BackendConfig defaults to.
func backendsForBalance(weights ...int) []*backend {
	out := make([]*backend, len(weights))
	for i, w := range weights {
		b := &backend{Addr: fmt.Sprintf("10.0.0.%d:80", i+1), Weight: w}
		b.Healthy.Store(true)
		out[i] = b
	}
	return out
}

func pickCounts(lb loadBalancer, backends []*backend, clientIP string, rounds int) []int {
	counts := make([]int, len(backends))
	for i := 0; i < rounds; i++ {
		idx := lb.pick(backends, clientIP)
		if idx >= 0 {
			counts[idx]++
		}
	}
	return counts
}

// Round robin must cycle in order and distribute exactly evenly.
func TestBalancerRoundRobinIsExactlyEven(t *testing.T) {
	backends := backendsForBalance(1, 1, 1, 1)
	lb := newBalancer(LBRoundRobin, backends)

	// The order must be strictly sequential, not merely balanced.
	for i := 0; i < 8; i++ {
		want := i % len(backends)
		if got := lb.pick(backends, ""); got != want {
			t.Fatalf("pick %d = %d, want %d (round robin must cycle in order)", i, got, want)
		}
	}

	counts := pickCounts(lb, backends, "", 400)
	for i, c := range counts {
		if c != 100 {
			t.Errorf("backend %d received %d of 400 picks, want exactly 100: %v", i, c, counts)
		}
	}
}

// Round robin must skip unhealthy backends entirely.
func TestBalancerRoundRobinSkipsUnhealthy(t *testing.T) {
	backends := backendsForBalance(1, 1, 1)
	backends[1].Healthy.Store(false)
	lb := newBalancer(LBRoundRobin, backends)

	counts := pickCounts(lb, backends, "", 300)
	if counts[1] != 0 {
		t.Fatalf("an unhealthy backend received %d picks", counts[1])
	}
	if counts[0]+counts[2] != 300 {
		t.Fatalf("healthy backends received %d of 300 picks: %v", counts[0]+counts[2], counts)
	}
}

// With every backend down there is nothing to pick.
func TestBalancerReportsNoBackendWhenAllUnhealthy(t *testing.T) {
	for _, typ := range []LoadBalancerType{LBRoundRobin, LBWeightedRR, LBLeastConn, LBIPHash, LBRandom} {
		backends := backendsForBalance(1, 1, 1)
		for _, b := range backends {
			b.Healthy.Store(false)
		}
		lb := newBalancer(typ, backends)
		if got := lb.pick(backends, "1.2.3.4"); got != -1 {
			t.Errorf("balancer %d returned %d with every backend unhealthy, want -1", typ, got)
		}
	}
}

func TestBalancerHandlesEmptyBackendSet(t *testing.T) {
	for _, typ := range []LoadBalancerType{LBRoundRobin, LBWeightedRR, LBLeastConn, LBIPHash, LBRandom} {
		lb := newBalancer(typ, nil)
		if got := lb.pick(nil, "1.2.3.4"); got != -1 {
			t.Errorf("balancer %d returned %d for an empty backend set, want -1", typ, got)
		}
	}
}

// Weighted round robin must hand out traffic in proportion to Weight.
func TestBalancerWeightedRRMatchesWeights(t *testing.T) {
	backends := backendsForBalance(1, 3, 6)
	lb := newBalancer(LBWeightedRR, backends)

	const cycles = 100
	total := (1 + 3 + 6) * cycles
	counts := pickCounts(lb, backends, "", total)

	want := []int{1 * cycles, 3 * cycles, 6 * cycles}
	for i := range want {
		if counts[i] != want[i] {
			t.Fatalf("weighted distribution = %v, want %v", counts, want)
		}
	}
}

// A weight above the cap must not be able to starve the others.
func TestBalancerWeightedRRCapsWeightAt100(t *testing.T) {
	backends := backendsForBalance(1, 5000)
	lb := newBalancer(LBWeightedRR, backends)

	total := 101 * 10
	counts := pickCounts(lb, backends, "", total)
	if counts[0] != 10 {
		t.Fatalf("backend 0 received %d picks, want 10 (weight 5000 must clamp to 100): %v", counts[0], counts)
	}
	if counts[1] != 1000 {
		t.Fatalf("backend 1 received %d picks, want 1000: %v", counts[1], counts)
	}
}

// A backend with zero weight contributes no slots, so it is never chosen.
func TestBalancerWeightedRRIgnoresZeroWeight(t *testing.T) {
	backends := backendsForBalance(0, 2)
	lb := newBalancer(LBWeightedRR, backends)

	counts := pickCounts(lb, backends, "", 100)
	if counts[0] != 0 {
		t.Fatalf("a zero-weight backend received %d picks: %v", counts[0], counts)
	}
	if counts[1] != 100 {
		t.Fatalf("backend 1 received %d of 100 picks: %v", counts[1], counts)
	}
}

// Least-connections must always choose the backend with the fewest in flight.
func TestBalancerLeastConnChoosesFewest(t *testing.T) {
	backends := backendsForBalance(1, 1, 1)
	backends[0].ActiveConns.Store(7)
	backends[1].ActiveConns.Store(2)
	backends[2].ActiveConns.Store(5)
	lb := newBalancer(LBLeastConn, backends)

	if got := lb.pick(backends, ""); got != 1 {
		t.Fatalf("pick = %d, want 1 (fewest active connections)", got)
	}

	// Once it is the busiest, it must stop being chosen.
	backends[1].ActiveConns.Store(9)
	if got := lb.pick(backends, ""); got != 2 {
		t.Fatalf("pick = %d, want 2 after backend 1 became busiest", got)
	}
}

func TestBalancerLeastConnSkipsUnhealthy(t *testing.T) {
	backends := backendsForBalance(1, 1)
	backends[0].ActiveConns.Store(0)
	backends[0].Healthy.Store(false)
	backends[1].ActiveConns.Store(50)
	lb := newBalancer(LBLeastConn, backends)

	if got := lb.pick(backends, ""); got != 1 {
		t.Fatalf("pick = %d, want 1; an idle but unhealthy backend must not be chosen", got)
	}
}

// IP hash must be stable for one client and must spread different clients.
func TestBalancerIPHashIsStablePerClient(t *testing.T) {
	backends := backendsForBalance(1, 1, 1, 1)
	lb := newBalancer(LBIPHash, backends)

	first := lb.pick(backends, "203.0.113.9")
	for i := 0; i < 50; i++ {
		if got := lb.pick(backends, "203.0.113.9"); got != first {
			t.Fatalf("same client mapped to %d then %d; IP hash must be consistent", first, got)
		}
	}

	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		seen[lb.pick(backends, fmt.Sprintf("198.51.100.%d", i%256))] = true
	}
	if len(seen) < 2 {
		t.Fatalf("200 distinct client IPs all mapped to %v; IP hash is not spreading", seen)
	}
}

// When a client's chosen backend is down the request must fall through to a
// healthy one rather than fail.
func TestBalancerIPHashFallsThroughWhenTargetDown(t *testing.T) {
	backends := backendsForBalance(1, 1, 1)
	lb := newBalancer(LBIPHash, backends)

	const ip = "203.0.113.9"
	target := lb.pick(backends, ip)
	backends[target].Healthy.Store(false)

	got := lb.pick(backends, ip)
	if got == target {
		t.Fatal("IP hash kept selecting a backend it had just marked unhealthy")
	}
	if got < 0 {
		t.Fatal("IP hash gave up instead of falling through to a healthy backend")
	}
}

// Random must only ever return healthy backends, and must use more than one.
func TestBalancerRandomStaysHealthyAndSpreads(t *testing.T) {
	backends := backendsForBalance(1, 1, 1, 1)
	backends[2].Healthy.Store(false)
	lb := newBalancer(LBRandom, backends)

	counts := pickCounts(lb, backends, "", 600)
	if counts[2] != 0 {
		t.Fatalf("random picked an unhealthy backend %d times", counts[2])
	}
	used := 0
	for i, c := range counts {
		if i != 2 && c > 0 {
			used++
		}
	}
	if used < 2 {
		t.Fatalf("random only ever used %d backend(s): %v", used, counts)
	}
}

// An unknown strategy must fall back to round robin rather than misbehave.
func TestBalancerUnknownTypeFallsBackToRoundRobin(t *testing.T) {
	backends := backendsForBalance(1, 1, 1)
	lb := newBalancer(LoadBalancerType(200), backends)

	counts := pickCounts(lb, backends, "", 300)
	for i, c := range counts {
		if c != 100 {
			t.Fatalf("unknown strategy did not behave as round robin: backend %d got %d: %v", i, c, counts)
		}
	}
}
