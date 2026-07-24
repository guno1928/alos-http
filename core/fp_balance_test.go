//go:build linux

package core

import "testing"

func fpTestGroup(lb LoadBalancerType, weights []int) *backendGroup {
	g := &backendGroup{lb: lb}
	for _, w := range weights {
		b := &fpBackend{weight: w}
		b.healthy.Store(true)
		g.backends = append(g.backends, b)
	}
	if lb == LBWeightedRR {
		for i, b := range g.backends {
			for j := 0; j < b.weight; j++ {
				g.weightedIndices = append(g.weightedIndices, i)
			}
		}
	}
	return g
}

func fpIndexOf(g *backendGroup, be *fpBackend) int {
	for i, b := range g.backends {
		if b == be {
			return i
		}
	}
	return -1
}

func TestFPRoundRobin(t *testing.T) {
	g := fpTestGroup(LBRoundRobin, []int{1, 1, 1})
	counts := make([]int, 3)
	for i := 0; i < 300; i++ {
		counts[fpIndexOf(g, g.pick(""))]++
	}
	for i, c := range counts {
		if c != 100 {
			t.Fatalf("roundrobin backend %d got %d, want 100", i, c)
		}
	}
}

func TestFPWeighted(t *testing.T) {
	g := fpTestGroup(LBWeightedRR, []int{3, 1})
	counts := make([]int, 2)
	for i := 0; i < 400; i++ {
		counts[fpIndexOf(g, g.pick(""))]++
	}
	if counts[0] != 300 || counts[1] != 100 {
		t.Fatalf("weighted 3:1 got %d:%d, want 300:100", counts[0], counts[1])
	}
}

func TestFPLeastConn(t *testing.T) {
	g := fpTestGroup(LBLeastConn, []int{1, 1, 1})
	g.backends[0].activeConns.Store(5)
	g.backends[1].activeConns.Store(2)
	g.backends[2].activeConns.Store(9)
	if g.pick("") != g.backends[1] {
		t.Fatalf("leastconn did not pick the backend with fewest active conns")
	}
}

func TestFPIPHash(t *testing.T) {
	g := fpTestGroup(LBIPHash, []int{1, 1, 1})
	first := g.pick("203.0.113.7")
	for i := 0; i < 100; i++ {
		if g.pick("203.0.113.7") != first {
			t.Fatalf("iphash not consistent for the same client IP")
		}
	}
	seen := make(map[*fpBackend]bool)
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"} {
		seen[g.pick(ip)] = true
	}
	if len(seen) < 2 {
		t.Fatalf("iphash mapped all distinct IPs to one backend (%d)", len(seen))
	}
}

func TestFPRandomSkipsUnhealthy(t *testing.T) {
	g := fpTestGroup(LBRandom, []int{1, 1, 1})
	g.backends[1].healthy.Store(false)
	hit := make([]int, 3)
	for i := 0; i < 300; i++ {
		hit[fpIndexOf(g, g.pick(""))]++
	}
	if hit[1] != 0 {
		t.Fatalf("random picked the unhealthy backend %d times", hit[1])
	}
	if hit[0] == 0 || hit[2] == 0 {
		t.Fatalf("random did not spread across healthy backends: %v", hit)
	}
}

func TestFPRoundRobinSkipsUnhealthy(t *testing.T) {
	g := fpTestGroup(LBRoundRobin, []int{1, 1, 1})
	g.backends[0].healthy.Store(false)
	for i := 0; i < 100; i++ {
		if g.pick("") == g.backends[0] {
			t.Fatalf("roundrobin returned unhealthy backend while healthy ones exist")
		}
	}
}
