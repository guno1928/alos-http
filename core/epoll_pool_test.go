//go:build linux && amd64

package core

import "testing"

func TestPool_PrewarmFloor(t *testing.T) {
	p := &epollConnPool{batchSize: 4}
	p.prewarm(10)
	if p.floorSlabs != 3 {
		t.Fatalf("floorSlabs=%d want 3 (ceil(10/4))", p.floorSlabs)
	}
	if len(p.slabs) != 3 {
		t.Fatalf("slabs=%d want 3", len(p.slabs))
	}
	if len(p.free) != 12 {
		t.Fatalf("free=%d want 12", len(p.free))
	}
}

func TestPool_GetServesFromFree(t *testing.T) {
	p := &epollConnPool{batchSize: 4}
	p.prewarm(4)
	c := p.get()
	if c == nil {
		t.Fatal("get returned nil")
	}
	if len(p.free) != 3 {
		t.Fatalf("free=%d want 3 after one get", len(p.free))
	}
	if c.slab.free != 3 {
		t.Fatalf("slab.free=%d want 3", c.slab.free)
	}
}

func TestPool_GetGrowsBeyondFloor(t *testing.T) {
	p := &epollConnPool{batchSize: 4}
	p.prewarm(4)
	for i := 0; i < 5; i++ {
		p.get()
	}
	if len(p.slabs) < 2 {
		t.Fatalf("slabs=%d, pool should grow past floor under load", len(p.slabs))
	}
}

func TestPool_ShrinkAfterReturn(t *testing.T) {
	p := &epollConnPool{batchSize: 4}
	p.prewarm(4)
	conns := make([]*epollConn, 0, 40)
	for i := 0; i < 40; i++ {
		conns = append(conns, p.get())
	}
	peak := len(p.slabs)
	if peak < 10 {
		t.Fatalf("expected growth to >=10 slabs, got %d", peak)
	}
	for _, c := range conns {
		p.put(c)
	}
	if len(p.slabs) >= peak {
		t.Fatalf("pool did not shrink: slabs=%d peak=%d", len(p.slabs), peak)
	}
	if len(p.slabs) < p.floorSlabs {
		t.Fatalf("pool shrank below floor: slabs=%d floor=%d", len(p.slabs), p.floorSlabs)
	}
}

func TestPool_NeverBelowFloor(t *testing.T) {
	p := &epollConnPool{batchSize: 4}
	p.prewarm(8)
	for i := 0; i < 100; i++ {
		c := p.get()
		p.put(c)
	}
	if len(p.slabs) < p.floorSlabs {
		t.Fatalf("slabs=%d below floor=%d", len(p.slabs), p.floorSlabs)
	}
}

func TestPool_PutDecrementsActiveConns(t *testing.T) {
	s := &Server{}
	p := &epollConnPool{batchSize: 4, server: s}
	p.prewarm(4)
	c := p.get()
	s.activeConns.Add(1)
	baseStats := Stats.ActiveConns.Load()
	Stats.ActiveConns.Add(1)
	p.put(c)
	if s.activeConns.Load() != 0 {
		t.Fatalf("server.activeConns=%d want 0", s.activeConns.Load())
	}
	if Stats.ActiveConns.Load() != baseStats {
		t.Fatalf("Stats.ActiveConns=%d want %d (unbalanced)", Stats.ActiveConns.Load(), baseStats)
	}
}

func TestPool_ShrinkEpollBufThreshold(t *testing.T) {
	small := make([]byte, 100)
	if got := shrinkEpollBuf(small); got == nil || len(got) != 0 {
		t.Fatalf("small buffer should be kept as len-0 slice, got nil=%v len=%d", got == nil, len(got))
	}
	big := make([]byte, epollBufShrinkThreshold+1)
	if got := shrinkEpollBuf(big); got != nil {
		t.Fatalf("oversized buffer should be dropped to nil, got cap=%d", cap(got))
	}
}

func TestPool_BufShrinkOnPut(t *testing.T) {
	s := &Server{}
	p := &epollConnPool{batchSize: 4, server: s}
	p.prewarm(4)
	c := p.get()
	c.reqBodyCopy = make([]byte, epollBufShrinkThreshold+10)
	s.activeConns.Add(1)
	Stats.ActiveConns.Add(1)
	p.put(c)
	if c.reqBodyCopy != nil {
		t.Fatalf("oversized reqBodyCopy should be dropped on put, got cap=%d", cap(c.reqBodyCopy))
	}
}
