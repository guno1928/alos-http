package core

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestPerIPConnLimiter_AcquireUpToLimit(t *testing.T) {
	l := newPerIPConnLimiter()
	defer l.Stop()
	for i := 0; i < 5; i++ {
		if !l.acquire("1.2.3.4", 5) {
			t.Fatalf("acquire %d should succeed", i)
		}
	}
	if l.acquire("1.2.3.4", 5) {
		t.Fatal("6th acquire must fail at limit 5")
	}
}

func TestPerIPConnLimiter_ReleaseAllowsReacquire(t *testing.T) {
	l := newPerIPConnLimiter()
	defer l.Stop()
	for i := 0; i < 5; i++ {
		l.acquire("1.2.3.4", 5)
	}
	l.release("1.2.3.4")
	if !l.acquire("1.2.3.4", 5) {
		t.Fatal("acquire after release should succeed")
	}
}

func TestPerIPConnLimiter_PerIPIsolation(t *testing.T) {
	l := newPerIPConnLimiter()
	defer l.Stop()
	for i := 0; i < 5; i++ {
		l.acquire("1.1.1.1", 5)
	}
	if !l.acquire("2.2.2.2", 5) {
		t.Fatal("a different IP must have its own budget")
	}
}

func TestPerIPConnLimiter_DisabledWhenLimitZero(t *testing.T) {
	l := newPerIPConnLimiter()
	defer l.Stop()
	for i := 0; i < 1000; i++ {
		if !l.acquire("1.2.3.4", 0) {
			t.Fatal("limit<=0 must always allow")
		}
	}
}

func TestPerIPConnLimiter_EmptyIPAllowed(t *testing.T) {
	l := newPerIPConnLimiter()
	defer l.Stop()
	if !l.acquire("", 5) {
		t.Fatal("empty IP must be allowed")
	}
}

func TestPerIPConnLimiter_NilSafe(t *testing.T) {
	var l *perIPConnLimiter
	if !l.acquire("x", 5) {
		t.Fatal("nil limiter acquire must allow")
	}
	l.release("x")
	l.Stop()
}

func TestPerIPConnLimiter_ReleaseNeverNegative(t *testing.T) {
	l := newPerIPConnLimiter()
	defer l.Stop()
	l.acquire("1.2.3.4", 5)
	l.release("1.2.3.4")
	l.release("1.2.3.4")
	for i := 0; i < 5; i++ {
		if !l.acquire("1.2.3.4", 5) {
			t.Fatalf("acquire %d after extra release should succeed (count clamped at 0)", i)
		}
	}
}

func TestPerIPConnLimiter_Concurrent(t *testing.T) {
	l := newPerIPConnLimiter()
	defer l.Stop()
	var wg sync.WaitGroup
	var granted int64
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if l.acquire("9.9.9.9", 10) {
					atomic.AddInt64(&granted, 1)
					l.release("9.9.9.9")
				}
			}
		}()
	}
	wg.Wait()
	for i := 0; i < 10; i++ {
		if !l.acquire("9.9.9.9", 10) {
			t.Fatalf("post-concurrent acquire %d failed (counter leaked)", i)
		}
	}
	if l.acquire("9.9.9.9", 10) {
		t.Fatal("11th should fail after 10 held")
	}
}

func TestPerIPConnLimiter_NeverExceedsLimitUnderRace(t *testing.T) {
	l := newPerIPConnLimiter()
	defer l.Stop()
	const limit = 8
	var held, maxHeld int64
	var wg sync.WaitGroup
	for g := 0; g < 40; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				if l.acquire("7.7.7.7", limit) {
					h := atomic.AddInt64(&held, 1)
					for {
						m := atomic.LoadInt64(&maxHeld)
						if h <= m || atomic.CompareAndSwapInt64(&maxHeld, m, h) {
							break
						}
					}
					atomic.AddInt64(&held, -1)
					l.release("7.7.7.7")
				}
			}
		}()
	}
	wg.Wait()
	if maxHeld > limit {
		t.Fatalf("concurrently held %d exceeded limit %d", maxHeld, limit)
	}
}

func TestConfig_MaxConnsPerIP_Default20(t *testing.T) {
	s := New(Config{})
	defer s.perIPConnLimiter.Stop()
	if s.perIPConnLimiter == nil {
		t.Fatal("limiter should be created by default")
	}
	if s.maxConnsPerIP != 20 {
		t.Fatalf("default maxConnsPerIP=%d want 20", s.maxConnsPerIP)
	}
}

func TestConfig_MaxConnsPerIP_Explicit(t *testing.T) {
	s := New(Config{MaxConnsPerIP: 5})
	defer s.perIPConnLimiter.Stop()
	if s.maxConnsPerIP != 5 {
		t.Fatalf("maxConnsPerIP=%d want 5", s.maxConnsPerIP)
	}
}

func TestConfig_MaxConnsPerIP_Disabled(t *testing.T) {
	s := New(Config{MaxConnsPerIP: -1})
	if s.perIPConnLimiter != nil {
		t.Fatal("negative MaxConnsPerIP must disable the limiter")
	}
}
