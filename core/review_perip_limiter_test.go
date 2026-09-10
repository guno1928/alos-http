package core

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const perIPRaceDuration = 150 * time.Millisecond

func TestPerIPLimiterSweepCannotLeakBudget(t *testing.T) {
	l := newPerIPLimiter(16)
	defer l.Stop()
	const ip = "198.51.100.7"
	const limit = 1

	stop := make(chan struct{})
	var inside atomic.Int64
	var violations atomic.Int64
	var admitted atomic.Int64
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				l.sweep()
			}
		}
	}()

	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if !l.acquire(ip, limit) {
					continue
				}
				admitted.Add(1)
				if inside.Add(1) > limit {
					violations.Add(1)
				}
				inside.Add(-1)
				l.release(ip)
			}
		}()
	}

	time.Sleep(perIPRaceDuration)
	close(stop)
	wg.Wait()

	if admitted.Load() == 0 {
		t.Fatal("no request was ever admitted; test setup is wrong")
	}
	if v := violations.Load(); v != 0 {
		t.Fatalf("per-IP limit of %d exceeded %d times while the sweeper ran; a counter deleted between creation and first increment gives the IP a second budget", limit, v)
	}
	if c, ok := l.m.Load(ip); ok && c.n.Load() != 0 {
		t.Fatalf("counter left at %d after all requests released", c.n.Load())
	}
}

func TestPerIPLimiterSweepRemovesIdleAndKeepsBusy(t *testing.T) {
	l := newPerIPLimiter(16)
	defer l.Stop()
	if !l.acquire("busy", 4) {
		t.Fatal("acquire busy")
	}
	if !l.acquire("idle", 4) {
		t.Fatal("acquire idle")
	}
	l.release("idle")
	l.sweep()
	if _, ok := l.m.Load("idle"); ok {
		t.Fatal("idle counter survived the sweep")
	}
	if c, ok := l.m.Load("busy"); !ok || c.n.Load() != 1 {
		t.Fatal("busy counter was swept or miscounted")
	}
	l.release("busy")
	if !l.acquire("idle", 1) {
		t.Fatal("re-acquire after sweep")
	}
	if l.acquire("idle", 1) {
		t.Fatal("limit not enforced on the fresh counter")
	}
}
