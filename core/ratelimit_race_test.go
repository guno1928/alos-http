//go:build linux && amd64

package core

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	rateLimitRaceRunFor   = 150 * time.Millisecond
	rateLimitRaceBlockFor = 3 * time.Millisecond
)

func TestRateLimitEngineExpiryNeverAdmitsOverQuotaPerTick(t *testing.T) {
	const quota = 1
	rl := NewRateLimitEngine()
	defer rl.Stop()
	rl.AddRule(RateLimitRule{Path: "/expiry", MaxReqs: quota, Window: 100 * time.Hour, BlockFor: rateLimitRaceBlockFor})
	workers := 2 * runtime.GOMAXPROCS(0)
	perTick := make([]map[int64]int, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for w := range workers {
		perTick[w] = make(map[int64]int)
		wg.Add(1)
		go func(admitted map[int64]int) {
			defer wg.Done()
			<-start
			deadline := turbo.Deadline(rateLimitRaceRunFor)
			for turbo.Until(deadline) > 0 {
				before := CoarseNanotime()
				ok, _, _ := rl.Check("192.0.2.1", "/expiry")
				if ok && CoarseNanotime() == before {
					admitted[before]++
				}
				runtime.Gosched()
			}
		}(perTick[w])
	}
	close(start)
	wg.Wait()
	total := make(map[int64]int)
	for _, admitted := range perTick {
		for tick, n := range admitted {
			total[tick] += n
		}
	}
	over, worst := 0, 0
	for _, n := range total {
		if n > quota {
			over++
		}
		worst = max(worst, n)
	}
	if over > 0 {
		t.Fatalf("%d of %d clock ticks admitted more than quota %d (worst %d)", over, len(total), quota, worst)
	}
}

func TestRateLimitEngineConcurrentStopDoesNotPanic(t *testing.T) {
	const rounds, callers = 200, 8
	var panics atomic.Int32
	for range rounds {
		rl := NewRateLimitEngine()
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range callers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					if recover() != nil {
						panics.Add(1)
					}
				}()
				<-start
				rl.Stop()
			}()
		}
		close(start)
		wg.Wait()
	}
	if n := panics.Load(); n != 0 {
		t.Fatalf("concurrent Stop panicked %d times in %d rounds", n, rounds)
	}
}
