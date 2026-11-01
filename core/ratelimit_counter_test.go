//go:build linux && amd64

package core

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/guno1928/alosmap"
)

const (
	rlTestWindow = int64(time.Hour)
	rlTestBlock  = int64(10 * time.Second)
	rlTestNow    = 1000 * rlTestWindow
)

func TestRlCounterQuotaAcrossBlockExpiry(t *testing.T) {
	var c rlCounter
	steps := []struct {
		at        int64
		want      rlOutcome
		wantRetry time.Duration
	}{
		{rlTestNow, rlAllowed, 0},
		{rlTestNow + 1, rlAllowed, 0},
		{rlTestNow + 2, rlLimited, time.Duration(rlTestBlock)},
		{rlTestNow + 2 + rlTestBlock/2, rlLimited, time.Duration(rlTestBlock / 2)},
		{rlTestNow + 2 + rlTestBlock, rlAllowed, 0},
		{rlTestNow + 3 + rlTestBlock, rlAllowed, 0},
		{rlTestNow + 4 + rlTestBlock, rlLimited, time.Duration(rlTestBlock)},
	}
	for i, s := range steps {
		got, retry := c.admit(s.at, rlTestWindow, 2, rlTestBlock)
		if got != s.want || retry != s.wantRetry {
			t.Fatalf("step %d: outcome %d retry %v, want %d retry %v", i, got, retry, s.want, s.wantRetry)
		}
	}
}

func TestRlCounterConcurrentExpiryAdmitsExactlyQuota(t *testing.T) {
	const quota, callers, rounds = 3, 64, 50
	for round := range rounds {
		var c rlCounter
		c.state.Store(rlBlockedFlag | uint64(rlTestNow))
		start := make(chan struct{})
		results := make(chan rlOutcome, callers)
		var wg sync.WaitGroup
		for range callers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				outcome, _ := c.admit(rlTestNow, rlTestWindow, quota, rlTestBlock)
				results <- outcome
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		allowed := 0
		for outcome := range results {
			if outcome == rlAllowed {
				allowed++
			}
		}
		if want := rlBlockedFlag | uint64(rlTestNow+rlTestBlock); allowed != quota || c.state.Load() != want {
			t.Fatalf("round %d: allowed %d (want %d), state %#x (want new block %#x)", round, allowed, quota, c.state.Load(), want)
		}
	}
}

func TestRlCounterLimitsEdgeConfigs(t *testing.T) {
	var zero rlCounter
	if got, _ := zero.admit(rlTestNow, rlTestWindow, 0, rlTestBlock); got != rlLimited {
		t.Fatalf("MaxReqs 0 admitted a request")
	}
	var huge rlCounter
	if got, retry := huge.admit(rlTestNow, rlTestWindow, 1, math.MaxInt64); got != rlAllowed || retry != 0 {
		t.Fatalf("first request refused")
	}
	if got, _ := huge.admit(rlTestNow, rlTestWindow, 1, math.MaxInt64); got != rlLimited {
		t.Fatalf("over-quota request admitted")
	}
	if huge.state.Load() != rlBlockedFlag|uint64(rlMaxBlockDeadline) {
		t.Fatalf("block deadline %#x did not saturate below the retired state", huge.state.Load())
	}
	var saturated rlCounter
	saturated.state.Store(rlEpochOf(rlTestNow, rlTestWindow) | rlCountMask)
	if got, _ := saturated.admit(rlTestNow, rlTestWindow, math.MaxInt64, rlTestBlock); got != rlAllowed || saturated.state.Load()&rlCountMask != rlCountMask {
		t.Fatalf("saturated counter changed or refused under an unlimited quota")
	}
}

func TestRlCounterRetireOnlyIdle(t *testing.T) {
	const longBlock = 2 * rlTestWindow
	var c rlCounter
	c.admit(rlTestNow, rlTestWindow, 1, longBlock)
	if c.retireIfIdle(rlTestNow+rlTestWindow, 0) {
		t.Fatal("retired an entry whose window has not ended")
	}
	c.admit(rlTestNow+1, rlTestWindow, 1, longBlock)
	if c.retireIfIdle(rlTestNow+rlTestWindow+1, 0) {
		t.Fatal("retired an entry that is still blocked")
	}
	if !c.retireIfIdle(rlTestNow+2+longBlock, 0) {
		t.Fatal("did not retire an idle entry")
	}
	if got, _ := c.admit(rlTestNow, rlTestWindow, 1, longBlock); got != rlRetired {
		t.Fatalf("admission on a retired entry returned %d", got)
	}
}

func TestRateLimitEngineRetiredEntryChargesLiveEntry(t *testing.T) {
	rl := NewRateLimitEngine()
	defer rl.Stop()
	rl.AddRule(RateLimitRule{Path: "/r", MaxReqs: 1, Window: time.Second, BlockFor: time.Hour})
	if ok, _, _ := rl.Check("192.0.2.1", "/r"); !ok {
		t.Fatal("first request refused")
	}
	stale, ok := rl.clients.Load("192.0.2.1|/r")
	if !ok {
		t.Fatal("entry not stored")
	}
	retireIdleRateLimitEntries(rl.clients, CoarseNanotime(), rlEngineIdleGrace)
	if _, ok := rl.clients.Load("192.0.2.1|/r"); !ok {
		t.Fatal("cleanup retired a live entry")
	}
	retireIdleRateLimitEntries(rl.clients, stale.reset.Load()+rlEngineIdleGrace+1, rlEngineIdleGrace)
	if _, ok := rl.clients.Load("192.0.2.1|/r"); ok {
		t.Fatal("cleanup kept an idle entry")
	}
	if got, _ := stale.admit(CoarseNanotime(), int64(time.Second), 1, int64(time.Hour)); got != rlRetired {
		t.Fatalf("cached pointer still counts on the retired entry: %d", got)
	}
	if ok, _, _ := rl.Check("192.0.2.1", "/r"); !ok {
		t.Fatal("request after retirement refused")
	}
	if ok, _, _ := rl.Check("192.0.2.1", "/r"); ok {
		t.Fatal("second request on the live entry was not charged")
	}
	live, ok := rl.clients.Load("192.0.2.1|/r")
	if !ok || live == stale {
		t.Fatal("no fresh live entry replaced the retired one")
	}
	stale.state.Store(rlRetiredState)
	rl.clients.Store("192.0.2.1|/r", stale)
	if ok, _, _ := rl.Check("192.0.2.1", "/r"); !ok {
		t.Fatal("Check did not replace a retired entry left in the map")
	}
	if replaced, _ := rl.clients.Load("192.0.2.1|/r"); replaced == stale {
		t.Fatal("retired entry still mapped after Check")
	}
}

func TestRateLimitMiddlewareCleanupRetiresOnlyIdle(t *testing.T) {
	entries := alosmap.NewTypedSized[string, *rateLimitMWEntry](16, 0)
	entry := &rateLimitMWEntry{}
	entry.admit(rlTestNow, rlTestWindow, 10, rlTestBlock)
	entries.Store("k", entry)
	retireIdleRateLimitEntries(entries, rlTestNow+rlTestWindow, 0)
	if _, ok := entries.Load("k"); !ok {
		t.Fatal("cleanup retired an entry inside its window")
	}
	retireIdleRateLimitEntries(entries, rlTestNow+rlTestWindow+1, 0)
	if _, ok := entries.Load("k"); ok || entry.state.Load() != rlRetiredState {
		t.Fatal("cleanup kept an idle entry")
	}
}
