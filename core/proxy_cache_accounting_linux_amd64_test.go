package core

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/guno1928/turbo"
)

const (
	proxyCacheAcctPoll       = 15 * time.Millisecond
	proxyCacheAcctDeadline   = 2 * time.Second
	proxyCacheAcctByteCap    = 8 << 10
	proxyCacheAcctPuts       = 500
	proxyCacheAcctStoppers   = 64
	proxyCacheAcctStopRounds = 100
)

func proxyCacheAcctExpectedCost(key string, e *cacheEntry) int64 {
	cost := int64(unsafe.Sizeof(cacheEntry{})+unsafe.Sizeof("")) + int64(len(key)+len(e.contentType)+cap(e.body)+cap(e.gzipBody))
	cost += int64(cap(e.headers)) * int64(unsafe.Sizeof([2]string{}))
	for _, field := range e.headers {
		cost += int64(len(field[0]) + len(field[1]))
	}
	return cost
}

func proxyCacheAcctRequireExact(t *testing.T, pc *ProxyCache) {
	t.Helper()
	var entries, cost int64
	pc.entries.Range(func(key string, e *cacheEntry) bool {
		entries++
		cost += proxyCacheAcctExpectedCost(key, e)
		return true
	})
	gotEntries, gotBytes, _, _ := pc.Stats()
	if gotEntries != entries || gotBytes != cost {
		t.Fatalf("counters say %d entries / %d bytes, live entries own %d / %d", gotEntries, gotBytes, entries, cost)
	}
}

func proxyCacheAcctWait(cond func() bool) bool {
	deadline := turbo.Deadline(proxyCacheAcctDeadline)
	for !cond() {
		if turbo.Until(deadline) <= 0 {
			return false
		}
		time.Sleep(proxyCacheAcctPoll)
	}
	return true
}

func TestProxyCacheChargesKeyHeadersAndEntry(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{})
	defer pc.Stop()
	pc.Put("GET", "h.test", "/"+strings.Repeat("k", 4096), 200, nil, "", nil)
	pc.Put("GET", "h.test", "/fields", 200, [][2]string{{"x-long", strings.Repeat("v", 2048)}, {"x-b", "c"}}, "application/x-test", nil)
	pc.Put("GET", "h.test", "/body", 200, nil, "text/plain", []byte(strings.Repeat("compressible body ", 64)))
	if entries, total, _, _ := pc.Stats(); entries != 3 || total < 4096+2048 {
		t.Fatalf("empty-body entries charged %d bytes for %d entries, want key and header bytes counted", total, entries)
	}
	proxyCacheAcctRequireExact(t, pc)
	pc.Put("GET", "h.test", "/fields", 200, nil, "", []byte("replacement"))
	proxyCacheAcctRequireExact(t, pc)
	pc.PurgeAll()
	if entries, total, _, _ := pc.Stats(); entries != 0 || total != 0 {
		t.Fatalf("after PurgeAll counters are %d entries / %d bytes, want 0 / 0", entries, total)
	}
}

func TestProxyCacheByteCapBoundsEmptyBodies(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{MaxTotalBytes: proxyCacheAcctByteCap})
	defer pc.Stop()
	for i := 0; i < proxyCacheAcctPuts; i++ {
		pc.Put("GET", "h.test", fmt.Sprintf("/%d?%s", i, strings.Repeat("q", 512)), 200, nil, "", nil)
	}
	settled := proxyCacheAcctWait(func() bool {
		entries, total, _, _ := pc.Stats()
		return !pc.evicting.Load() && entries > 0 && total > 0 && total <= proxyCacheAcctByteCap
	})
	entries, total, _, _ := pc.Stats()
	if !settled {
		t.Fatalf("%d empty-body entries with 512-byte keys retained, charged %d bytes against a %d byte cap", entries, total, proxyCacheAcctByteCap)
	}
	proxyCacheAcctRequireExact(t, pc)
}

func TestProxyCacheNewDefaultsMaxEntries(t *testing.T) {
	for _, tc := range []struct {
		given, want int64
	}{{0, 10000}, {-1, -1}, {7, 7}} {
		pc := NewProxyCache(ProxyCacheConfig{MaxEntries: tc.given})
		got := pc.config.Load().MaxEntries
		pc.Stop()
		if got != tc.want {
			t.Fatalf("NewProxyCache MaxEntries %d became %d, want %d", tc.given, got, tc.want)
		}
	}
}

func TestProxyCacheRefreshAtEntryCap(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{MaxEntries: 1})
	defer pc.Stop()
	pc.Put("GET", "h.test", "/same", 200, nil, "", []byte("old"))
	pc.Put("GET", "h.test", "/same", 200, nil, "", []byte("replacement"))
	entry, hit := pc.GetFP("GET", "h.test", "/same", true)
	if !hit || string(entry.body) != "replacement" {
		t.Fatalf("refresh at the entry cap: hit=%v body=%q, want replacement", hit, proxyCacheAcctBody(entry))
	}
	proxyCacheAcctRequireExact(t, pc)
}

func proxyCacheAcctBody(e *cacheEntry) string {
	if e == nil {
		return ""
	}
	return string(e.body)
}

func TestProxyCacheConcurrentStop(t *testing.T) {
	for round := 0; round < proxyCacheAcctStopRounds; round++ {
		pc := NewProxyCache(ProxyCacheConfig{})
		start := make(chan struct{})
		panics := make(chan any, proxyCacheAcctStoppers)
		var stoppers sync.WaitGroup
		for i := 0; i < proxyCacheAcctStoppers; i++ {
			stoppers.Add(1)
			go func() {
				defer stoppers.Done()
				defer func() {
					if r := recover(); r != nil {
						panics <- r
					}
				}()
				<-start
				pc.Stop()
			}()
		}
		close(start)
		stoppers.Wait()
		close(panics)
		for r := range panics {
			t.Fatalf("round %d: concurrent Stop panicked: %v", round, r)
		}
		select {
		case <-pc.stopCh:
		default:
			t.Fatal("Stop did not close the stop channel")
		}
	}
}
