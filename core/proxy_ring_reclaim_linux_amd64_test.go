//go:build linux && amd64

package core

import (
	"sync"
	"testing"
)

// TestReclaimAfterTimeoutDrainsCompletion verifies a completion already posted
// to the ring (here a NOP — the exact state a timed-out op leaves behind) is
// drained by reclaimAfterTimeout, which then reports the ring clean.
func TestReclaimAfterTimeoutDrainsCompletion(t *testing.T) {
	ring, err := newIOUring(proxyRingEntries)
	if err != nil {
		t.Skipf("io_uring unavailable: %v", err)
	}
	defer ring.close()

	if _, err := ring.getSqe(); err != nil { // cleared SQE == IORING_OP_NOP
		t.Fatalf("getSqe: %v", err)
	}
	if _, err := ring.submitAndWait(1); err != nil {
		t.Fatalf("submitAndWait: %v", err)
	}
	if !ring.reclaimAfterTimeout(-1) {
		t.Fatal("reclaimAfterTimeout did not drain the pending completion")
	}
	if _, ok := ring.tryCqe(); ok {
		t.Fatal("completion queue not empty after reclaim")
	}
}

// TestReplaceReadRingInstallsFreshRing verifies the guaranteed-clean fallback.
func TestReplaceReadRingInstallsFreshRing(t *testing.T) {
	ring, err := newIOUring(proxyRingEntries)
	if err != nil {
		t.Skipf("io_uring unavailable: %v", err)
	}
	pool := &proxyRingPool{
		readRings:    []*ioUring{ring},
		writeRings:   make([]*ioUring, 1),
		connectRings: make([]*ioUring, 1),
		readMu:       make([]sync.Mutex, 1),
		writeMu:      make([]sync.Mutex, 1),
		connectMu:    make([]sync.Mutex, 1),
		count:        1,
	}
	old := pool.readRings[0]
	pool.readMu[0].Lock()
	pool.replaceReadRing(0)
	pool.readMu[0].Unlock()

	got, idx := pool.acquireReadRing()
	pool.releaseReadRing(idx)
	if got == old {
		t.Fatal("replaceReadRing did not install a new ring")
	}
	if got == nil || got.fd < 0 {
		t.Fatal("replacement ring is not usable")
	}
	got.close()
}

// BenchmarkReclaimAfterTimeoutClean measures the cost of reclaim when there is
// already a completion to drain (the common kernel path).
func BenchmarkReclaimAfterTimeoutClean(b *testing.B) {
	ring, err := newIOUring(proxyRingEntries)
	if err != nil {
		b.Skipf("io_uring unavailable: %v", err)
	}
	defer ring.close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ring.getSqe(); err != nil {
			b.Fatal(err)
		}
		if _, err := ring.submitAndWait(1); err != nil {
			b.Fatal(err)
		}
		ring.reclaimAfterTimeout(-1)
	}
}
