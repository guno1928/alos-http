//go:build linux && amd64

package core

import (
	"sync"
	"testing"
)

// TestReclaimAfterTimeoutDrainsCompletion verifies that a completion already
// posted to the ring (here a NOP) is drained by reclaimAfterTimeout, which then
// reports the ring as clean — so it would not be reaped by the next borrower.
func TestReclaimAfterTimeoutDrainsCompletion(t *testing.T) {
	ring, err := newIOUring(proxyRingEntries)
	if err != nil {
		t.Skipf("io_uring unavailable: %v", err)
	}
	defer ring.close()

	// A cleared SQE is IORING_OP_NOP (opcode 0); it completes immediately.
	sqe, err := ring.getSqe()
	if err != nil {
		t.Fatalf("getSqe: %v", err)
	}
	_ = sqe
	if _, err := ring.submitAndWait(1); err != nil {
		t.Fatalf("submitAndWait: %v", err)
	}

	// The NOP completion is now in the CQ, unconsumed — the exact state a
	// timed-out op leaves behind. reclaimAfterTimeout must drain it.
	if !ring.reclaimAfterTimeout(-1) {
		t.Fatal("reclaimAfterTimeout did not drain the pending completion")
	}
	// CQ must now be empty.
	if _, ok := ring.tryCqe(); ok {
		t.Fatal("completion queue not empty after reclaim")
	}
}

// TestReplaceReadRingInstallsFreshRing verifies the guaranteed-clean fallback:
// the slot gets a new, usable ring and the old one is closed.
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
