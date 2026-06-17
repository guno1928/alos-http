//go:build linux && amd64

package core

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestReadCqOverflow verifies the extracted overflow-counter read mirrors the
// value the kernel would write into the CQ ring at CqOff.Overflow. The kernel
// side (the actual overflow event and the GETEVENTS flush that recovers dropped
// completions) requires a live io_uring instance and is exercised in production,
// not here; this test covers the observable userspace read.
func TestReadCqOverflow(t *testing.T) {
	if got := readCqOverflow(nil); got != 0 {
		t.Fatalf("readCqOverflow(nil) = %d, want 0", got)
	}

	var counter uint32
	if got := readCqOverflow(&counter); got != 0 {
		t.Fatalf("readCqOverflow(zero) = %d, want 0", got)
	}

	atomic.StoreUint32(&counter, 7)
	if got := readCqOverflow(&counter); got != 7 {
		t.Fatalf("readCqOverflow = %d, want 7", got)
	}
}

// TestReadCqOverflowConcurrent ensures the read is race-free against concurrent
// kernel-style increments of the shared counter.
func TestReadCqOverflowConcurrent(t *testing.T) {
	var counter uint32
	const writers = 4
	const incrPerWriter = 1000

	var writerWg sync.WaitGroup
	writerWg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer writerWg.Done()
			for j := 0; j < incrPerWriter; j++ {
				atomic.AddUint32(&counter, 1)
			}
		}()
	}

	stop := make(chan struct{})
	var readerWg sync.WaitGroup
	readerWg.Add(1)
	go func() {
		defer readerWg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = readCqOverflow(&counter)
			}
		}
	}()

	writerWg.Wait()
	close(stop)
	readerWg.Wait()

	if got := readCqOverflow(&counter); got != writers*incrPerWriter {
		t.Fatalf("final counter = %d, want %d", got, writers*incrPerWriter)
	}
}

// TestObserveCqOverflowTracksAndLogs verifies the per-ring bookkeeping in
// observeCqOverflow without entering the kernel: it advances lastCqOverflow only
// when the counter moves, marks the first overflow as logged, and is a no-op
// when the counter is unchanged. The flush syscall path is guarded by fd < 0 so
// the method does not touch a real ring here.
func TestObserveCqOverflowTracksAndLogs(t *testing.T) {
	var counter uint32
	ring := &ioUring{
		fd:         -1, // forces flushCqOverflow to short-circuit (EBADF), no syscall
		cqOverflow: &counter,
	}

	// No movement: no-op, nothing logged.
	ring.observeCqOverflow()
	if ring.lastCqOverflow != 0 || ring.overflowLogged {
		t.Fatalf("unchanged counter should be a no-op: last=%d logged=%v", ring.lastCqOverflow, ring.overflowLogged)
	}

	// Kernel drops some completions.
	atomic.StoreUint32(&counter, 3)
	ring.observeCqOverflow()
	if ring.lastCqOverflow != 3 {
		t.Fatalf("lastCqOverflow = %d, want 3", ring.lastCqOverflow)
	}
	if !ring.overflowLogged {
		t.Fatalf("overflowLogged should be set after first overflow")
	}

	// Same value again: no further advance.
	ring.observeCqOverflow()
	if ring.lastCqOverflow != 3 {
		t.Fatalf("lastCqOverflow advanced without counter movement: %d", ring.lastCqOverflow)
	}

	// More drops: counter keeps advancing.
	atomic.StoreUint32(&counter, 10)
	ring.observeCqOverflow()
	if ring.lastCqOverflow != 10 {
		t.Fatalf("lastCqOverflow = %d, want 10", ring.lastCqOverflow)
	}
}

// TestFlushCqOverflowGuards confirms flushCqOverflow fails closed on a dead ring
// rather than issuing a syscall on an invalid fd.
func TestFlushCqOverflowGuards(t *testing.T) {
	var ring *ioUring
	if err := ring.flushCqOverflow(); err == nil {
		t.Fatalf("nil ring should return error")
	}

	closed := &ioUring{fd: -1}
	if err := closed.flushCqOverflow(); err == nil {
		t.Fatalf("closed ring (fd<0) should return error")
	}
}
