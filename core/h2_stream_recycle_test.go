package core

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/guno1928/alosmap"
)

// TestH2StreamRSTVsDispatchNoDoublePut stresses the single-owner recycle
// guard: for each iteration a stream is "dispatched" (read-loop ref + dispatch
// ref) and then a RST_STREAM read-loop close races the dispatch goroutine's
// completion close. Under the old code (Reset()+Put() in the RST handler while
// the dispatch goroutine still held the stream) the race detector and the
// double-Put / negative-gauge assertions below surface the use-after-free.
//
// Invariants asserted:
//   - each stream is recycled (Put) exactly once (no double-Put / UAF),
//   - activeStreams returns to 0 and never observes a value below zero.
func TestH2StreamRSTVsDispatchNoDoublePut(t *testing.T) {
	const iterations = 20000

	hc := &H2Conn{
		streams: alosmap.New(alosmap.WithCapacity(256), alosmap.WithoutCleanup()),
	}
	defer hc.streams.Close()

	// Streams are recycled into StreamPool and handed back out by later
	// iterations, so a per-object Put count is meaningless. The invariant that
	// matters is per-iteration: the stream dispatched this iteration is
	// recycled exactly once (perIterRecycles), and the total across the run
	// equals the iteration count (no double-Put, no missed Put).
	var (
		perIterStream   atomic.Pointer[H2Stream]
		perIterRecycles atomic.Int32
		putTotal        atomic.Int64
		minGauge        atomic.Int32
	)

	prevHook := streamRecycleHook
	streamRecycleHook = func(s *H2Stream) {
		putTotal.Add(1)
		if s == perIterStream.Load() {
			perIterRecycles.Add(1)
		}
	}
	defer func() { streamRecycleHook = prevHook }()

	observeGauge := func() {
		g := hc.activeStreams.Load()
		for {
			cur := minGauge.Load()
			if g >= cur {
				break
			}
			if minGauge.CompareAndSwap(cur, g) {
				break
			}
		}
	}

	for i := 0; i < iterations; i++ {
		streamID := uint32(i*2 + 1)

		// Simulate processDecodedHeaders/handleData END_STREAM setup:
		// store with the read-loop reference, then add the dispatch reference.
		stream := StreamPool.Get().(*H2Stream)
		stream.Reset()
		stream.ID = streamID
		stream.refs.Store(1)
		hc.streams.Store(alosmap.I(int64(streamID)), stream)
		hc.activeStreams.Add(1)

		stream.refs.Add(1) // dispatch reference

		perIterStream.Store(stream)
		perIterRecycles.Store(0)

		var wg sync.WaitGroup
		wg.Add(2)

		// Read-loop goroutine: RST_STREAM for this stream id.
		go func() {
			defer wg.Done()
			hc.closeStreamFromReadLoop(streamID, stream)
			observeGauge()
		}()

		// Dispatch goroutine: normal completion close + release its own ref.
		go func() {
			defer wg.Done()
			hc.closeStreamFromReadLoop(streamID, stream)
			hc.releaseStream(stream)
			observeGauge()
		}()

		wg.Wait()

		if got := perIterRecycles.Load(); got != 1 {
			t.Fatalf("iter %d: stream recycled %d times, want exactly 1 (double-Put/UAF or missed Put)", i, got)
		}
		if got := stream.refs.Load(); got != 0 {
			t.Fatalf("iter %d: stream refs = %d, want 0", i, got)
		}
	}

	if g := hc.activeStreams.Load(); g != 0 {
		t.Fatalf("activeStreams = %d after run, want 0", g)
	}
	if mg := minGauge.Load(); mg < 0 {
		t.Fatalf("activeStreams went negative (min observed = %d)", mg)
	}
	if got := putTotal.Load(); got != iterations {
		t.Fatalf("total recycles = %d, want %d", got, iterations)
	}
}

// TestH2StreamDoubleRSTNoGaugeDrift verifies a racing double RST_STREAM for the
// same stream id (no dispatch in flight) recycles exactly once and decrements
// the gauge exactly once, matching the Open-stream RST path.
func TestH2StreamDoubleRSTNoGaugeDrift(t *testing.T) {
	const iterations = 20000

	hc := &H2Conn{
		streams: alosmap.New(alosmap.WithCapacity(256), alosmap.WithoutCleanup()),
	}
	defer hc.streams.Close()

	var recycles atomic.Int64
	prevHook := streamRecycleHook
	streamRecycleHook = func(*H2Stream) { recycles.Add(1) }
	defer func() { streamRecycleHook = prevHook }()

	for i := 0; i < iterations; i++ {
		streamID := uint32(i*2 + 1)

		stream := StreamPool.Get().(*H2Stream)
		stream.Reset()
		stream.ID = streamID
		stream.refs.Store(1) // open stream: only the read-loop reference
		hc.streams.Store(alosmap.I(int64(streamID)), stream)
		hc.activeStreams.Add(1)

		var wg sync.WaitGroup
		wg.Add(2)
		for j := 0; j < 2; j++ {
			go func() {
				defer wg.Done()
				hc.closeStreamFromReadLoop(streamID, stream)
			}()
		}
		wg.Wait()
	}

	if g := hc.activeStreams.Load(); g != 0 {
		t.Fatalf("activeStreams = %d after double-RST run, want 0", g)
	}
	if got := recycles.Load(); got != iterations {
		t.Fatalf("recycles = %d, want %d (double-Put or missed Put)", got, iterations)
	}
}
