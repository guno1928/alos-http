package core

import (
	"net"
	"sync"
	"testing"
)

// newTestQUICConn builds a QUICConn with just the fields the stream-limit /
// reset-rate logic touches, deliberately leaving keys/udpConn nil so the
// best-effort send paths in closeWithError become no-ops (no network).
func newTestQUICConn() *QUICConn {
	qc := &QUICConn{
		done:        make(chan struct{}),
		streams:     make(map[uint64]*QUICStream),
		dispatchSem: make(chan struct{}, quicMaxConcurrentRequests),
		remoteAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
	}
	return qc
}

func streamFrame(id uint64, fin bool) quicStreamFrame {
	return quicStreamFrame{streamID: id, offset: 0, data: nil, fin: fin}
}

// Opening peer bidi streams beyond the advertised MAX_STREAMS closes the
// connection with STREAM_LIMIT_ERROR and does not allocate the overflow stream.
func TestStreamLimitExceededClosesConnection(t *testing.T) {
	qc := newTestQUICConn()

	// Client-initiated bidi stream IDs are 0, 4, 8, ... (id % 4 == 0).
	for i := uint64(0); i < quicMaxBidiStreams; i++ {
		qc.handleStreamFrameIncoming(streamFrame(i*4, false))
		if qc.closed.Load() {
			t.Fatalf("connection closed early at stream %d", i)
		}
	}

	if got := qc.peerBidiStreams; got != quicMaxBidiStreams {
		t.Fatalf("peerBidiStreams = %d, want %d", got, quicMaxBidiStreams)
	}

	// One more distinct peer bidi stream must trip the limit.
	qc.handleStreamFrameIncoming(streamFrame(quicMaxBidiStreams*4, false))
	if !qc.closed.Load() {
		t.Fatal("expected connection closed after exceeding bidi stream limit")
	}

	qc.streamsMu.Lock()
	_, present := qc.streams[quicMaxBidiStreams*4]
	n := len(qc.streams)
	qc.streamsMu.Unlock()
	if present {
		t.Fatal("overflow stream should not have been stored")
	}
	if n != int(quicMaxBidiStreams) {
		t.Fatalf("stream map size = %d, want %d", n, quicMaxBidiStreams)
	}
}

// Re-using an already-open stream ID must not re-count toward the limit.
func TestStreamLimitDoesNotDoubleCount(t *testing.T) {
	qc := newTestQUICConn()
	qc.handleStreamFrameIncoming(streamFrame(0, false))
	qc.handleStreamFrameIncoming(streamFrame(0, false))
	if qc.peerBidiStreams != 1 {
		t.Fatalf("peerBidiStreams = %d, want 1", qc.peerBidiStreams)
	}
}

// A STREAM frame carrying a server-initiated stream ID is a PROTOCOL_VIOLATION
// and must close the connection without creating the stream.
func TestServerInitiatedStreamIDRejected(t *testing.T) {
	qc := newTestQUICConn()

	// id % 4 == 1 => server-initiated bidi; the server never opened it.
	qc.handleStreamFrameIncoming(streamFrame(1, true))

	if !qc.closed.Load() {
		t.Fatal("expected connection closed on server-initiated stream ID")
	}
	qc.streamsMu.Lock()
	_, present := qc.streams[1]
	qc.streamsMu.Unlock()
	if present {
		t.Fatal("server-initiated stream must not be stored")
	}
}

// RESET_STREAM tears down the stream, removes it from the map, and releases no
// double slot; the live-stream map must not drift.
func TestResetStreamTeardown(t *testing.T) {
	qc := newTestQUICConn()

	const id = uint64(0)
	qc.handleStreamFrameIncoming(streamFrame(id, false))
	qc.streamsMu.Lock()
	_, present := qc.streams[id]
	qc.streamsMu.Unlock()
	if !present {
		t.Fatal("stream should exist before reset")
	}

	qc.handleResetStream(quicResetStreamFrame{streamID: id, errorCode: 0, finalSize: 0})

	qc.streamsMu.Lock()
	_, present = qc.streams[id]
	n := len(qc.streams)
	qc.streamsMu.Unlock()
	if present {
		t.Fatal("stream should be removed after reset")
	}
	if n != 0 {
		t.Fatalf("stream map size = %d after reset, want 0", n)
	}

	// Reset for an unknown stream must not drift the map or panic.
	qc.handleResetStream(quicResetStreamFrame{streamID: 4, errorCode: 0, finalSize: 0})
	qc.streamsMu.Lock()
	n = len(qc.streams)
	qc.streamsMu.Unlock()
	if n != 0 {
		t.Fatalf("stream map size = %d after reset of unknown stream, want 0", n)
	}
}

// Dispatching a stream acquires a semaphore slot that is released when the
// handler returns; a subsequent RESET_STREAM must not release a second slot
// (no negative/over-release drift).
func TestDispatchSemaphoreReleasedNoDrift(t *testing.T) {
	qc := newTestQUICConn()
	qc.h3 = &H3Conn{} // non-nil so dispatch is attempted

	const id = uint64(0)
	s := newQUICStream(id, qc)
	qc.streamsMu.Lock()
	qc.streams[id] = s
	qc.peerBidiStreams = 1
	qc.streamsMu.Unlock()

	if !s.markDispatched() {
		t.Fatal("first markDispatched should win")
	}
	if s.markDispatched() {
		t.Fatal("second markDispatched must lose")
	}

	// Simulate a dispatch goroutine holding its slot (the handler owns the slot
	// until it returns).
	qc.dispatchSem <- struct{}{}
	if len(qc.dispatchSem) != 1 {
		t.Fatalf("slot count = %d, want 1", len(qc.dispatchSem))
	}

	// RESET_STREAM tears down the stream but must leave the slot count alone.
	qc.handleResetStream(quicResetStreamFrame{streamID: id})
	if len(qc.dispatchSem) != 1 {
		t.Fatalf("slot count after reset = %d, want 1 (no double release)", len(qc.dispatchSem))
	}
	<-qc.dispatchSem
}

// A flood of RESET_STREAM frames beyond the per-connection cap closes the
// connection with the excessive-load error.
func TestResetFloodClosesConnection(t *testing.T) {
	qc := newTestQUICConn()

	for i := uint64(0); i <= quicMaxResetsPerConn; i++ {
		// Distinct client bidi IDs; streams need not exist for the cap to apply.
		qc.handleResetStream(quicResetStreamFrame{streamID: i * 4})
	}

	if !qc.closed.Load() {
		t.Fatal("expected connection closed after reset flood")
	}
	if qc.resetCount <= quicMaxResetsPerConn {
		t.Fatalf("resetCount = %d, want > %d", qc.resetCount, quicMaxResetsPerConn)
	}
}

// Concurrent STREAM and RESET_STREAM processing must be race-free and keep the
// stream map and counters consistent (run under -race).
func TestConcurrentStreamAndResetRaceSafe(t *testing.T) {
	qc := newTestQUICConn()
	qc.h3 = &H3Conn{}

	var wg sync.WaitGroup
	const n = 200
	for i := 0; i < n; i++ {
		id := uint64(i) * 4
		wg.Add(2)
		go func() {
			defer wg.Done()
			qc.handleStreamFrameIncoming(streamFrame(id, false))
		}()
		go func() {
			defer wg.Done()
			qc.handleResetStream(quicResetStreamFrame{streamID: id})
		}()
	}
	wg.Wait()
}
