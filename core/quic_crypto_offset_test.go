package core

import "testing"

// newCryptoTestConn builds a minimal QUICConn suitable for exercising
// handleCryptoFrame in isolation. It has no encryption keys, so any
// sendConnectionClose triggered by the reject path is a no-op (sendFrames
// returns early when no valid keys exist) rather than touching the network.
func newCryptoTestConn() *QUICConn {
	return &QUICConn{
		tlsState: &quicTLSState{},
		done:     make(chan struct{}),
		streams:  make(map[uint64]*QUICStream),
	}
}

// TestHandleCryptoFrameHugeOffsetRejected verifies that a single CRYPTO frame
// carrying an attacker-controlled offset far beyond the handshake buffer cap is
// rejected before any reassembly buffer is allocated, and that the connection
// is torn down (finding C1: pre-auth OOM via CRYPTO frame offset).
func TestHandleCryptoFrameHugeOffsetRejected(t *testing.T) {
	qc := newCryptoTestConn()

	// offset=2^40 with a single data byte previously caused make([]byte, ~1TB).
	qc.handleCryptoFrame(quicSpaceInitial, quicCryptoFrame{
		offset: 1 << 40,
		data:   []byte{0x01},
	})

	if got := len(qc.cryptoBuf[quicSpaceInitial]); got != 0 {
		t.Fatalf("crypto buffer was allocated despite oversized offset: len=%d", got)
	}
	if got := len(qc.cryptoRcv[quicSpaceInitial]); got != 0 {
		t.Fatalf("crypto rcv bitmap was allocated despite oversized offset: len=%d", got)
	}
	if !qc.closed.Load() {
		t.Fatalf("connection was not closed after oversized CRYPTO offset")
	}
}

// TestHandleCryptoFrameOffsetOverflowRejected verifies that an offset+length
// combination that would wrap uint64 is rejected before allocation. With
// offset just under the cap and a length pushing past it, the subtraction guard
// (uint64(len(f.data)) > quicMaxCryptoBuffer-f.offset) must trip.
func TestHandleCryptoFrameOffsetOverflowRejected(t *testing.T) {
	qc := newCryptoTestConn()

	// offset at the cap, any non-empty data exceeds quicMaxCryptoBuffer-offset (==0).
	qc.handleCryptoFrame(quicSpaceInitial, quicCryptoFrame{
		offset: quicMaxCryptoBuffer,
		data:   []byte{0x01},
	})

	if got := len(qc.cryptoBuf[quicSpaceInitial]); got != 0 {
		t.Fatalf("crypto buffer was allocated despite overflow-prone frame: len=%d", got)
	}
	if !qc.closed.Load() {
		t.Fatalf("connection was not closed after overflow-prone CRYPTO frame")
	}
}

// TestHandleCryptoFrameWithinBoundAccepted verifies the happy path still works:
// a small, in-bounds CRYPTO frame is buffered without closing the connection.
func TestHandleCryptoFrameWithinBoundAccepted(t *testing.T) {
	qc := newCryptoTestConn()

	qc.handleCryptoFrame(quicSpaceInitial, quicCryptoFrame{
		offset: 0,
		data:   []byte{0x16, 0x00, 0x00, 0x00}, // not a complete message; just buffered
	})

	if got := len(qc.cryptoBuf[quicSpaceInitial]); got != 4 {
		t.Fatalf("expected crypto buffer of len 4, got %d", got)
	}
	if qc.closed.Load() {
		t.Fatalf("connection was unexpectedly closed for an in-bounds CRYPTO frame")
	}
}
