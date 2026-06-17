package core

import (
	"testing"
)

// newTestStream builds a stream with no backing connection. handleStreamFrame
// only touches stream-local state, so a nil conn is fine for these unit tests.
func newTestStream() *QUICStream {
	return newQUICStream(0, nil)
}

// A STREAM frame whose absolute end offset exceeds the stream receive window
// must be rejected as a flow-control violation and must NOT allocate a buffer
// sized to the attacker-chosen offset.
func TestHandleStreamFrame_HugeOffsetRejected(t *testing.T) {
	s := newTestStream()

	f := quicStreamFrame{
		streamID: 0,
		offset:   1 << 40, // ~1 TiB, far beyond maxRecv (1 MiB)
		data:     []byte("boom"),
	}

	newBytes, flowErr := s.handleStreamFrame(f)
	if !flowErr {
		t.Fatalf("expected flow-control violation for offset %d > maxRecv %d", f.offset, s.maxRecv)
	}
	if newBytes != 0 {
		t.Fatalf("rejected frame must contribute 0 bytes, got %d", newBytes)
	}
	if uint64(len(s.recvBuf)) > s.maxRecv {
		t.Fatalf("buffer grew past maxRecv: len=%d maxRecv=%d", len(s.recvBuf), s.maxRecv)
	}
	if len(s.recvBuf) != 0 {
		t.Fatalf("rejected frame must not buffer anything, got %d bytes", len(s.recvBuf))
	}
}

// offset + len that overflows uint64 must be rejected without wrapping.
func TestHandleStreamFrame_OffsetLengthOverflowRejected(t *testing.T) {
	s := newTestStream()
	s.maxRecv = ^uint64(0) // disable the window bound so only the overflow check fires

	f := quicStreamFrame{
		offset: ^uint64(0) - 1,
		data:   []byte("xx"), // offset+len wraps past 2^64
	}

	_, flowErr := s.handleStreamFrame(f)
	if !flowErr {
		t.Fatal("expected rejection on offset+len uint64 overflow")
	}
	if len(s.recvBuf) != 0 {
		t.Fatalf("overflowing frame must not buffer anything, got %d bytes", len(s.recvBuf))
	}
}

// A duplicate/retransmit (offset < recvOff) must not perform an unsigned
// subtraction that wraps and drives a giant allocation.
func TestHandleStreamFrame_DuplicateNoUnderflow(t *testing.T) {
	s := newTestStream()

	// Deliver the first chunk in order.
	if _, flowErr := s.handleStreamFrame(quicStreamFrame{offset: 0, data: []byte("hello")}); flowErr {
		t.Fatal("unexpected flow error on in-order frame")
	}
	if s.recvOff != 5 {
		t.Fatalf("recvOff = %d, want 5", s.recvOff)
	}

	// Retransmit the exact same bytes (offset 0 < recvOff 5).
	newBytes, flowErr := s.handleStreamFrame(quicStreamFrame{offset: 0, data: []byte("hello")})
	if flowErr {
		t.Fatal("duplicate frame must not be a flow-control error")
	}
	if newBytes != 0 {
		t.Fatalf("pure duplicate must contribute 0 new bytes, got %d", newBytes)
	}
	if uint64(len(s.recvBuf)) > s.maxRecv {
		t.Fatalf("duplicate caused oversized buffer: len=%d (underflow?)", len(s.recvBuf))
	}
	if s.recvOff != 5 {
		t.Fatalf("duplicate moved recvOff to %d, want 5", s.recvOff)
	}
}

// A frame that partially overlaps already-received data (offset < recvOff but
// extends past it) must only count and buffer the new tail, without underflow.
func TestHandleStreamFrame_PartialOverlapTailOnly(t *testing.T) {
	s := newTestStream()

	if _, flowErr := s.handleStreamFrame(quicStreamFrame{offset: 0, data: []byte("hello")}); flowErr {
		t.Fatal("unexpected flow error on in-order frame")
	}

	// offset 2 ("llo world") overlaps "llo" and adds " world".
	newBytes, flowErr := s.handleStreamFrame(quicStreamFrame{offset: 2, data: []byte("llo world")})
	if flowErr {
		t.Fatal("partial overlap must not be a flow-control error")
	}
	if newBytes != 6 { // " world"
		t.Fatalf("partial overlap new bytes = %d, want 6", newBytes)
	}
	if s.recvOff != 11 {
		t.Fatalf("recvOff = %d, want 11", s.recvOff)
	}
	if string(s.recvBuf) != "hello world" {
		t.Fatalf("reassembled %q, want %q", s.recvBuf, "hello world")
	}
}

// In-order delivery accounts exactly the contributed bytes once.
func TestHandleStreamFrame_InOrderAccounting(t *testing.T) {
	s := newTestStream()

	n1, _ := s.handleStreamFrame(quicStreamFrame{offset: 0, data: []byte("abc")})
	n2, _ := s.handleStreamFrame(quicStreamFrame{offset: 3, data: []byte("de")})
	if n1 != 3 || n2 != 2 {
		t.Fatalf("accounting wrong: n1=%d n2=%d, want 3 and 2", n1, n2)
	}
}

// Out-of-order delivery must charge connection flow control against the
// highest received offset, counting each byte once: the gap-filling frame that
// arrives later must contribute 0 new bytes, not re-charge the prefix.
func TestHandleStreamFrame_OutOfOrderNoDoubleCount(t *testing.T) {
	s := newTestStream()

	// Ahead-of-order frame at offset 5 (recvOff still 0).
	nAhead, flowErr := s.handleStreamFrame(quicStreamFrame{offset: 5, data: []byte("world")})
	if flowErr {
		t.Fatal("unexpected flow error on out-of-order frame")
	}
	if nAhead != 10 { // highest offset jumps 0 -> 10
		t.Fatalf("ahead frame new bytes = %d, want 10", nAhead)
	}

	// Now the gap filler at offset 0..5. Highest offset (10) does not advance.
	nFill, flowErr := s.handleStreamFrame(quicStreamFrame{offset: 0, data: []byte("hello")})
	if flowErr {
		t.Fatal("unexpected flow error on gap-filling frame")
	}
	if nFill != 0 {
		t.Fatalf("gap filler must contribute 0 new bytes (no double count), got %d", nFill)
	}
	if s.recvHighOff != 10 {
		t.Fatalf("recvHighOff = %d, want 10 (highest offset must not regress)", s.recvHighOff)
	}
}

// Connection-level flow control: total newly received bytes across streams
// must not exceed maxDataLocal, and the offending frame must close the conn
// with FLOW_CONTROL_ERROR.
func TestHandleStreamFrameIncoming_ConnFlowControl(t *testing.T) {
	qc := newQUICConn(nil, nil, nil, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})
	qc.maxDataLocal = 8 // tiny connection window for the test

	// 5 bytes: within window.
	qc.handleStreamFrameIncoming(quicStreamFrame{streamID: 0, offset: 0, data: []byte("hello")})
	if qc.closed.Load() {
		t.Fatal("connection closed prematurely on in-window data")
	}
	if qc.dataRecv != 5 {
		t.Fatalf("dataRecv = %d, want 5", qc.dataRecv)
	}

	// 4 more bytes on another stream: 5+4=9 > 8 -> must reject and close.
	qc.handleStreamFrameIncoming(quicStreamFrame{streamID: 4, offset: 0, data: []byte("over")})
	if !qc.closed.Load() {
		t.Fatal("connection must close with FLOW_CONTROL when conn window exceeded")
	}
	if qc.dataRecv > qc.maxDataLocal {
		t.Fatalf("dataRecv %d exceeded maxDataLocal %d (limit not enforced)", qc.dataRecv, qc.maxDataLocal)
	}
}
