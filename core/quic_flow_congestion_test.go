package core

import (
	"testing"
	"time"
)

func timeUnix(sec int64) time.Time { return time.Unix(sec, 0) }

// TestQUICStreamFlowControl verifies drainSendBuf never returns more than the
// per-stream or connection window allows and reports "blocked" when no credit
// is available.
func TestQUICStreamFlowControl(t *testing.T) {
	s := &QUICStream{maxSend: 100}
	s.sendBuf = make([]byte, 1000)
	s.sendFin = true // FIN rides the last data chunk once the buffer drains

	// Connection window is the binding limit.
	data, _, _, blocked := s.drainSendBuf(1200, 40)
	if blocked {
		t.Fatal("unexpected block with credit available")
	}
	if len(data) != 40 {
		t.Fatalf("conn window not honored: got %d want 40", len(data))
	}

	// Now the stream window (100 - 40 = 60) is the binding limit.
	data, _, _, blocked = s.drainSendBuf(1200, 1<<20)
	if blocked {
		t.Fatal("unexpected block")
	}
	if len(data) != 60 {
		t.Fatalf("stream window not honored: got %d want 60", len(data))
	}

	// Stream window exhausted (sendOff == maxSend): must report blocked.
	_, _, _, blocked = s.drainSendBuf(1200, 1<<20)
	if !blocked {
		t.Fatal("expected flow-control block at stream window limit")
	}

	// Opening the stream window resumes sending.
	s.maxSend = 1000
	data, _, fin, blocked := s.drainSendBuf(1200, 1<<20)
	if blocked {
		t.Fatal("unexpected block after window opened")
	}
	if len(data) != 900 || !fin {
		t.Fatalf("expected final 900 bytes with fin: got %d fin=%v", len(data), fin)
	}
}

// TestQUICCongestionWindow verifies slow start, congestion avoidance, the
// loss-driven multiplicative decrease, and the canSend gate.
func TestQUICCongestionWindow(t *testing.T) {
	ls := newQuicLossState()
	if ls.cwnd != quicInitialCwnd {
		t.Fatalf("initial cwnd: got %d want %d", ls.cwnd, quicInitialCwnd)
	}
	if !ls.canSend() {
		t.Fatal("should be able to send with empty flight")
	}

	// Slow start: cwnd grows by the acked byte count.
	start := ls.cwnd
	ls.onCongestionAck(3000)
	if ls.cwnd != start+3000 {
		t.Fatalf("slow-start growth: got %d want %d", ls.cwnd, start+3000)
	}

	// canSend gate: once bytesInFlight reaches cwnd, no more may be sent.
	ls.bytesInFlight = ls.cwnd
	if ls.canSend() {
		t.Fatal("should be congestion-blocked at cwnd")
	}
	ls.bytesInFlight = 0

	// Loss halves cwnd (down to the floor) and exits slow start.
	before := ls.cwnd
	ls.onCongestionLoss(timeUnix(2), timeUnix(3))
	want := before / 2
	if want < quicMinCwnd {
		want = quicMinCwnd
	}
	if ls.cwnd != want {
		t.Fatalf("loss decrease: got %d want %d", ls.cwnd, want)
	}
	if ls.ssthresh != want {
		t.Fatalf("ssthresh after loss: got %d want %d", ls.ssthresh, want)
	}

	// A loss from an earlier-than-recovery send time must not re-halve cwnd.
	stable := ls.cwnd
	ls.onCongestionLoss(timeUnix(1), timeUnix(4))
	if ls.cwnd != stable {
		t.Fatalf("loss within recovery period should not reduce cwnd again: got %d want %d", ls.cwnd, stable)
	}
}
