package core

import (
	"bytes"
	"testing"
	"time"
)

func TestQUICLostAckOnlyPacketIsNotRetransmittedFromScratch(t *testing.T) {
	ls := newQuicLossState()
	scratch := []byte{quicFrameACK, 1, 0, 0, 1}
	ls.onPacketSent(quicSpaceAppData, 1, 30, false, scratch)
	copy(scratch, []byte{0xde, 0xad, 0xbe, 0xef, 0x00})
	for pn := uint64(2); pn <= 6; pn++ {
		ls.onPacketSent(quicSpaceAppData, pn, 30, true, []byte{quicFramePing})
	}
	lost := ls.onAckReceived(quicSpaceAppData, quicAckFrame{largestAck: 6, firstRange: 4}, 0)
	for _, f := range lost {
		if bytes.Equal(f, []byte{0xde, 0xad, 0xbe, 0xef, 0x00}) {
			t.Fatal("lost non-ack-eliciting packet retransmitted the overwritten scratch buffer")
		}
		if f[0] == quicFrameACK {
			t.Fatal("stale ACK frame scheduled for retransmission")
		}
	}
}

func TestQUICEveryAckElicitingPacketStaysRetransmittable(t *testing.T) {
	ls := newQuicLossState()
	ls.cwnd = 1 << 40
	const sent = quicMaxTrackedSent
	for pn := uint64(0); pn < sent; pn++ {
		ls.onPacketSent(quicSpaceAppData, pn, 1200, true, []byte{quicFramePing})
	}
	if ls.canSend() {
		t.Fatal("canSend must apply backpressure once in-flight packets exceed the window")
	}
	ls.mu.Lock()
	for i := range ls.sent[quicSpaceAppData] {
		ls.sent[quicSpaceAppData][i].sent -= int64(10 * time.Second)
	}
	ls.mu.Unlock()
	frames := ls.ptoExpiredFrames(quicSpaceAppData)
	if len(frames) != sent {
		t.Fatalf("PTO recovered %d of %d ack-eliciting packets; the rest were silently untracked and can never be retransmitted", len(frames), sent)
	}
}
