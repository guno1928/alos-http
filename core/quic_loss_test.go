package core

import (
	"testing"
)

// sentPNs returns the set of packet numbers still tracked as sent (unacked)
// in the given space, for assertions.
func sentPNs(ls *quicLossState, space int) map[uint64]bool {
	out := make(map[uint64]bool, len(ls.sent[space]))
	for i := range ls.sent[space] {
		out[ls.sent[space][i].pn] = true
	}
	return out
}

// TestOnAckReceivedRejectsFirstRangeUnderflow covers the uint64 underflow:
// firstRange > largestAck must be rejected without mutating loss state.
func TestOnAckReceivedRejectsFirstRangeUnderflow(t *testing.T) {
	ls := newQuicLossState()
	ls.onPacketSent(quicSpaceAppData, 0, 100, true, []byte{1})
	ls.onPacketSent(quicSpaceAppData, 1, 100, true, []byte{2})

	ack := quicAckFrame{largestAck: 1, firstRange: 5} // 5 > 1 -> would underflow
	_, err := ls.onAckReceived(quicSpaceAppData, ack, 2, 0)
	if err != errQuicAckInvalid {
		t.Fatalf("expected errQuicAckInvalid, got %v", err)
	}
	if got := len(ls.sent[quicSpaceAppData]); got != 2 {
		t.Fatalf("sent packets must be untouched on reject, got %d", got)
	}
	if ls.largestAcked[quicSpaceAppData] != -1 {
		t.Fatalf("largestAcked must not advance on reject, got %d", ls.largestAcked[quicSpaceAppData])
	}
}

// TestOnAckReceivedRejectsUnsentPacket covers optimistic-ack: acking a packet
// number the endpoint never sent (largestAck >= nextSendPN) must be rejected.
func TestOnAckReceivedRejectsUnsentPacket(t *testing.T) {
	ls := newQuicLossState()
	ls.onPacketSent(quicSpaceAppData, 0, 100, true, []byte{1})
	ls.onPacketSent(quicSpaceAppData, 1, 100, true, []byte{2})

	// nextSendPN is 2 (PNs 0 and 1 were sent); acking PN 5 is optimistic.
	ack := quicAckFrame{largestAck: 5, firstRange: 0}
	_, err := ls.onAckReceived(quicSpaceAppData, ack, 2, 0)
	if err != errQuicAckInvalid {
		t.Fatalf("expected errQuicAckInvalid for unsent PN, got %v", err)
	}
	if ls.largestAcked[quicSpaceAppData] != -1 {
		t.Fatalf("largestAcked must not advance on reject, got %d", ls.largestAcked[quicSpaceAppData])
	}
}

// TestOnAckReceivedRejectsEmptySpace covers the boundary where nothing was sent:
// nextSendPN == 0 so any largestAck (including 0) is an ack of an unsent packet.
func TestOnAckReceivedRejectsEmptySpace(t *testing.T) {
	ls := newQuicLossState()
	ack := quicAckFrame{largestAck: 0, firstRange: 0}
	_, err := ls.onAckReceived(quicSpaceAppData, ack, 0, 0)
	if err != errQuicAckInvalid {
		t.Fatalf("expected errQuicAckInvalid for empty space, got %v", err)
	}
}

// TestOnAckReceivedRejectsRangeGapUnderflow covers the gap/count underflow in a
// subsequent ACK range: a gap larger than the remaining window must be rejected.
func TestOnAckReceivedRejectsRangeGapUnderflow(t *testing.T) {
	ls := newQuicLossState()
	for pn := uint64(0); pn < 4; pn++ {
		ls.onPacketSent(quicSpaceAppData, pn, 100, true, []byte{byte(pn)})
	}
	// largestAck=3, firstRange=0 acks PN 3. lo becomes 3; a gap of 10 would
	// underflow lo-gap-2.
	ack := quicAckFrame{
		largestAck: 3,
		firstRange: 0,
		ranges:     []quicAckRange{{gap: 10, count: 0}},
	}
	_, err := ls.onAckReceived(quicSpaceAppData, ack, 4, 0)
	if err != errQuicAckInvalid {
		t.Fatalf("expected errQuicAckInvalid for gap underflow, got %v", err)
	}
}

// TestOnAckReceivedValidSingleRange confirms a well-formed ACK is still
// processed: the acked packets are removed from the sent set and largestAcked
// advances.
func TestOnAckReceivedValidSingleRange(t *testing.T) {
	ls := newQuicLossState()
	for pn := uint64(0); pn < 3; pn++ {
		ls.onPacketSent(quicSpaceAppData, pn, 100, true, []byte{byte(pn)})
	}
	bytesBefore := ls.bytesInFlight

	// Ack PNs 1..2 (largestAck=2, firstRange=1). PN 0 stays in flight (within
	// the packet-loss threshold so it is not declared lost).
	ack := quicAckFrame{largestAck: 2, firstRange: 1}
	lost, err := ls.onAckReceived(quicSpaceAppData, ack, 3, 0)
	if err != nil {
		t.Fatalf("valid ACK rejected: %v", err)
	}
	if len(lost) != 0 {
		t.Fatalf("expected no lost frames, got %d", len(lost))
	}
	if ls.largestAcked[quicSpaceAppData] != 2 {
		t.Fatalf("largestAcked should be 2, got %d", ls.largestAcked[quicSpaceAppData])
	}
	remaining := sentPNs(ls, quicSpaceAppData)
	if remaining[1] || remaining[2] {
		t.Fatalf("acked PNs 1,2 must be removed, remaining=%v", remaining)
	}
	if !remaining[0] {
		t.Fatalf("unacked PN 0 must remain, remaining=%v", remaining)
	}
	if ls.bytesInFlight != bytesBefore-200 {
		t.Fatalf("bytesInFlight should drop by 200, before=%d after=%d", bytesBefore, ls.bytesInFlight)
	}
}

// TestOnAckReceivedValidMultiRange confirms a multi-range ACK with a real gap
// is processed across both ranges.
func TestOnAckReceivedValidMultiRange(t *testing.T) {
	ls := newQuicLossState()
	for pn := uint64(0); pn < 6; pn++ {
		ls.onPacketSent(quicSpaceAppData, pn, 100, true, []byte{byte(pn)})
	}
	// First range acks PN 5 (largestAck=5, firstRange=0). gap=0 -> next range
	// largest = 5-0-2 = 3, count=0 acks PN 3. PNs 4 (gap) and 0..2 stay.
	ack := quicAckFrame{
		largestAck: 5,
		firstRange: 0,
		ranges:     []quicAckRange{{gap: 0, count: 0}},
	}
	if _, err := ls.onAckReceived(quicSpaceAppData, ack, 6, 0); err != nil {
		t.Fatalf("valid multi-range ACK rejected: %v", err)
	}
	remaining := sentPNs(ls, quicSpaceAppData)
	if remaining[5] || remaining[3] {
		t.Fatalf("acked PNs 5,3 must be removed, remaining=%v", remaining)
	}
	if !remaining[4] {
		t.Fatalf("gap PN 4 must remain, remaining=%v", remaining)
	}
}

// TestOnAckReceivedNoUnderflowFromMaxGap ensures a gap near uint64 max cannot
// overflow the gap+2 addition and slip past the bound check.
func TestOnAckReceivedNoUnderflowFromMaxGap(t *testing.T) {
	ls := newQuicLossState()
	for pn := uint64(0); pn < 4; pn++ {
		ls.onPacketSent(quicSpaceAppData, pn, 100, true, []byte{byte(pn)})
	}
	ack := quicAckFrame{
		largestAck: 3,
		firstRange: 0,
		ranges:     []quicAckRange{{gap: ^uint64(0) - 1, count: 0}}, // gap+2 overflows
	}
	if _, err := ls.onAckReceived(quicSpaceAppData, ack, 4, 0); err != errQuicAckInvalid {
		t.Fatalf("expected errQuicAckInvalid for max-gap overflow, got %v", err)
	}
}
