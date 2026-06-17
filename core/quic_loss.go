package core

import "time"

const (
	quicInitialRTT       = 333 * time.Millisecond
	quicMaxAckDelay      = 25 * time.Millisecond
	quicTimerGranularity = time.Millisecond
	quicPktThreshold     = 3
	quicTimeThreshold    = 9.0 / 8.0

	// quicErrFrameEncoding is the QUIC transport error code FRAME_ENCODING_ERROR
	// (RFC 9000 §20.1), used to close the connection when a peer sends a frame
	// with structurally invalid contents (here: an ACK whose ranges underflow or
	// acknowledge packet numbers the endpoint never sent).
	quicErrFrameEncoding = 0x07
)

type quicSentPacket struct {
	pn        uint64
	sent      time.Time
	size      int
	ackElicit bool
	frames    []byte
	inFlight  bool
}

type quicLossState struct {
	smoothedRTT  time.Duration
	rttVar       time.Duration
	minRTT       time.Duration
	firstRTTDone bool

	largestAcked [3]int64
	lossTime     [3]time.Time

	sent          [3][]quicSentPacket
	bytesInFlight int

	ptoCount    int
	ptoTimerSet bool
	ptoDeadline time.Time
}

func newQuicLossState() *quicLossState {
	ls := &quicLossState{
		smoothedRTT: quicInitialRTT,
		rttVar:      quicInitialRTT / 2,
		minRTT:      0,
	}
	ls.largestAcked[0] = -1
	ls.largestAcked[1] = -1
	ls.largestAcked[2] = -1
	return ls
}

func (ls *quicLossState) onPacketSent(space int, pn uint64, size int, ackElicit bool, frames []byte) {
	sp := quicSentPacket{
		pn:        pn,
		sent:      time.Now(),
		size:      size,
		ackElicit: ackElicit,
		frames:    frames,
		inFlight:  ackElicit,
	}
	ls.sent[space] = append(ls.sent[space], sp)
	if ackElicit {
		ls.bytesInFlight += size
	}
}

// onAckReceived processes a peer ACK frame. nextSendPN is the next packet
// number that will be sent in this space (i.e. one past the highest PN ever
// sent), used to reject optimistic acks. All ACK fields are attacker-controlled,
// so every range bound is validated against uint64 underflow before use; on any
// violation the ACK is rejected with errQuicAckInvalid and no state is mutated.
func (ls *quicLossState) onAckReceived(space int, ack quicAckFrame, nextSendPN uint64, ackDelay time.Duration) ([][]byte, error) {
	// Reject acks for packets never sent (optimistic ack): an empty space has
	// nextSendPN == 0 so any largestAck is rejected, otherwise the highest valid
	// PN is nextSendPN-1.
	if ack.largestAck >= nextSendPN {
		return nil, errQuicAckInvalid
	}
	// firstRange counts packets below largestAck; a value exceeding largestAck
	// would underflow the window. (largestAck-firstRange is the lowest PN acked.)
	if ack.firstRange > ack.largestAck {
		return nil, errQuicAckInvalid
	}

	largest := int64(ack.largestAck)
	if largest > ls.largestAcked[space] {
		ls.largestAcked[space] = largest
	}

	var ackedPackets []quicSentPacket
	var lostFrames [][]byte

	lo := ack.largestAck - ack.firstRange
	hi := ack.largestAck
	ackedPackets = ls.markAcked(space, lo, hi, ackedPackets)

	for _, r := range ack.ranges {
		// Each subsequent range walks downward: gap+2 packets must sit below the
		// current lo. Guard the gap test as lo-2 >= gap (rather than lo >= gap+2)
		// so a gap near uint64 max can't overflow the addition and slip through.
		if lo < 2 || r.gap > lo-2 {
			return nil, errQuicAckInvalid
		}
		hi = lo - r.gap - 2
		if r.count > hi {
			return nil, errQuicAckInvalid
		}
		lo = hi - r.count
		ackedPackets = ls.markAcked(space, lo, hi, ackedPackets)
	}

	if len(ackedPackets) > 0 {
		latestRTT := time.Since(ackedPackets[len(ackedPackets)-1].sent)
		ls.updateRTT(latestRTT, ackDelay)
	}

	lostFrames = ls.detectLost(space, lostFrames)

	ls.ptoCount = 0
	return lostFrames, nil
}

func (ls *quicLossState) markAcked(space int, lo, hi uint64, out []quicSentPacket) []quicSentPacket {
	remaining := ls.sent[space][:0]
	for i := range ls.sent[space] {
		sp := &ls.sent[space][i]
		if sp.pn >= lo && sp.pn <= hi {
			if sp.inFlight {
				ls.bytesInFlight -= sp.size
			}
			out = append(out, *sp)
		} else {
			remaining = append(remaining, *sp)
		}
	}
	ls.sent[space] = remaining
	return out
}

func (ls *quicLossState) detectLost(space int, lostFrames [][]byte) [][]byte {
	if ls.largestAcked[space] < 0 {
		return lostFrames
	}
	threshold := uint64(ls.largestAcked[space]) - quicPktThreshold + 1
	lossDelay := time.Duration(float64(max64(ls.smoothedRTT, ls.minRTT)) * quicTimeThreshold)
	if lossDelay < quicTimerGranularity {
		lossDelay = quicTimerGranularity
	}
	cutoff := time.Now().Add(-lossDelay)

	remaining := ls.sent[space][:0]
	for i := range ls.sent[space] {
		sp := &ls.sent[space][i]
		if sp.pn < threshold || sp.sent.Before(cutoff) {
			if sp.inFlight {
				ls.bytesInFlight -= sp.size
			}
			if len(sp.frames) > 0 {
				lostFrames = append(lostFrames, sp.frames)
			}
		} else {
			remaining = append(remaining, *sp)
		}
	}
	ls.sent[space] = remaining
	return lostFrames
}

func (ls *quicLossState) updateRTT(latestRTT, ackDelay time.Duration) {
	if ls.minRTT == 0 || latestRTT < ls.minRTT {
		ls.minRTT = latestRTT
	}

	if !ls.firstRTTDone {
		ls.smoothedRTT = latestRTT
		ls.rttVar = latestRTT / 2
		ls.firstRTTDone = true
		return
	}

	adjustedRTT := latestRTT
	if latestRTT >= ls.minRTT+ackDelay {
		adjustedRTT = latestRTT - ackDelay
	}

	diff := ls.smoothedRTT - adjustedRTT
	if diff < 0 {
		diff = -diff
	}
	ls.rttVar = (3*ls.rttVar + diff) / 4
	ls.smoothedRTT = (7*ls.smoothedRTT + adjustedRTT) / 8
}

func (ls *quicLossState) ptoTimeout() time.Duration {
	pto := ls.smoothedRTT + max64(4*ls.rttVar, quicTimerGranularity) + quicMaxAckDelay
	return pto * time.Duration(1<<uint(ls.ptoCount))
}

func (ls *quicLossState) hasUnackedCrypto(space int) bool {
	for i := range ls.sent[space] {
		if ls.sent[space][i].ackElicit {
			return true
		}
	}
	return false
}

func max64(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
