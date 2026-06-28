package core

import (
	"math"
	"sync"
	"time"
)

const (
	quicInitialRTT        = 333 * time.Millisecond
	quicMaxAckDelay       = 25 * time.Millisecond
	quicTimerGranularity  = time.Millisecond
	quicPktThreshold      = 3
	quicTimeThreshold     = 9.0 / 8.0
)

type quicSentPacket struct {
	pn          uint64
	sent        time.Time
	size        int
	ackElicit   bool
	frames      []byte
	inFlight    bool
}

type quicLossState struct {
	mu sync.Mutex

	smoothedRTT  time.Duration
	rttVar       time.Duration
	minRTT       time.Duration
	firstRTTDone bool

	largestAcked [3]int64
	lossTime     [3]time.Time

	sent          [3][]quicSentPacket
	bytesInFlight int

	cwnd     uint64
	ssthresh uint64

	ptoCount     int
	ptoTimerSet  bool
	ptoDeadline  time.Time
}

func newQuicLossState() *quicLossState {
	ls := &quicLossState{
		smoothedRTT: quicInitialRTT,
		rttVar:      quicInitialRTT / 2,
		minRTT:      0,
		cwnd:        10 * quicMaxPacketSize,
		ssthresh:    math.MaxUint64,
	}
	ls.largestAcked[0] = -1
	ls.largestAcked[1] = -1
	ls.largestAcked[2] = -1
	return ls
}

func (ls *quicLossState) onPacketSent(space int, pn uint64, size int, ackElicit bool, frames []byte) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if len(ls.sent[space]) >= 4096 {
		return
	}
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

func (ls *quicLossState) onAckReceived(space int, ack quicAckFrame, ackDelay time.Duration) [][]byte {
	if ack.firstRange > ack.largestAck {
		return nil
	}

	ls.mu.Lock()
	defer ls.mu.Unlock()

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
		if lo < r.gap+2 {
			break
		}
		hi = lo - r.gap - 2
		if hi < r.count {
			break
		}
		lo = hi - r.count
		ackedPackets = ls.markAcked(space, lo, hi, ackedPackets)
	}

	if len(ackedPackets) > 0 {
		latestRTT := time.Since(ackedPackets[len(ackedPackets)-1].sent)
		ls.updateRTT(latestRTT, ackDelay)
	}

	var ackedInFlight uint64
	for i := range ackedPackets {
		if ackedPackets[i].inFlight {
			ackedInFlight += uint64(ackedPackets[i].size)
		}
	}
	if ackedInFlight > 0 {
		if ls.cwnd < ls.ssthresh {
			ls.cwnd += ackedInFlight
		} else {
			ls.cwnd += quicMaxPacketSize * ackedInFlight / ls.cwnd
		}
	}

	lostFrames = ls.detectLost(space, lostFrames)

	ls.ptoCount = 0
	return lostFrames
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
	la := uint64(ls.largestAcked[space])
	var threshold uint64
	if la+1 > quicPktThreshold {
		threshold = la - quicPktThreshold + 1
	}
	lossDelay := time.Duration(float64(max64(ls.smoothedRTT, ls.minRTT)) * quicTimeThreshold)
	if lossDelay < quicTimerGranularity {
		lossDelay = quicTimerGranularity
	}
	cutoff := time.Now().Add(-lossDelay)

	hadLoss := false
	remaining := ls.sent[space][:0]
	for i := range ls.sent[space] {
		sp := &ls.sent[space][i]
		if sp.pn < threshold || sp.sent.Before(cutoff) {
			if sp.inFlight {
				ls.bytesInFlight -= sp.size
				hadLoss = true
			}
			if len(sp.frames) > 0 {
				lostFrames = append(lostFrames, sp.frames)
			}
		} else {
			remaining = append(remaining, *sp)
		}
	}
	ls.sent[space] = remaining

	if hadLoss {
		ls.ssthresh = ls.cwnd / 2
		if ls.ssthresh < 2*quicMaxPacketSize {
			ls.ssthresh = 2 * quicMaxPacketSize
		}
		ls.cwnd = ls.ssthresh
	}

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

func (ls *quicLossState) canSend() bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return uint64(ls.bytesInFlight) < ls.cwnd
}

func (ls *quicLossState) largestAckedPN(space int) int64 {
	ls.mu.Lock()
	v := ls.largestAcked[space]
	ls.mu.Unlock()
	return v
}

func max64(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
