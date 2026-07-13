package core

import (
	"math"
	"sync"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicInitialRTT       = 100 * time.Millisecond
	quicMaxAckDelay      = 25 * time.Millisecond
	quicTimerGranularity = time.Millisecond
	quicPktThreshold     = 3
	quicTimeThreshold    = 9.0 / 8.0
)

type quicSentPacket struct {
	pn        uint64
	sent      int64
	size      int
	ackElicit bool
	frames    []byte
	framesBuf *[]byte
	inFlight  bool
}

var quicFramePool = sync.Pool{
	New: func() any { b := make([]byte, 0, 256); return &b },
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

	ptoCount    int
	ptoTimerSet bool
	ptoDeadline time.Time
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
	var framesBuf *[]byte
	stored := frames
	if ackElicit && len(frames) > 0 {
		framesBuf = quicFramePool.Get().(*[]byte)
		*framesBuf = append((*framesBuf)[:0], frames...)
		stored = *framesBuf
	}
	now := turbo.Now()
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if len(ls.sent[space]) >= 4096 {
		if framesBuf != nil {
			quicFramePool.Put(framesBuf)
		}
		return
	}
	sp := quicSentPacket{
		pn:        pn,
		sent:      now,
		size:      size,
		ackElicit: ackElicit,
		frames:    stored,
		framesBuf: framesBuf,
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

	var lostFrames [][]byte
	var ackedInFlight uint64
	var newestSent int64
	var anyAcked bool

	lo := ack.largestAck - ack.firstRange
	hi := ack.largestAck
	ls.markAcked(space, lo, hi, &ackedInFlight, &newestSent, &anyAcked)

	for _, r := range ack.ranges {
		if lo < r.gap+2 {
			break
		}
		hi = lo - r.gap - 2
		if hi < r.count {
			break
		}
		lo = hi - r.count
		ls.markAcked(space, lo, hi, &ackedInFlight, &newestSent, &anyAcked)
	}

	if anyAcked && newestSent != 0 {
		latestRTT := turbo.Since(newestSent)
		if latestRTT < quicTimerGranularity {
			latestRTT = quicTimerGranularity
		}
		ls.updateRTT(latestRTT, ackDelay)
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

func (ls *quicLossState) markAcked(space int, lo, hi uint64, ackedInFlight *uint64, newestSent *int64, anyAcked *bool) {
	remaining := ls.sent[space][:0]
	for i := range ls.sent[space] {
		sp := &ls.sent[space][i]
		if sp.pn >= lo && sp.pn <= hi {
			if sp.inFlight {
				ls.bytesInFlight -= sp.size
				*ackedInFlight += uint64(sp.size)
			}
			if sp.sent > *newestSent {
				*newestSent = sp.sent
			}
			*anyAcked = true
			if sp.framesBuf != nil {
				quicFramePool.Put(sp.framesBuf)
			}
		} else {
			remaining = append(remaining, *sp)
		}
	}
	ls.sent[space] = remaining
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
	cutoff := turbo.Now() - int64(lossDelay)

	hadLoss := false
	remaining := ls.sent[space][:0]
	for i := range ls.sent[space] {
		sp := &ls.sent[space][i]
		lost := int64(sp.pn) <= ls.largestAcked[space] && (sp.pn < threshold || sp.sent < cutoff)
		if lost {
			if sp.inFlight {
				ls.bytesInFlight -= sp.size
				hadLoss = true
			}
			if len(sp.frames) > 0 {
				fcopy := make([]byte, len(sp.frames))
				copy(fcopy, sp.frames)
				lostFrames = append(lostFrames, fcopy)
			}
			if sp.framesBuf != nil {
				quicFramePool.Put(sp.framesBuf)
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

// ptoExpiredFrames implements RFC 9002 tail-loss recovery. When ack-eliciting
// packets have been outstanding longer than the probe timeout (no ACK has
// arrived to advance largestAcked past them), they cannot be recovered by
// ACK-based loss detection, so they are surfaced here for retransmission. The
// expired packets are removed from the sent list, their bytes freed from the
// in-flight count, and the PTO backoff counter is bumped.
func (ls *quicLossState) ptoExpiredFrames(space int) [][]byte {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if len(ls.sent[space]) == 0 {
		return nil
	}
	pto := ls.smoothedRTT + max64(4*ls.rttVar, quicTimerGranularity) + quicMaxAckDelay
	pto *= time.Duration(1 << uint(ls.ptoCount))
	cutoff := turbo.Now() - int64(pto)

	var frames [][]byte
	remaining := ls.sent[space][:0]
	for i := range ls.sent[space] {
		sp := &ls.sent[space][i]
		if sp.ackElicit && sp.sent < cutoff {
			if sp.inFlight {
				ls.bytesInFlight -= sp.size
			}
			if len(sp.frames) > 0 {
				fcopy := make([]byte, len(sp.frames))
				copy(fcopy, sp.frames)
				frames = append(frames, fcopy)
			}
			if sp.framesBuf != nil {
				quicFramePool.Put(sp.framesBuf)
			}
		} else {
			remaining = append(remaining, *sp)
		}
	}
	ls.sent[space] = remaining
	if len(frames) > 0 {
		ls.ptoCount++
	}
	return frames
}

func max64(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
