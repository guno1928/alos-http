package core

import (
	"log"
	"sync"
	"time"

	"github.com/guno1928/turbo"
)

const (
	quicTimerTick      = 2 * time.Millisecond
	quicIdleCheckEvery = int64(time.Second)
)

type quicTimerHub struct {
	mu       sync.Mutex
	conns    map[*QUICConn]struct{}
	snapshot []*QUICConn
	started  bool
}

func (h *quicTimerHub) add(qc *QUICConn, done <-chan struct{}) {
	h.mu.Lock()
	if h.conns == nil {
		h.conns = make(map[*QUICConn]struct{}, 256)
	}
	h.conns[qc] = struct{}{}
	start := !h.started
	h.started = true
	h.mu.Unlock()
	if start {
		go h.run(done)
	}
}

func (h *quicTimerHub) remove(qc *QUICConn) {
	h.mu.Lock()
	delete(h.conns, qc)
	h.mu.Unlock()
}

func (h *quicTimerHub) run(done <-chan struct{}) {
	ticker := time.NewTicker(quicTimerTick)
	defer ticker.Stop()
	var lastIdleCheck int64
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}
		now := turbo.UnixNano()
		checkIdle := now-lastIdleCheck >= quicIdleCheckEvery
		if checkIdle {
			lastIdleCheck = now
		}
		h.mu.Lock()
		h.snapshot = h.snapshot[:0]
		for qc := range h.conns {
			h.snapshot = append(h.snapshot, qc)
		}
		h.mu.Unlock()
		for _, qc := range h.snapshot {
			qc.tick(now, checkIdle)
		}
	}
}

func (qc *QUICConn) tick(now int64, checkIdle bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[QUIC-PANIC] timer tick: %v", r)
		}
	}()
	if checkIdle && qc.idleTimeout > 0 && time.Duration(now-qc.lastActive.Load()) > qc.idleTimeout {
		qc.close()
		return
	}
	if !qc.timerWork.Swap(false) {
		return
	}
	qc.flushPendingAck(quicSpaceAppData)
	for _, frames := range qc.loss.ptoExpiredFrames(quicSpaceAppData) {
		qc.sendFrames(quicSpaceAppData, frames, true)
	}
	qc.writeMu.Lock()
	if len(qc.coalesceEnds) > 0 {
		qc.drainCoalescedLocked()
	}
	pending := len(qc.pendingAck[quicSpaceAppData]) > 0 || len(qc.coalesceEnds) > 0
	qc.writeMu.Unlock()
	if pending || qc.loss.hasSentPackets(quicSpaceAppData) {
		qc.timerWork.Store(true)
	}
}
