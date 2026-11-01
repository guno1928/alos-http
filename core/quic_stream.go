//go:build linux && amd64

package core

import (
	"io"
	"sync"
	"sync/atomic"

	"github.com/guno1928/turbo"
)

type quicOOOSegment struct {
	off  uint64
	data []byte
}

func (seg *quicOOOSegment) end() uint64 {
	return seg.off + uint64(len(seg.data))
}

const (
	quicMinOOOSegmentCap     = 256
	quicOOOWindowBytesPerGap = 1200
	quicOOOSegmentOverhead   = 64
)

type quicOOOResult uint8

const (
	quicOOOStored quicOOOResult = iota
	quicOOODropped
	quicOOOTooManyGaps
)

func quicStreamIsLocal(id uint64, isServer bool) bool {
	initiator := id & 0x01
	if isServer {
		return initiator == 1
	}
	return initiator == 0
}

func quicStreamIsBidi(id uint64) bool {
	return id&0x02 == 0
}

// QUICStream is a single stream on a QUIC connection, providing buffered
// reads of incoming data and buffered writes of outgoing data.
type QUICStream struct {
	id          uint64
	conn        *QUICConn
	refCount    atomic.Int32
	dispatched  atomic.Bool
	cleanupDone atomic.Bool

	mu sync.Mutex

	recvBuf      []byte
	recvBufP     *[]byte
	recvOOO      quicOOOList
	oooBytes     uint64
	recvMax      uint64
	recvOff      uint64
	recvFin      bool
	recvFinSeen  bool
	recvFinOff   uint64
	recvClosed   bool
	recvOverflow bool
	maxRecv      uint64
	recvWindow   uint64
	recvGranted  uint64
	recvReady    chan struct{}

	sendBuf         []byte
	sendOff         uint64
	sendFin         bool
	sendClosed      bool
	maxSend         uint64
	blockedSent     uint64
	stalledSend     int64
	stallSince      int64
	awaitingCleanup bool
	recvAccounted   int64

	recvReset   bool
	sendReset   bool
	inHandler   bool
	peerAborted bool
	cancel      cancelSlot
}

func newQUICStream(id uint64, conn *QUICConn) *QUICStream {
	window := quicStreamRecvLimit(conn)
	return &QUICStream{
		id:          id,
		conn:        conn,
		maxRecv:     quicStreamRecvCap(conn, window),
		recvWindow:  window,
		recvGranted: window,
		maxSend:     quicDefaultStreamSendWindow,
	}
}

const quicDefaultStreamSendWindow = 1 << 20

func quicStreamRecvLimit(conn *QUICConn) uint64 {
	limit := uint64(1 << 18)
	if conn != nil && conn.server != nil && conn.server.config.QUICMaxStreamData > 0 {
		limit = uint64(conn.server.config.QUICMaxStreamData)
	}
	return limit
}

const (
	quicStreamRecvUnlimitedCap = uint64(1) << 62
	quicStreamRecvFrameSlack   = 16 << 10
)

func quicStreamRecvCap(conn *QUICConn, window uint64) uint64 {
	if conn == nil || conn.server == nil {
		return window
	}
	limits := conn.server.limits.Load()
	if limits.MaxBodySize < 0 {
		return quicStreamRecvUnlimitedCap
	}
	capBytes := uint64(limits.MaxBodySize) + uint64(limits.MaxHeaderSize) + quicStreamRecvFrameSlack
	if capBytes < window {
		return window
	}
	return capBytes
}

const (
	quicRecvAccepted = 1 << iota
	quicRecvEndOfData
	quicRecvViolation
	quicRecvRejected
	quicRecvFinalSizeError
)

var quicStreamPool = sync.Pool{
	New: func() any { return &QUICStream{} },
}

const quicRecvDataPoolMaxCap = 64 << 10

var quicRecvDataPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 2048); return &b },
}

func getPooledStream(id uint64, conn *QUICConn) *QUICStream {
	s := quicStreamPool.Get().(*QUICStream)
	s.id = id
	s.conn = conn
	s.recvBuf = nil
	s.recvBufP = nil
	s.recvOOO = quicOOOList{}
	s.oooBytes = 0
	s.recvMax = 0
	s.recvOff = 0
	s.recvFin = false
	s.recvFinSeen = false
	s.recvFinOff = 0
	s.recvClosed = false
	s.recvOverflow = false
	s.recvWindow = quicStreamRecvLimit(conn)
	s.recvGranted = s.recvWindow
	s.maxRecv = quicStreamRecvCap(conn, s.recvWindow)
	s.recvReady = nil
	s.sendBuf = nil
	s.sendOff = 0
	s.sendFin = false
	s.sendClosed = false
	s.maxSend = conn.peerStreamWindow
	s.blockedSent = 0
	s.stalledSend = 0
	s.stallSince = 0
	s.awaitingCleanup = false
	s.recvAccounted = 0
	s.recvReset = false
	s.sendReset = false
	s.inHandler = false
	s.peerAborted = false
	if s.cancel.p.Load() != nil {
		s.cancel.p.Store(nil)
	}
	s.refCount.Store(0)
	s.dispatched.Store(false)
	s.cleanupDone.Store(false)
	return s
}

func (qc *QUICConn) releaseStream(s *QUICStream) {
	if s.refCount.Add(-1) == 0 {
		if s.conn != nil && s.recvAccounted > 0 {
			s.conn.server.releaseConnBodyBytes(&s.conn.bodyReserved, s.recvAccounted)
			s.recvAccounted = 0
		}
		if s.recvBufP != nil {
			putBoxedBufCapped(&quicRecvDataPool, s.recvBufP, quicRecvDataPoolMaxCap)
			s.recvBufP = nil
		}
		s.conn = nil
		s.recvBuf = nil
		s.recvOOO = quicOOOList{}
		s.sendBuf = nil
		quicStreamPool.Put(s)
	}
}

func (s *QUICStream) handleStreamFrame(f quicStreamFrame) (accepted int, flags int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.recvClosed || s.recvOverflow {
		return 0, 0
	}

	end := f.offset + uint64(len(f.data))
	if end > s.recvGranted {
		return 0, quicRecvViolation
	}
	if s.violatesFinalSizeLocked(end, f.fin) {
		return 0, quicRecvFinalSizeError
	}
	if end > s.recvMax {
		if s.conn != nil && !s.conn.consumeRecvFlowCredit(end-s.recvMax) {
			return 0, quicRecvViolation
		}
		s.recvMax = end
	}

	if s.recvBufP == nil {
		s.recvBufP = quicRecvDataPool.Get().(*[]byte)
		s.recvBuf = (*s.recvBufP)[:0]
	}

	if len(f.data) > 0 && end > s.recvOff {
		if f.offset < s.recvOff {
			trim := s.recvOff - f.offset
			f.data = f.data[trim:]
			f.offset = s.recvOff
		}
		if f.offset == s.recvOff {
			if !s.appendContig(f.data) {
				return 0, s.rejectRecvLocked()
			}
			accepted = len(f.data)
			if s.recvOOO.len() > 0 {
				s.coalesceOOO()
			}
		} else {
			n, result := s.insertOOO(f.offset, f.data)
			switch result {
			case quicOOOTooManyGaps, quicOOODropped:
				return 0, s.rejectRecvLocked()
			}
			accepted = n
		}
	}

	flags = quicRecvAccepted
	if f.fin {
		s.recvFinSeen = true
		s.recvFinOff = end
	}
	if s.recvFinSeen && s.recvOff >= s.recvFinOff {
		s.recvFin = true
	}
	if !s.recvFin && s.recvOff >= s.maxRecv {
		s.recvOverflow = true
		s.recvFin = true
	}
	if s.recvFin {
		flags |= quicRecvEndOfData
	}

	if s.recvReady != nil {
		select {
		case s.recvReady <- struct{}{}:
		default:
		}
	}
	return accepted, flags
}

func (s *QUICStream) violatesFinalSizeLocked(end uint64, fin bool) bool {
	if s.recvFinSeen {
		return end > s.recvFinOff || fin && end != s.recvFinOff
	}
	return fin && end < s.recvMax
}

func (s *QUICStream) rejectRecvLocked() int {
	s.recvClosed = true
	return quicRecvRejected
}

func (s *QUICStream) unreceivedCredit() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, unique := s.receivedExtent()
	if s.recvGranted <= unique {
		return 0
	}
	return s.recvGranted - unique
}

func (s *QUICStream) streamCreditToGrant() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recvFinSeen || s.recvGranted >= s.maxRecv || s.recvOff+s.recvWindow/2 <= s.recvGranted {
		return 0
	}
	grant := s.recvOff + s.recvWindow
	if grant > s.maxRecv {
		grant = s.maxRecv
	}
	s.recvGranted = grant
	return grant
}

func (s *QUICStream) overflowed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recvOverflow
}

func (s *QUICStream) outstanding() uint64 {
	return uint64(len(s.recvBuf)) + s.oooBytes
}

func (s *QUICStream) reserve(n int) bool {
	if n <= 0 {
		return true
	}
	if s.outstanding()+uint64(n) > s.maxRecv {
		return false
	}
	if s.conn != nil && s.conn.server != nil && !s.conn.server.tryReserveConnBodyBytes(&s.conn.bodyReserved, n) {
		return false
	}
	s.recvAccounted += int64(n)
	return true
}

func (s *QUICStream) releaseReserved(n int) {
	if n <= 0 {
		return
	}
	if s.conn != nil && s.conn.server != nil {
		s.conn.server.releaseConnBodyBytes(&s.conn.bodyReserved, int64(n))
	}
	s.recvAccounted -= int64(n)
	if s.recvAccounted < 0 {
		s.recvAccounted = 0
	}
}

func (s *QUICStream) appendContig(data []byte) bool {
	if !s.reserve(len(data)) {
		return false
	}
	s.recvBuf = append(s.recvBuf, data...)
	s.recvOff += uint64(len(data))
	return true
}

func (s *QUICStream) oooSegmentCap() int {
	return max(quicMinOOOSegmentCap, int(s.recvWindow/quicOOOWindowBytesPerGap))
}

func (s *QUICStream) oooNewBytes(first quicOOOPos, off, end uint64) (newBytes uint64, opensSegment bool) {
	pos := off
	for p := first; pos < end; p = s.recvOOO.next(p) {
		seg := s.recvOOO.at(p)
		gapEnd := end
		if seg != nil && seg.off < end {
			gapEnd = seg.off
		}
		if gapEnd > pos {
			if pos == off {
				prev := s.recvOOO.before(first)
				opensSegment = prev == nil || prev.end() != off
			}
			newBytes += gapEnd - pos
		}
		if seg == nil || seg.off >= end {
			break
		}
		pos = seg.end()
	}
	return newBytes, opensSegment
}

func (s *QUICStream) insertOOO(off uint64, data []byte) (int, quicOOOResult) {
	end := off + uint64(len(data))
	first := s.recvOOO.firstEndingAfter(off)
	newBytes, opensSegment := s.oooNewBytes(first, off, end)
	if newBytes == 0 {
		return 0, quicOOOStored
	}
	if opensSegment && s.recvOOO.len() >= s.oooSegmentCap() {
		return 0, quicOOOTooManyGaps
	}
	if !s.reserve(int(newBytes)) {
		return 0, quicOOODropped
	}
	if opensSegment && !s.reserveSegmentOverhead() {
		s.releaseReserved(int(newBytes))
		return 0, quicOOODropped
	}
	pos := off
	prev := s.recvOOO.before(first)
	for p := first; pos < end; p = s.recvOOO.next(p) {
		seg := s.recvOOO.at(p)
		gapEnd := end
		if seg != nil && seg.off < end {
			gapEnd = seg.off
		}
		if gapEnd > pos {
			piece := data[pos-off : gapEnd-off]
			if prev != nil && prev.end() == pos {
				prev.data = append(prev.data, piece...)
			} else {
				p = s.recvOOO.next(s.recvOOO.insert(p, quicOOOSegment{off: pos, data: append([]byte(nil), piece...)}))
				seg = s.recvOOO.at(p)
			}
		}
		if seg == nil || seg.off >= end {
			break
		}
		pos = seg.end()
		prev = seg
	}
	s.oooBytes += newBytes
	return int(newBytes), quicOOOStored
}

func (s *QUICStream) reserveSegmentOverhead() bool {
	if s.conn != nil && s.conn.server != nil && !s.conn.server.tryReserveConnBodyBytes(&s.conn.bodyReserved, quicOOOSegmentOverhead) {
		return false
	}
	s.recvAccounted += quicOOOSegmentOverhead
	return true
}

func (s *QUICStream) coalesceOOO() {
	consumed := 0
	for p := (quicOOOPos{}); consumed < s.recvOOO.len(); p = s.recvOOO.next(p) {
		seg := s.recvOOO.at(p)
		if seg.off > s.recvOff {
			break
		}
		consumed++
		s.oooBytes -= uint64(len(seg.data))
		s.releaseReserved(quicOOOSegmentOverhead)
		segEnd := seg.end()
		if segEnd <= s.recvOff {
			s.releaseReserved(len(seg.data))
			continue
		}
		start := s.recvOff - seg.off
		s.releaseReserved(int(start))
		s.recvBuf = append(s.recvBuf, seg.data[start:]...)
		s.recvOff = segEnd
	}
	if consumed > 0 {
		s.recvOOO.dropFront(consumed)
	}
}

// Read copies received stream data into p, blocking until data arrives,
// the stream is closed, or the peer has finished sending, in which case
// it returns io.EOF.
func (s *QUICStream) Read(p []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.recvBuf) > 0 {
			n := copy(p, s.recvBuf)
			s.recvBuf = s.recvBuf[n:]
			atFin := s.recvFin && len(s.recvBuf) == 0
			s.mu.Unlock()
			if atFin {
				return n, io.EOF
			}
			return n, nil
		}
		if s.recvFin {
			s.mu.Unlock()
			return 0, io.EOF
		}
		if s.recvClosed {
			s.mu.Unlock()
			return 0, io.EOF
		}
		if s.recvReady == nil {
			s.recvReady = make(chan struct{}, 1)
		}
		ch := s.recvReady
		s.mu.Unlock()

		<-ch
	}
}

// ReadAll blocks until the peer finishes sending or the stream is closed,
// then returns all data received so far.
func (s *QUICStream) ReadAll() ([]byte, error) {
	return s.readAll(false)
}

func (s *QUICStream) readRequest() ([]byte, error) {
	return s.readAll(true)
}

func (s *QUICStream) readAll(startHandler bool) ([]byte, error) {
	for {
		s.mu.Lock()
		if s.recvFin || s.recvClosed {
			buf := s.recvBuf
			s.recvBuf = nil
			if startHandler {
				s.inHandler = true
				if s.peerAborted {
					s.cancel.cancel(ErrClientGone)
				}
			}
			s.mu.Unlock()
			return buf, nil
		}
		if s.recvReady == nil {
			s.recvReady = make(chan struct{}, 1)
		}
		ch := s.recvReady
		s.mu.Unlock()
		<-ch
	}
}

// Write appends data to the stream's outgoing buffer for later
// transmission. It returns ErrStreamClosed if the stream has already
// been closed or its send side finished.
func (s *QUICStream) Write(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sendClosed || s.sendFin {
		return ErrStreamClosed
	}

	s.sendBuf = append(s.sendBuf, data...)
	return nil
}

func (s *QUICStream) setSendBuf(data []byte) {
	s.mu.Lock()
	if !s.sendClosed {
		s.sendBuf = data
	}
	s.sendFin = true
	s.mu.Unlock()
}

func (s *QUICStream) sendBufDrained() bool {
	s.mu.Lock()
	empty := len(s.sendBuf) == 0
	s.mu.Unlock()
	return empty
}

// FinishWrite marks the stream's send side as finished, so the outgoing
// buffer is sent with a FIN once fully drained.
func (s *QUICStream) FinishWrite() {
	s.mu.Lock()
	s.sendFin = true
	s.mu.Unlock()
}

// Close marks both the receive and send sides of the stream as closed
// and wakes any goroutine blocked in Read or ReadAll.
func (s *QUICStream) Close() {
	s.mu.Lock()
	s.recvClosed = true
	s.sendClosed = true
	s.sendBuf = nil
	s.releaseStalledLocked(s.stalledSend)
	if s.recvReady != nil {
		select {
		case s.recvReady <- struct{}{}:
		default:
		}
	}
	s.mu.Unlock()
}

func (s *QUICStream) drainSendBuf(maxBytes int) (data []byte, offset uint64, fin bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sendReset {
		return nil, s.sendOff, false
	}
	if len(s.sendBuf) == 0 {
		if s.sendFin && !s.sendClosed {
			return nil, s.sendOff, true
		}
		return nil, s.sendOff, false
	}

	n := len(s.sendBuf)
	if n > maxBytes {
		n = maxBytes
	}

	data = s.sendBuf[:n:n]
	offset = s.sendOff
	s.sendBuf = s.sendBuf[n:]
	s.sendOff += uint64(n)
	if s.stalledSend > 0 {
		s.releaseStalledLocked(min(int64(n), s.stalledSend))
	}

	fin = s.sendFin && len(s.sendBuf) == 0
	return data, offset, fin
}

func (s *QUICStream) receivedExtent() (highest, unique uint64) {
	highest = s.recvOff
	if s.recvOOO.len() > 0 {
		highest = s.recvOOO.last().end()
	}
	return highest, s.recvOff + s.oooBytes
}

func (s *QUICStream) applyPeerReset(finalSize uint64) (uncounted uint64, errCode uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	highest, unique := s.receivedExtent()
	if (s.recvFinSeen && finalSize != s.recvFinOff) || finalSize < max(highest, s.recvMax) {
		return 0, quicErrFinalSize
	}
	if finalSize > s.recvGranted {
		return 0, quicErrFlowControl
	}
	if finalSize > s.recvMax {
		if s.conn != nil && !s.conn.consumeRecvFlowCredit(finalSize-s.recvMax) {
			return 0, quicErrFlowControl
		}
		s.recvMax = finalSize
	}
	if s.recvReset {
		return 0, 0
	}
	s.recvReset = true
	s.recvFinSeen = true
	s.recvFinOff = finalSize
	s.recvClosed = true
	if s.recvReady != nil {
		select {
		case s.recvReady <- struct{}{}:
		default:
		}
	}
	return finalSize - unique, 0
}

func (s *QUICStream) takeReceived() (data []byte, fin bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data = s.recvBuf
	s.recvBuf = s.recvBuf[:0]
	s.releaseReserved(len(data))
	return data, s.recvFin
}

func (s *QUICStream) resetSend() (finalSize uint64, first bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendReset {
		return s.sendOff, false
	}
	s.sendReset = true
	s.sendClosed = true
	s.sendBuf = nil
	s.releaseStalledLocked(s.stalledSend)
	return s.sendOff, true
}

func (s *QUICStream) beginStalledAccounting(now int64) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := int64(len(s.sendBuf)) - s.stalledSend
	if pending <= 0 {
		return 0
	}
	if s.stalledSend == 0 {
		s.stallSince = now
	}
	s.stalledSend += pending
	return pending
}

func (s *QUICStream) stallStart() (since int64, stalled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stallSince, s.stalledSend > 0
}

func (s *QUICStream) releaseStalledLocked(n int64) {
	if n <= 0 || s.conn == nil {
		return
	}
	now := turbo.UnixNano()
	s.stalledSend -= n
	s.stallSince = now
	s.conn.stalledSendBytes.Add(-n)
	s.conn.lastSendProgress.Store(now)
}

func (s *QUICStream) beginHandler(req *Request) {
	s.cancel.attach(req)
}

func (s *QUICStream) endHandler(req *Request) {
	req.finishContext()
}

func (s *QUICStream) handlerFinishedLocked() {
	s.inHandler = false
}

func (s *QUICStream) abortHandler(cause error) {
	s.mu.Lock()
	s.peerAborted = true
	if s.inHandler {
		s.cancel.cancel(cause)
	}
	s.mu.Unlock()
}
