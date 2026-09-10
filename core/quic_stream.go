package core

import (
	"io"
	"sort"
	"sync"
	"sync/atomic"
)

type quicOOOSegment struct {
	off  uint64
	data []byte
}

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
	recvOOO      []quicOOOSegment
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
	awaitingCleanup bool
	recvAccounted   int64
}

func newQUICStream(id uint64, conn *QUICConn) *QUICStream {
	window := quicStreamRecvLimit(conn)
	return &QUICStream{
		id:          id,
		conn:        conn,
		maxRecv:     quicStreamRecvCap(conn, window),
		recvWindow:  window,
		recvGranted: window,
		maxSend:     1 << 20,
	}
}

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
	cfg := &conn.server.config
	if cfg.MaxBodySize < 0 {
		return quicStreamRecvUnlimitedCap
	}
	capBytes := uint64(cfg.MaxBodySize) + uint64(cfg.MaxHeaderSize) + quicStreamRecvFrameSlack
	if capBytes < window {
		return window
	}
	return capBytes
}

const (
	quicRecvAccepted = 1 << iota
	quicRecvEndOfData
	quicRecvViolation
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
	s.recvOOO = nil
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
	s.maxSend = 1 << 20
	if conn.peerStreamWindow > 0 {
		s.maxSend = conn.peerStreamWindow
	}
	s.blockedSent = 0
	s.awaitingCleanup = false
	s.recvAccounted = 0
	s.refCount.Store(0)
	s.dispatched.Store(false)
	s.cleanupDone.Store(false)
	return s
}

func (qc *QUICConn) releaseStream(s *QUICStream) {
	if s.refCount.Add(-1) == 0 {
		if s.conn != nil && s.recvAccounted > 0 {
			s.conn.server.releaseBodyBytes(s.recvAccounted)
			s.recvAccounted = 0
		}
		if s.recvBufP != nil {
			putBoxedBufCapped(&quicRecvDataPool, s.recvBufP, quicRecvDataPoolMaxCap)
			s.recvBufP = nil
		}
		s.conn = nil
		s.recvBuf = nil
		s.recvOOO = nil
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
				return 0, 0
			}
			accepted = len(f.data)
			s.coalesceOOO()
		} else {
			n, ok := s.insertOOO(f.offset, f.data)
			if !ok {
				return 0, 0
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
	total := uint64(len(s.recvBuf))
	for i := range s.recvOOO {
		total += uint64(len(s.recvOOO[i].data))
	}
	return total
}

func (s *QUICStream) reserve(n int) bool {
	if n <= 0 {
		return true
	}
	if s.outstanding()+uint64(n) > s.maxRecv {
		return false
	}
	if s.conn != nil && s.conn.server != nil && !s.conn.server.tryReserveBodyBytes(n) {
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
		s.conn.server.releaseBodyBytes(int64(n))
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

func (s *QUICStream) insertOOO(off uint64, data []byte) (int, bool) {
	end := off + uint64(len(data))
	pos := off
	var additions []quicOOOSegment
	for i := range s.recvOOO {
		seg := s.recvOOO[i]
		if pos >= end || seg.off >= end {
			break
		}
		segEnd := seg.off + uint64(len(seg.data))
		if segEnd <= pos {
			continue
		}
		if seg.off > pos {
			additions = append(additions, quicOOOSegment{off: pos, data: data[pos-off : seg.off-off]})
		}
		if segEnd > pos {
			pos = segEnd
		}
	}
	if pos < end {
		additions = append(additions, quicOOOSegment{off: pos, data: data[pos-off:]})
	}
	total := 0
	for i := range additions {
		total += len(additions[i].data)
	}
	if total == 0 {
		return 0, true
	}
	if !s.reserve(total) {
		return 0, false
	}
	for i := range additions {
		s.recvOOO = append(s.recvOOO, quicOOOSegment{off: additions[i].off, data: append([]byte(nil), additions[i].data...)})
	}
	sort.Slice(s.recvOOO, func(a, b int) bool { return s.recvOOO[a].off < s.recvOOO[b].off })
	return total, true
}

func (s *QUICStream) coalesceOOO() {
	i := 0
	for i < len(s.recvOOO) {
		seg := s.recvOOO[i]
		if seg.off > s.recvOff {
			break
		}
		segEnd := seg.off + uint64(len(seg.data))
		if segEnd <= s.recvOff {
			s.releaseReserved(len(seg.data))
			i++
			continue
		}
		start := s.recvOff - seg.off
		s.releaseReserved(int(start))
		s.recvBuf = append(s.recvBuf, seg.data[start:]...)
		s.recvOff = segEnd
		i++
	}
	if i > 0 {
		s.recvOOO = append(s.recvOOO[:0], s.recvOOO[i:]...)
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
	for {
		s.mu.Lock()
		if s.recvFin || s.recvClosed {
			buf := s.recvBuf
			s.recvBuf = nil
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
	s.sendBuf = data
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

	fin = s.sendFin && len(s.sendBuf) == 0
	return data, offset, fin
}
