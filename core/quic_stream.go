package core

import (
	"io"
	"sync"
	"sync/atomic"
)

const (
	quicStreamBidiClient = 0x00
	quicStreamBidiServer = 0x01
	quicStreamUniClient  = 0x02
	quicStreamUniServer  = 0x03
)

func quicStreamType(id uint64) int {
	return int(id & 0x03)
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

	recvBuf    []byte
	recvBufP   *[]byte
	recvOff    uint64
	recvFin    bool
	recvFinOff uint64
	recvClosed bool
	maxRecv    uint64
	recvReady  chan struct{}

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
	return &QUICStream{
		id:      id,
		conn:    conn,
		maxRecv: quicStreamRecvLimit(conn),
		maxSend: 1 << 20,
	}
}

func quicStreamRecvLimit(conn *QUICConn) uint64 {
	limit := uint64(1 << 18)
	if conn != nil && conn.server != nil && conn.server.config.QUICMaxStreamData > 0 {
		limit = uint64(conn.server.config.QUICMaxStreamData)
	}
	return limit
}

var quicStreamPool = sync.Pool{
	New: func() any { return &QUICStream{} },
}

var quicRecvDataPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 2048); return &b },
}

func getPooledStream(id uint64, conn *QUICConn) *QUICStream {
	s := quicStreamPool.Get().(*QUICStream)
	s.id = id
	s.conn = conn
	s.recvBuf = nil
	s.recvBufP = nil
	s.recvOff = 0
	s.recvFin = false
	s.recvFinOff = 0
	s.recvClosed = false
	s.maxRecv = quicStreamRecvLimit(conn)
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
			quicRecvDataPool.Put(s.recvBufP)
			s.recvBufP = nil
		}
		s.conn = nil
		s.recvBuf = nil
		s.sendBuf = nil
		quicStreamPool.Put(s)
	}
}

func (s *QUICStream) handleStreamFrame(f quicStreamFrame) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.recvClosed {
		return false
	}

	if s.recvBufP == nil {
		s.recvBufP = quicRecvDataPool.Get().(*[]byte)
		s.recvBuf = (*s.recvBufP)[:0]
	}

	if f.offset == s.recvOff {
		if uint64(len(s.recvBuf))+uint64(len(f.data)) > s.maxRecv {
			return false
		}
		if len(f.data) > 0 && !s.conn.server.tryReserveBodyBytes(len(f.data)) {
			return false
		}
		s.recvAccounted += int64(len(f.data))
		s.recvBuf = append(s.recvBuf, f.data...)
		s.recvOff += uint64(len(f.data))
	} else if f.offset > s.recvOff {
		needed := f.offset - s.recvOff + uint64(len(f.data))
		if needed > s.maxRecv {
			return false
		}
		if uint64(len(s.recvBuf)) < needed {
			delta := int(needed) - len(s.recvBuf)
			if !s.conn.server.tryReserveBodyBytes(delta) {
				return false
			}
			s.recvAccounted += int64(delta)
			grown := make([]byte, needed)
			copy(grown, s.recvBuf)
			s.recvBuf = grown
		}
		copy(s.recvBuf[f.offset-s.recvOff:], f.data)
	}

	if f.fin {
		s.recvFin = true
		s.recvFinOff = f.offset + uint64(len(f.data))
	}

	if s.recvReady != nil {
		select {
		case s.recvReady <- struct{}{}:
		default:
		}
	}
	return true
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
