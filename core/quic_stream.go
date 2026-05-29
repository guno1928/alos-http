package core

import (
	"io"
	"sync"
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

type QUICStream struct {
	id   uint64
	conn *QUICConn

	mu sync.Mutex

	recvBuf    []byte
	recvOff    uint64
	recvFin    bool
	recvFinOff uint64
	recvClosed bool
	maxRecv    uint64
	recvReady  chan struct{}

	sendBuf    []byte
	sendOff    uint64
	sendFin    bool
	sendClosed bool
	maxSend    uint64
}

func newQUICStream(id uint64, conn *QUICConn) *QUICStream {
	return &QUICStream{
		id:        id,
		conn:      conn,
		maxRecv:   1 << 20,
		maxSend:   1 << 20,
		recvReady: make(chan struct{}, 1),
	}
}

func (s *QUICStream) handleStreamFrame(f quicStreamFrame) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.recvClosed {
		return
	}

	if f.offset == s.recvOff {
		s.recvBuf = append(s.recvBuf, f.data...)
		s.recvOff += uint64(len(f.data))
	} else if f.offset > s.recvOff {
		needed := f.offset - s.recvOff + uint64(len(f.data))
		if uint64(len(s.recvBuf)) < needed {
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

	select {
	case s.recvReady <- struct{}{}:
	default:
	}
}

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
		s.mu.Unlock()

		<-s.recvReady
	}
}

func (s *QUICStream) ReadAll() ([]byte, error) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := s.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err == io.EOF {
				return buf, nil
			}
			return buf, err
		}
	}
}

func (s *QUICStream) Write(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sendClosed || s.sendFin {
		return ErrStreamClosed
	}

	s.sendBuf = append(s.sendBuf, data...)
	return nil
}

func (s *QUICStream) FinishWrite() {
	s.mu.Lock()
	s.sendFin = true
	s.mu.Unlock()
}

func (s *QUICStream) Close() {
	s.mu.Lock()
	s.recvClosed = true
	s.sendClosed = true
	s.mu.Unlock()

	select {
	case s.recvReady <- struct{}{}:
	default:
	}
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

	data = make([]byte, n)
	copy(data, s.sendBuf[:n])
	offset = s.sendOff
	s.sendBuf = s.sendBuf[n:]
	s.sendOff += uint64(n)

	fin = s.sendFin && len(s.sendBuf) == 0
	return data, offset, fin
}
