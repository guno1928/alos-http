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

	recvBuf     []byte
	recvOff     uint64
	recvHighOff uint64
	recvFin     bool
	recvFinOff  uint64
	recvClosed  bool
	maxRecv     uint64
	recvReady   chan struct{}

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
		maxRecv:   quicInitialMaxStreamData,
		maxSend:   quicInitialMaxStreamData,
		recvReady: make(chan struct{}, 1),
	}
}

// handleStreamFrame ingests a received STREAM frame, enforcing stream-level
// receive flow control. It returns the number of newly received bytes that
// advance this stream's highest received offset (which the caller folds into
// connection-level flow control) and whether the frame violated flow control.
// On a flow-control violation it buffers nothing and reports flowControlError
// so the caller can close the connection (fail closed).
func (s *QUICStream) handleStreamFrame(f quicStreamFrame) (newBytes uint64, flowControlError bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.recvClosed {
		return 0, false
	}

	// Treat the peer-supplied offset/length as hostile: the final absolute
	// offset must fit within the advertised stream receive window. This also
	// rejects any offset+len that would overflow uint64 before we allocate.
	dataLen := uint64(len(f.data))
	end := f.offset + dataLen
	if end < f.offset || end > s.maxRecv {
		return 0, true
	}

	// Connection flow control counts the largest offset ever received on the
	// stream (RFC 9000 §4.1), tracked by recvHighOff, NOT the contiguous
	// in-order boundary recvOff. Counting only the delta past the previous high
	// offset means out-of-order frames are charged once and gap-filling
	// retransmits charge nothing — no double counting, no inflation.
	if end > s.recvHighOff {
		newBytes = end - s.recvHighOff
		s.recvHighOff = end
	}

	// Note: we never compute f.offset - s.recvOff when f.offset < s.recvOff;
	// that unsigned subtraction wraps to a near-2^64 value and would drive a
	// giant allocation. The switch below branches on ordering instead.

	switch {
	case f.offset == s.recvOff:
		s.recvBuf = append(s.recvBuf, f.data...)
		s.recvOff = end

	case f.offset > s.recvOff:
		// Out-of-order ahead: reserve space up to end (bounded by maxRecv above).
		needed := end - s.recvOff
		if uint64(len(s.recvBuf)) < needed {
			grown := make([]byte, needed)
			copy(grown, s.recvBuf)
			s.recvBuf = grown
		}
		copy(s.recvBuf[f.offset-s.recvOff:], f.data)

	default:
		// f.offset < s.recvOff: already-received data, possibly with a new tail.
		// Append only the still-missing tail (if any) without any unsigned wrap.
		if end > s.recvOff {
			already := s.recvOff - f.offset
			s.recvBuf = append(s.recvBuf, f.data[already:]...)
			s.recvOff = end
		}
	}

	if f.fin {
		s.recvFin = true
		s.recvFinOff = end
	}

	select {
	case s.recvReady <- struct{}{}:
	default:
	}

	return newBytes, false
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
