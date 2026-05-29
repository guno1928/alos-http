package core

import (
	"crypto/rand"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	quicSpaceInitial   = 0
	quicSpaceHandshake = 1
	quicSpaceAppData   = 2

	quicDefaultIdleTimeout   = 30 * time.Second
	quicMaxPacketSize        = 1200
	quicConnIDLen            = 8
	quicInitialMaxData       = 10 << 20
	quicInitialMaxStreamData = 1 << 20
	quicMaxBidiStreams       = 1024
	quicMaxUniStreams        = 128
)

type QUICConn struct {
	srcConnID  [20]byte
	srcCIDLen  int
	dstConnID  [20]byte
	dstCIDLen  int
	origDstConnID [20]byte
	origDstLen    int
	version    uint32

	keys        [3]*quicKeys
	sendKeys    [3]*quicKeys
	sendPN      [3]uint64
	recvLargest [3]int64
	loss        *quicLossState
	cryptoBuf   [3][]byte

	tlsState   *quicTLSState
	handshakeDone atomic.Bool

	streams      map[uint64]*QUICStream
	streamsMu    sync.Mutex
	nextBidiRemote uint64
	nextUniRemote  uint64
	nextBidiLocal  uint64
	nextUniLocal   uint64

	maxDataLocal   uint64
	maxDataRemote  uint64
	dataSent       uint64
	dataRecv       uint64

	server     *Server
	remoteAddr net.Addr
	udpConn    net.PacketConn
	udpAddr    *net.UDPAddr
	uringUDP   uringUDPSender
	closed     atomic.Bool
	done       chan struct{}
	writeMu    sync.Mutex

	idleTimeout time.Duration
	lastActive  time.Time

	pendingFrames []byte
	h3            *H3Conn
	inbound       chan []byte
}

func newQUICConn(server *Server, udpConn net.PacketConn, remoteAddr net.Addr, dcid, scid []byte) *QUICConn {
	qc := &QUICConn{
		version:        quicVersion1,
		server:         server,
		udpConn:        udpConn,
		remoteAddr:     remoteAddr,
		done:           make(chan struct{}),
		streams:        make(map[uint64]*QUICStream),
		loss:           newQuicLossState(),
		idleTimeout:    quicDefaultIdleTimeout,
		lastActive:     time.Now(),
		maxDataLocal:   quicInitialMaxData,
		maxDataRemote:  quicInitialMaxData,
		nextBidiRemote: 0,
		nextUniRemote:  2,
		nextBidiLocal:  1,
		nextUniLocal:   3,
	}

	qc.inbound = make(chan []byte, 256)
	qc.recvLargest[0] = -1
	qc.recvLargest[1] = -1
	qc.recvLargest[2] = -1
	qc.origDstLen = copy(qc.origDstConnID[:], dcid)

	var newCID [quicConnIDLen]byte
	rand.Read(newCID[:])
	qc.srcCIDLen = copy(qc.srcConnID[:], newCID[:])
	qc.dstCIDLen = copy(qc.dstConnID[:], scid)

	return qc
}

func (qc *QUICConn) srcCID() []byte {
	return qc.srcConnID[:qc.srcCIDLen]
}

func (qc *QUICConn) dstCID() []byte {
	return qc.dstConnID[:qc.dstCIDLen]
}

func (qc *QUICConn) getOrigDstCID() []byte {
	return qc.origDstConnID[:qc.origDstLen]
}

func (qc *QUICConn) handlePacket(data []byte) {
	if qc == nil || qc.closed.Load() {
		return
	}
	select {
	case qc.inbound <- data:
	default:
	}
}

func (qc *QUICConn) recvLoop() {
	for {
		select {
		case data := <-qc.inbound:
			qc.lastActive = time.Now()
			qc.processPacket(data)
		case <-qc.done:
			return
		}
	}
}

func (qc *QUICConn) processPacket(data []byte) {
	for len(data) > 0 {
		if quicIsLongHeader(data) {
			consumed := qc.handleLongHeaderPacket(data)
			if consumed <= 0 || consumed > len(data) {
				break
			}
			data = data[consumed:]
		} else {
			qc.handleShortHeaderPacket(data)
			break
		}
	}
}

func (qc *QUICConn) handleLongHeaderPacket(data []byte) int {
	hdr, total, err := quicParseLongHeader(data)
	if err != nil {
		return 0
	}
	packet := data[:total]

	switch hdr.pktType {
	case quicPktInitial:
		qc.handleInitialPacket(packet, &hdr)
	case quicPktHandshake:
		qc.handleHandshakePacket(packet, &hdr)
	}
	return total
}

func (qc *QUICConn) handleShortHeaderPacket(data []byte) {
	hdr, err := quicParseShortHeader(data, qc.srcCIDLen)
	if err != nil {
		return
	}

	keys := qc.keys[quicSpaceAppData]
	if keys == nil || !keys.valid {
		return
	}

	plaintext, err := quicDecryptPacket(data, &hdr, keys, qc.loss.largestAcked[quicSpaceAppData])
	if err != nil {
		return
	}

	qc.processFrames(quicSpaceAppData, hdr.pn, plaintext)
}

func (qc *QUICConn) handleInitialPacket(packet []byte, hdr *quicPacketHeader) {
	keys := qc.keys[quicSpaceInitial]
	if keys == nil || !keys.valid {
		return
	}

	plaintext, err := quicDecryptPacket(packet, hdr, keys, qc.loss.largestAcked[quicSpaceInitial])
	if err != nil {
		return
	}

	qc.processFrames(quicSpaceInitial, hdr.pn, plaintext)
}

func (qc *QUICConn) handleHandshakePacket(packet []byte, hdr *quicPacketHeader) {
	keys := qc.keys[quicSpaceHandshake]
	if keys == nil || !keys.valid {
		return
	}

	plaintext, err := quicDecryptPacket(packet, hdr, keys, qc.loss.largestAcked[quicSpaceHandshake])
	if err != nil {
		return
	}

	qc.processFrames(quicSpaceHandshake, hdr.pn, plaintext)
}

func (qc *QUICConn) processFrames(space int, pn uint64, frames []byte) {
	if int64(pn) > qc.recvLargest[space] {
		qc.recvLargest[space] = int64(pn)
	}
	needsAck := false

	visitor := &quicFrameVisitor{
		onACK: func(f quicAckFrame) {
			lostFrames := qc.loss.onAckReceived(space, f, quicMaxAckDelay)
			for _, frames := range lostFrames {
				qc.retransmitFrames(space, frames)
			}
		},
		onCrypto: func(f quicCryptoFrame) {
			needsAck = true
			qc.handleCryptoFrame(space, f)
		},
		onStream: func(f quicStreamFrame) {
			needsAck = true
			qc.handleStreamFrameIncoming(f)
		},
		onMaxData: func(f quicMaxDataFrame) {
			needsAck = true
			if f.maxData > qc.maxDataRemote {
				qc.maxDataRemote = f.maxData
			}
		},
		onMaxStreamData: func(f quicMaxStreamDataFrame) {
			needsAck = true
			qc.streamsMu.Lock()
			if s, ok := qc.streams[f.streamID]; ok {
				s.mu.Lock()
				if f.maxStreamData > s.maxSend {
					s.maxSend = f.maxStreamData
				}
				s.mu.Unlock()
			}
			qc.streamsMu.Unlock()
		},
		onMaxStreams: func(f quicMaxStreamsFrame) {
			needsAck = true
		},
		onConnClose: func(f quicConnCloseFrame) {
			qc.close()
		},
		onHandshakeDone: func() {
			needsAck = true
		},
		onPing: func() {
			needsAck = true
		},
	}

	if err := quicParseFrames(frames, visitor); err != nil {
		log.Printf("[QUIC] frame parse error: %v", err)
		return
	}

	if needsAck {
		qc.sendACK(space)
	}
}

func (qc *QUICConn) handleCryptoFrame(space int, f quicCryptoFrame) {
	if qc.tlsState == nil {
		return
	}
	end := f.offset + uint64(len(f.data))
	if end <= uint64(len(qc.cryptoBuf[space])) {
		return
	}
	if f.offset <= uint64(len(qc.cryptoBuf[space])) {
		newData := f.data[uint64(len(qc.cryptoBuf[space]))-f.offset:]
		qc.cryptoBuf[space] = append(qc.cryptoBuf[space], newData...)
	}
	qc.tlsState.handleCryptoData(qc, space, qc.cryptoBuf[space])
}

func (qc *QUICConn) handleStreamFrameIncoming(f quicStreamFrame) {
	qc.streamsMu.Lock()
	s, ok := qc.streams[f.streamID]
	if !ok {
		s = newQUICStream(f.streamID, qc)
		qc.streams[f.streamID] = s
	}
	qc.streamsMu.Unlock()

	s.handleStreamFrame(f)

	if f.fin && qc.h3 != nil && quicStreamIsBidi(f.streamID) && !quicStreamIsLocal(f.streamID, true) {
		go qc.h3.handleRequestStream(s)
	}
}

func (qc *QUICConn) getOrCreateStream(id uint64) *QUICStream {
	qc.streamsMu.Lock()
	defer qc.streamsMu.Unlock()
	s, ok := qc.streams[id]
	if !ok {
		s = newQUICStream(id, qc)
		qc.streams[id] = s
	}
	return s
}

func (qc *QUICConn) openLocalBidiStream() *QUICStream {
	qc.streamsMu.Lock()
	id := qc.nextBidiLocal
	qc.nextBidiLocal += 4
	s := newQUICStream(id, qc)
	qc.streams[id] = s
	qc.streamsMu.Unlock()
	return s
}

func (qc *QUICConn) openLocalUniStream() *QUICStream {
	qc.streamsMu.Lock()
	id := qc.nextUniLocal
	qc.nextUniLocal += 4
	s := newQUICStream(id, qc)
	qc.streams[id] = s
	qc.streamsMu.Unlock()
	return s
}

func (qc *QUICConn) sendCrypto(space int, data []byte) {
	var frames []byte
	frames = quicAppendCryptoFrame(frames, 0, data)
	qc.sendFrames(space, frames, true)
}

func (qc *QUICConn) sendACK(space int) {
	largest := qc.recvLargest[space]
	if largest < 0 {
		return
	}
	var frames []byte
	frames = quicAppendACKFrame(frames, uint64(largest), 0, uint64(largest))
	qc.sendFrames(space, frames, false)
}

func (qc *QUICConn) sendFrames(space int, frames []byte, ackEliciting bool) {
	keys := qc.sendKeys[space]
	if keys == nil || !keys.valid {
		keys = qc.keys[space]
	}
	if keys == nil || !keys.valid {
		return
	}

	qc.writeMu.Lock()
	defer qc.writeMu.Unlock()

	pn := qc.sendPN[space]
	qc.sendPN[space]++
	largestAcked := qc.loss.largestAcked[space]

	var packet []byte
	switch space {
	case quicSpaceInitial:
		packet = quicBuildInitialPacket(nil, qc.dstCID(), qc.srcCID(), nil, frames, pn, largestAcked, keys)
		if len(packet) < quicMaxPacketSize {
			padding := quicMaxPacketSize - len(packet)
			padded := make([]byte, 0, quicMaxPacketSize)
			frames = append(frames, make([]byte, padding)...)
			packet = quicBuildInitialPacket(padded, qc.dstCID(), qc.srcCID(), nil, frames, pn, largestAcked, keys)
		}
	case quicSpaceHandshake:
		packet = quicBuildHandshakePacket(nil, qc.dstCID(), qc.srcCID(), frames, pn, largestAcked, keys)
	case quicSpaceAppData:
		packet = quicBuildShortPacket(nil, qc.dstCID(), frames, pn, largestAcked, keys)
	}

	if len(packet) > 0 {
		if qc.uringUDP != nil && qc.udpAddr != nil {
			qc.uringUDP.sendTo(packet, qc.udpAddr)
		} else if qc.udpConn != nil {
			qc.udpConn.WriteTo(packet, qc.remoteAddr)
		}
		qc.loss.onPacketSent(space, pn, len(packet), ackEliciting, frames)
	}
}

func (qc *QUICConn) sendStreamData(s *QUICStream) {
	for {
		data, offset, fin := s.drainSendBuf(quicMaxPacketSize - 100)
		if len(data) == 0 && !fin {
			return
		}

		var frames []byte
		frames = quicAppendStreamFrame(frames, s.id, offset, data, fin)
		qc.sendFrames(quicSpaceAppData, frames, true)

		if fin || len(data) == 0 {
			return
		}
	}
}

func (qc *QUICConn) retransmitFrames(space int, frames []byte) {
	qc.sendFrames(space, frames, true)
}

func (qc *QUICConn) close() {
	if !qc.closed.CompareAndSwap(false, true) {
		return
	}
	close(qc.done)

	qc.streamsMu.Lock()
	for _, s := range qc.streams {
		s.Close()
	}
	qc.streamsMu.Unlock()
}

func (qc *QUICConn) sendConnectionClose(errorCode uint64, reason string) {
	var frames []byte
	frames = quicAppendConnCloseFrame(frames, errorCode, 0, reason)

	space := quicSpaceAppData
	if qc.keys[quicSpaceAppData] == nil || !qc.keys[quicSpaceAppData].valid {
		space = quicSpaceHandshake
	}
	if qc.keys[space] == nil || !qc.keys[space].valid {
		space = quicSpaceInitial
	}

	qc.sendFrames(space, frames, false)
}

func (qc *QUICConn) runIdleTimer() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-qc.done:
			return
		case <-ticker.C:
			if time.Since(qc.lastActive) > qc.idleTimeout {
				qc.close()
				return
			}
		}
	}
}
