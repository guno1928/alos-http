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

	// quicUnvalidatedIdleTimeout reaps connections whose path has not yet been
	// validated (no decryptable Handshake packet processed) far sooner than the
	// full idle timeout, so a flood of spoofed Initials is freed quickly instead
	// of pinning a conn + 2 goroutines for the full idle window. See finding C3.
	quicUnvalidatedIdleTimeout = 3 * time.Second

	// quicMaxLiveConns bounds the total number of live QUIC connections the
	// server tracks. When at the cap, a new Initial is dropped (no conn
	// allocated, no goroutines spawned) rather than growing unbounded under a
	// spoofed-Initial handshake flood. Generous default; see finding C3.
	quicMaxLiveConns = 65536
)

type QUICConn struct {
	srcConnID     [20]byte
	srcCIDLen     int
	dstConnID     [20]byte
	dstCIDLen     int
	origDstConnID [20]byte
	origDstLen    int
	version       uint32

	keys        [3]*quicKeys
	sendKeys    [3]*quicKeys
	sendPN      [3]uint64
	recvLargest [3]int64
	loss        *quicLossState
	cryptoBuf   [3][]byte
	cryptoRcv   [3][]bool

	tlsState      *quicTLSState
	handshakeDone atomic.Bool
	firstFlight   struct {
		serverHello       []byte
		ee, cert, cv, fin []byte
		sent              bool
	}

	streams        map[uint64]*QUICStream
	streamsMu      sync.Mutex
	nextBidiRemote uint64
	nextUniRemote  uint64
	nextBidiLocal  uint64
	nextUniLocal   uint64

	maxDataLocal  uint64
	maxDataRemote uint64
	dataSent      uint64
	dataRecv      uint64

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

	// Anti-amplification accounting (RFC 9000 §8). Touched from both the
	// recv goroutine and send paths, so accessed via atomics. pathValidated
	// flips true once a decryptable Handshake packet is processed, which
	// validates the peer address per RFC 9000 §8.1. See finding C3.
	bytesReceived atomic.Uint64
	bytesSent     atomic.Uint64
	pathValidated atomic.Bool

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

// quicConnCap returns the maximum number of live QUIC connections the server
// will track concurrently.
func (s *Server) quicConnCap() int64 {
	return quicMaxLiveConns
}

// reserveQUICConn atomically reserves a live-connection slot, failing closed
// when the server is already at the cardinality cap. On a denied reservation it
// undoes its own increment so the gauge cannot drift. The caller MUST pair a
// successful reservation (true) with exactly one releaseQUICConn once the
// connection is torn down. See finding C3 (handshake-flood mitigation).
func (s *Server) reserveQUICConn() bool {
	if s.quicLiveConns.Add(1) > s.quicConnCap() {
		s.quicLiveConns.Add(-1)
		return false
	}
	return true
}

// releaseQUICConn frees a previously reserved live-connection slot. It must be
// called exactly once per successful reserveQUICConn.
func (s *Server) releaseQUICConn() {
	s.quicLiveConns.Add(-1)
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
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[QUIC-PANIC] recvLoop panic: %v", r)
		}
	}()
	if debugFlag.Load() {
		log.Printf("[QUIC-DBG] recvLoop started for %s", qc.remoteAddr.String())
	}
	for {
		select {
		case data := <-qc.inbound:
			qc.lastActive = time.Now()
			qc.bytesReceived.Add(uint64(len(data)))
			qc.processPacket(data)
		case <-qc.done:
			return
		}
	}
}

func (qc *QUICConn) processPacket(data []byte) {
	if debugFlag.Load() {
		log.Printf("[QUIC-DBG] processPacket: %d bytes, first=0x%02x", len(data), data[0])
	}
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
		if debugFlag.Load() {
			log.Printf("[QUIC-DBG] parseLongHeader failed: %v (dataLen=%d)", err, len(data))
		}
		return 0
	}
	packet := data[:total]

	if debugFlag.Load() {
		log.Printf("[QUIC-DBG] longHeader: type=%d ver=0x%08x dcid=%x scid=%x total=%d pnOff=%d payOff=%d payLen=%d",
			hdr.pktType, hdr.version, hdr.dcid, hdr.scid, total, hdr.pnOffset, hdr.payloadOff, hdr.payloadLen)
	}

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
		if debugFlag.Load() {
			log.Printf("[QUIC-DBG] handleInitial: no keys (nil=%v)", keys == nil)
		}
		return
	}

	plaintext, err := quicDecryptPacket(packet, hdr, keys, qc.loss.largestAcked[quicSpaceInitial])
	if err != nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-DBG] handleInitial: decrypt failed: %v (pktLen=%d pnOff=%d payOff=%d payLen=%d)", err, len(packet), hdr.pnOffset, hdr.payloadOff, hdr.payloadLen)
		}
		return
	}

	if debugFlag.Load() {
		log.Printf("[QUIC-DBG] handleInitial: decrypted %d bytes, pn=%d", len(plaintext), hdr.pn)
	}
	qc.processFrames(quicSpaceInitial, hdr.pn, plaintext)
}

func (qc *QUICConn) handleHandshakePacket(packet []byte, hdr *quicPacketHeader) {
	keys := qc.keys[quicSpaceHandshake]
	if keys == nil || !keys.valid {
		if debugFlag.Load() {
			log.Printf("[QUIC-DBG] handleHandshake: no keys (nil=%v valid=%v)", keys == nil, keys != nil && keys.valid)
		}
		return
	}

	plaintext, err := quicDecryptPacket(packet, hdr, keys, qc.loss.largestAcked[quicSpaceHandshake])
	if err != nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-DBG] handleHandshake: decrypt failed: %v", err)
		}
		return
	}

	if debugFlag.Load() {
		log.Printf("[QUIC-DBG] handleHandshake: decrypted %d bytes, pn=%d", len(plaintext), hdr.pn)
	}

	// A decryptable Handshake packet proves the peer received our Initial
	// keys at this address, validating the path per RFC 9000 §8.1.
	qc.markPathValidated()

	qc.processFrames(quicSpaceHandshake, hdr.pn, plaintext)
}

// markPathValidated records that the peer's address has been validated.
// Idempotent and race-safe; the effective idle timeout (see effectiveIdleTimeout)
// reads pathValidated directly, so no further state needs to change here.
func (qc *QUICConn) markPathValidated() {
	qc.pathValidated.Store(true)
}

// effectiveIdleTimeout returns the unvalidated (fast) idle timeout until the
// peer's path is validated, then the full idle timeout. Reaping unvalidated
// conns quickly bounds the cost of a spoofed-Initial flood. See finding C3.
func (qc *QUICConn) effectiveIdleTimeout() time.Duration {
	if qc.pathValidated.Load() {
		return qc.idleTimeout
	}
	if qc.idleTimeout < quicUnvalidatedIdleTimeout {
		return qc.idleTimeout
	}
	return quicUnvalidatedIdleTimeout
}

// amplificationBudgetExceeded reports whether sending n more bytes to an
// unvalidated path would exceed the RFC 9000 §8 3x anti-amplification budget.
// TODO(C3-followup): once Retry/token address validation lands, gate
// sendFirstFlight (and other server sends before path validation) on this.
// Currently advisory only — it is computed and tested but never used to block
// a send, to avoid changing handshake behavior in this minimal PR.
func (qc *QUICConn) amplificationBudgetExceeded(n int) bool {
	if qc.pathValidated.Load() {
		return false
	}
	return qc.bytesSent.Load()+uint64(n) > 3*qc.bytesReceived.Load()
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

	if needsAck && (space != quicSpaceInitial || qc.handshakeDone.Load()) {
		qc.sendACK(space)
	}
}

func (qc *QUICConn) handleCryptoFrame(space int, f quicCryptoFrame) {
	if qc.tlsState == nil {
		return
	}

	end := f.offset + uint64(len(f.data))
	if end > uint64(len(qc.cryptoBuf[space])) {
		grownBuf := make([]byte, end)
		copy(grownBuf, qc.cryptoBuf[space])
		grownRcv := make([]bool, end)
		copy(grownRcv, qc.cryptoRcv[space])
		qc.cryptoBuf[space] = grownBuf
		qc.cryptoRcv[space] = grownRcv
	}
	copy(qc.cryptoBuf[space][f.offset:], f.data)
	for i := f.offset; i < end; i++ {
		qc.cryptoRcv[space][i] = true
	}

	if len(qc.cryptoBuf[space]) < 4 || !qc.cryptoRcv[space][0] || !qc.cryptoRcv[space][1] || !qc.cryptoRcv[space][2] || !qc.cryptoRcv[space][3] {
		return
	}

	msgLen := int(qc.cryptoBuf[space][1])<<16 | int(qc.cryptoBuf[space][2])<<8 | int(qc.cryptoBuf[space][3])
	needed := 4 + msgLen
	if len(qc.cryptoBuf[space]) < needed {
		return
	}

	for i := 0; i < needed; i++ {
		if !qc.cryptoRcv[space][i] {
			return
		}
	}

	if debugFlag.Load() {
		log.Printf("[QUIC-DBG] handleCryptoFrame: space=%d complete message %d bytes, all bytes verified", space, needed)
	}
	qc.tlsState.handleCryptoData(qc, space, qc.cryptoBuf[space][:needed])
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
	const maxCryptoPerPacket = 1000
	offset := uint64(0)
	for len(data) > 0 {
		chunk := data
		if len(chunk) > maxCryptoPerPacket {
			chunk = data[:maxCryptoPerPacket]
		}
		var frames []byte
		frames = quicAppendCryptoFrame(frames, offset, chunk)
		qc.sendFrames(space, frames, true)
		if debugFlag.Load() {
			log.Printf("[QUIC-DBG] sendCrypto: space=%d offset=%d chunkLen=%d remaining=%d", space, offset, len(chunk), len(data)-len(chunk))
		}
		offset += uint64(len(chunk))
		data = data[len(chunk):]
	}
}

func (qc *QUICConn) sendACK(space int) {
	largest := qc.recvLargest[space]
	if largest < 0 {
		return
	}
	var frames []byte
	frames = quicAppendACKFrame(frames, uint64(largest), 0, 0)
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
		var sendErr error
		if qc.uringUDP != nil && qc.udpAddr != nil {
			_, sendErr = qc.uringUDP.sendTo(packet, qc.udpAddr)
		} else if qc.udpConn != nil {
			_, sendErr = qc.udpConn.WriteTo(packet, qc.remoteAddr)
		}
		if debugFlag.Load() {
			log.Printf("[QUIC-DBG] sendFrames: space=%d pn=%d pktLen=%d framesLen=%d sendErr=%v dst=%v",
				space, pn, len(packet), len(frames), sendErr, qc.udpAddr)
		}
		qc.bytesSent.Add(uint64(len(packet)))
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

func (qc *QUICConn) sendFirstFlight(serverHello, ee, cert, cv, fin []byte) {
	if !qc.firstFlight.sent {
		qc.firstFlight.serverHello = make([]byte, len(serverHello))
		copy(qc.firstFlight.serverHello, serverHello)
		qc.firstFlight.ee = make([]byte, len(ee))
		copy(qc.firstFlight.ee, ee)
		qc.firstFlight.cert = make([]byte, len(cert))
		copy(qc.firstFlight.cert, cert)
		qc.firstFlight.cv = make([]byte, len(cv))
		copy(qc.firstFlight.cv, cv)
		qc.firstFlight.fin = make([]byte, len(fin))
		copy(qc.firstFlight.fin, fin)
		qc.firstFlight.sent = true
	}

	qc.writeMu.Lock()
	defer qc.writeMu.Unlock()

	initialKeys := qc.sendKeys[quicSpaceInitial]
	if initialKeys == nil || !initialKeys.valid {
		initialKeys = qc.keys[quicSpaceInitial]
	}
	hsKeys := qc.sendKeys[quicSpaceHandshake]
	if hsKeys == nil || !hsKeys.valid {
		hsKeys = qc.keys[quicSpaceHandshake]
	}
	if initialKeys == nil || hsKeys == nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-DBG] sendFirstFlight: missing keys")
		}
		return
	}

	sendDatagram := func(data []byte) {
		if qc.uringUDP != nil && qc.udpAddr != nil {
			qc.uringUDP.sendTo(data, qc.udpAddr)
		} else if qc.udpConn != nil {
			qc.udpConn.WriteTo(data, qc.remoteAddr)
		}
		qc.bytesSent.Add(uint64(len(data)))
	}

	var initialFrames []byte
	largest := qc.recvLargest[quicSpaceInitial]
	if largest >= 0 {
		initialFrames = quicAppendACKFrame(initialFrames, uint64(largest), 0, 0)
	}
	initialFrames = quicAppendCryptoFrame(initialFrames, 0, serverHello)

	pn0 := qc.sendPN[quicSpaceInitial]
	qc.sendPN[quicSpaceInitial]++
	la0 := qc.loss.largestAcked[quicSpaceInitial]

	var hsMessages []byte
	hsMessages = append(hsMessages, ee...)
	hsMessages = append(hsMessages, cert...)
	hsMessages = append(hsMessages, cv...)
	hsMessages = append(hsMessages, fin...)

	const maxCryptoPerPacket = 1000

	firstHSChunk := hsMessages
	if len(firstHSChunk) > maxCryptoPerPacket {
		firstHSChunk = hsMessages[:maxCryptoPerPacket]
	}
	var firstHSFrames []byte
	firstHSFrames = quicAppendCryptoFrame(firstHSFrames, 0, firstHSChunk)
	pnHS0 := qc.sendPN[quicSpaceHandshake]
	qc.sendPN[quicSpaceHandshake]++
	laHS := qc.loss.largestAcked[quicSpaceHandshake]
	firstHSPkt := quicBuildHandshakePacket(nil, qc.dstCID(), qc.srcCID(), firstHSFrames, pnHS0, laHS, hsKeys)

	if debugFlag.Load() {
		log.Printf("[H3-DBG] sendFirstFlight: building Initial pkt dcid=%x scid=%x pn=%d", qc.dstCID(), qc.srcCID(), pn0)
	}
	initialPkt := quicBuildInitialPacket(nil, qc.dstCID(), qc.srcCID(), nil, initialFrames, pn0, la0, initialKeys)
	if debugFlag.Load() {
		log.Printf("[H3-DBG] sendFirstFlight: Initial pkt %d bytes, first20=%x", len(initialPkt), initialPkt[:min(20, len(initialPkt))])
		log.Printf("[H3-DBG] sendFirstFlight: HS0 pkt %d bytes, first20=%x", len(firstHSPkt), firstHSPkt[:min(20, len(firstHSPkt))])
	}
	datagram := make([]byte, 0, quicMaxPacketSize+len(firstHSPkt))
	datagram = append(datagram, initialPkt...)
	datagram = append(datagram, firstHSPkt...)

	if len(datagram) < quicMaxPacketSize {
		padNeeded := quicMaxPacketSize - len(datagram)
		paddedFrames := make([]byte, len(initialFrames)+padNeeded)
		copy(paddedFrames, initialFrames)
		initialPkt = quicBuildInitialPacket(nil, qc.dstCID(), qc.srcCID(), nil, paddedFrames, pn0, la0, initialKeys)
		datagram = datagram[:0]
		datagram = append(datagram, initialPkt...)
		datagram = append(datagram, firstHSPkt...)
	}
	if debugFlag.Load() {
		log.Printf("[H3-DBG] sendFirstFlight: datagram1 %d bytes (initial=%d hs=%d) first50=%x hsStart=%x",
			len(datagram), len(initialPkt), len(firstHSPkt),
			datagram[:min(50, len(datagram))],
			datagram[len(initialPkt):min(len(initialPkt)+20, len(datagram))])
	}
	sendDatagram(datagram)
	qc.loss.onPacketSent(quicSpaceInitial, pn0, quicMaxPacketSize, true, initialFrames)
	qc.loss.onPacketSent(quicSpaceHandshake, pnHS0, len(firstHSPkt), true, firstHSFrames)

	hsOffset := uint64(len(firstHSChunk))
	remaining := hsMessages[len(firstHSChunk):]
	chunkIdx := 1
	for len(remaining) > 0 {
		chunk := remaining
		if len(chunk) > maxCryptoPerPacket {
			chunk = remaining[:maxCryptoPerPacket]
		}
		var hsFrames []byte
		hsFrames = quicAppendCryptoFrame(hsFrames, hsOffset, chunk)
		pnHS := qc.sendPN[quicSpaceHandshake]
		qc.sendPN[quicSpaceHandshake]++
		hsPkt := quicBuildHandshakePacket(nil, qc.dstCID(), qc.srcCID(), hsFrames, pnHS, laHS, hsKeys)
		if debugFlag.Load() {
			log.Printf("[H3-DBG] sendFirstFlight: datagram%d (HS%d) %d bytes, crypto offset=%d len=%d",
				chunkIdx+1, chunkIdx, len(hsPkt), hsOffset, len(chunk))
		}
		sendDatagram(hsPkt)
		qc.loss.onPacketSent(quicSpaceHandshake, pnHS, len(hsPkt), true, hsFrames)
		hsOffset += uint64(len(chunk))
		remaining = remaining[len(chunk):]
		chunkIdx++
	}

	if debugFlag.Load() {
		log.Printf("[H3-DBG] sendFirstFlight: total %d datagrams, hsMessages=%d bytes across %d chunks",
			chunkIdx+1, len(hsMessages), chunkIdx)
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
	// 1s granularity so the short unvalidated timeout (quicUnvalidatedIdleTimeout)
	// is honored promptly under a spoofed-Initial flood; the cost is one extra
	// wakeup/second per live conn, bounded by the connection cardinality cap.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-qc.done:
			return
		case <-ticker.C:
			if time.Since(qc.lastActive) > qc.effectiveIdleTimeout() {
				qc.close()
				return
			}
		}
	}
}
