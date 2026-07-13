package core

import (
	"crypto/rand"
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guno1928/alosmap"
	"github.com/guno1928/turbo"
)

type quicConnMap = alosmap.TypedMap[[20]byte, *QUICConn]

const (
	quicSpaceInitial   = 0
	quicSpaceHandshake = 1
	quicSpaceAppData   = 2

	quicPktBufCap = 33280

	quicDefaultIdleTimeout      = 30 * time.Second
	quicMaxPacketSize           = 1200
	quicConnIDLen               = 8
	quicInitialMaxData          = 10 << 20
	quicInitialMaxStreamData    = 1 << 20
	quicMaxCryptoBuf            = 64 << 10
	quicMaxConcurrentReqStreams = 256
	quicKeyUpdateThreshold      = 1 << 20
	quicMaxBidiStreams          = 1024
	quicMaxUniStreams           = 128
	quicMaxTrackedStreams       = 2048
	quicMaxConns                = 1 << 16
	quicReqStreamQueueSize      = 8192
	quicCoalesceBudget          = 1100
)

const reqStreamShards = 4

var (
	reqStreamWorkChs  [reqStreamShards]chan *QUICStream
	reqStreamWorkOnce sync.Once
	connShardCounter  atomic.Uint32
)

func startReqStreamWorkers() {
	reqStreamWorkOnce.Do(func() {
		perShard := runtime.NumCPU()/2 + 1
		for i := range reqStreamWorkChs {
			reqStreamWorkChs[i] = make(chan *QUICStream, quicReqStreamQueueSize/reqStreamShards)
			for w := 0; w < perShard; w++ {
				go reqStreamWorker(reqStreamWorkChs[i])
			}
		}
	})
}

func reqStreamWorker(ch chan *QUICStream) {
	for s := range ch {
		s.conn.serveRequestStream(s)
	}
}

var quicActiveConns atomic.Int64

var quicPktBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, quicPktBufCap); return &b },
}

var quicRecvBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, quicPktBufCap); return &b },
}

type quicInboundPkt struct {
	data []byte
	pbuf *[]byte
}

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
	recvLargest    [3]int64
	ackRanges      [3][]pnRange
	pendingAck     [3][]byte
	ackScratch     [3][]byte
	frameScratch   []byte
	combineScratch []byte
	coalesceBuf      []byte
	coalesceEnds     []int
	coalesceStart    int
	pktBudget        int
	peerStreamWindow uint64
	streamWriters    atomic.Int32
	workShard        uint8
	loss           *quicLossState
	cryptoBuf   [3][]byte
	cryptoRcv   [3][]bool

	recvKeyPhase   uint32
	sendKeyPhase   uint32
	nextRecvKeys   *quicKeys
	prevRecvKeys   *quicKeys
	prevKeyRetire  time.Time
	packetsInEpoch atomic.Uint64
	recvSecret     []byte
	sendSecret     []byte
	appSuite       *CipherSuiteConfig
	origHP         headerProtector

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
	dataSent       uint64
	dataRecv       uint64
	dataRecvGranted uint64

	bytesSent        atomic.Uint64
	bytesReceived    atomic.Uint64
	addressValidated atomic.Bool

	server     *Server
	remoteAddr net.Addr
	udpConn    net.PacketConn
	udpAddr    *net.UDPAddr
	uringUDP   uringUDPSender
	closed     atomic.Bool
	done       chan struct{}
	writeMu    sync.Mutex

	idleTimeout time.Duration
	lastActive  atomic.Int64

	pendingFrames []byte
	h3            *H3Conn
	inbound       chan quicInboundPkt

	activeReqStreams   atomic.Int32
	bidiStreamsRetired atomic.Uint64
}

func newQUICConn(server *Server, udpConn net.PacketConn, remoteAddr net.Addr, dcid, scid []byte) *QUICConn {
	maxData := uint64(quicInitialMaxData)
	if server.config.QUICMaxData > 0 {
		maxData = uint64(server.config.QUICMaxData)
	}
	qc := &QUICConn{
		version:        quicVersion1,
		server:         server,
		udpConn:        udpConn,
		remoteAddr:     remoteAddr,
		done:           make(chan struct{}),
		streams:        make(map[uint64]*QUICStream),
		loss:           newQuicLossState(),
		idleTimeout:    defaultDuration(server.config.IdleTimeout, quicDefaultIdleTimeout),
		maxDataLocal:    maxData,
		maxDataRemote:   maxData,
		dataRecvGranted: maxData,
		nextBidiRemote: 0,
		nextUniRemote:  2,
		nextBidiLocal:  1,
		nextUniLocal:   3,
	}

	qc.workShard = uint8(connShardCounter.Add(1) % reqStreamShards)
	qc.pktBudget = quicCoalesceBudget
	qc.lastActive.Store(turbo.UnixNano())
	qc.inbound = make(chan quicInboundPkt, 256)
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

func quicCIDKey(cid []byte) [20]byte {
	var key [20]byte
	copy(key[:], cid)
	return key
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
	qc.handlePacketPooled(data, nil)
}

func (qc *QUICConn) handlePacketPooled(data []byte, pbuf *[]byte) {
	if qc == nil || qc.closed.Load() {
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
		return
	}
	select {
	case qc.inbound <- quicInboundPkt{data: data, pbuf: pbuf}:
	default:
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
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
		case pkt := <-qc.inbound:
			qc.lastActive.Store(turbo.UnixNano())
			qc.processPacket(pkt.data)
			if pkt.pbuf != nil {
				quicRecvBufPool.Put(pkt.pbuf)
			}
		case <-qc.done:
			return
		}
	}
}

func (qc *QUICConn) processPacket(data []byte) {
	qc.bytesReceived.Add(uint64(len(data)))
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

	hp := keys.hp
	if qc.origHP != nil {
		hp = qc.origHP
	}

	sampleOffset := hdr.pnOffset + 4
	if sampleOffset+16 > len(data) {
		return
	}
	mask := hp.mask(data[sampleOffset:])
	data[0] ^= mask[0] & 0x1f

	pktKeyPhase := uint32((data[0] & 0x04) >> 2)

	pnLen := int(data[0]&0x03) + 1
	for i := 0; i < pnLen; i++ {
		data[hdr.pnOffset+i] ^= mask[1+i]
	}

	truncatedPN := quicReadPacketNumber(data[hdr.pnOffset:], pnLen)
	pn := quicDecodePacketNumber(truncatedPN, pnLen, qc.recvLargest[quicSpaceAppData])
	hdr.pn = pn
	hdr.pnLen = pnLen

	headerEnd := hdr.pnOffset + pnLen
	payloadEnd := hdr.payloadOff + hdr.payloadLen
	if headerEnd > payloadEnd {
		return
	}

	header := data[:headerEnd]
	ciphertext := data[headerEnd:payloadEnd]

	var plaintext []byte

	if pktKeyPhase == qc.recvKeyPhase {
		plaintext, err = keys.decrypt(ciphertext[:0], header, ciphertext, pn)
	} else if qc.nextRecvKeys != nil {
		plaintext, err = qc.nextRecvKeys.decrypt(ciphertext[:0], header, ciphertext, pn)
		if err == nil {
			qc.prevRecvKeys = keys
			qc.keys[quicSpaceAppData] = qc.nextRecvKeys
			qc.nextRecvKeys = nil
			qc.recvKeyPhase = pktKeyPhase
			qc.writeMu.Lock()
			pto := qc.loss.ptoTimeout()
			qc.writeMu.Unlock()
			qc.prevKeyRetire = time.Now().Add(3 * pto)
			qc.deriveNextRecvKeys()
			qc.respondToPeerKeyUpdate(pktKeyPhase)
		}
	}

	if err != nil && qc.prevRecvKeys != nil && time.Now().Before(qc.prevKeyRetire) {
		plaintext, err = qc.prevRecvKeys.decrypt(ciphertext[:0], header, ciphertext, pn)
	}

	if err != nil {
		return
	}

	if qc.prevRecvKeys != nil && time.Now().After(qc.prevKeyRetire) {
		qc.prevRecvKeys = nil
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

	plaintext, err := quicDecryptPacket(packet, hdr, keys, qc.recvLargest[quicSpaceInitial])
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

	plaintext, err := quicDecryptPacket(packet, hdr, keys, qc.recvLargest[quicSpaceHandshake])
	if err != nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-DBG] handleHandshake: decrypt failed: %v", err)
		}
		return
	}

	if debugFlag.Load() {
		log.Printf("[QUIC-DBG] handleHandshake: decrypted %d bytes, pn=%d", len(plaintext), hdr.pn)
	}
	qc.processFrames(quicSpaceHandshake, hdr.pn, plaintext)
}

func (qc *QUICConn) processFrames(space int, pn uint64, frames []byte) {
	if int64(pn) > qc.recvLargest[space] {
		qc.recvLargest[space] = int64(pn)
	}
	qc.recordRecvPN(space, pn)
	needsAck := false

	visitor := &quicFrameVisitor{
		onACK: func(f quicAckFrame) {
			qc.writeMu.Lock()
			lostFrames := qc.loss.onAckReceived(space, f, quicMaxAckDelay)
			if len(qc.coalesceEnds) > 0 {
				qc.drainCoalescedLocked()
			}
			qc.writeMu.Unlock()
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
			qc.writeMu.Lock()
			if f.maxData > qc.maxDataRemote {
				qc.maxDataRemote = f.maxData
			}
			qc.writeMu.Unlock()
		},
		onMaxStreamData: func(f quicMaxStreamDataFrame) {
			needsAck = true
			qc.streamsMu.Lock()
			s, ok := qc.streams[f.streamID]
			if ok {
				s.refCount.Add(1)
			}
			qc.streamsMu.Unlock()
			if !ok {
				return
			}
			s.mu.Lock()
			grew := f.maxStreamData > s.maxSend
			if grew {
				s.maxSend = f.maxStreamData
			}
			pending := len(s.sendBuf) > 0
			s.mu.Unlock()
			if grew && pending {
				qc.sendStreamData(s)
				qc.maybeFinishStream(s)
			}
			qc.releaseStream(s)
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
		if space == quicSpaceAppData {
			qc.stashAck(space)
		} else {
			qc.sendACK(space)
		}
	}
}

func (qc *QUICConn) stashAck(space int) {
	if len(qc.ackRanges[space]) == 0 {
		return
	}
	qc.writeMu.Lock()
	qc.ackScratch[space] = quicAppendACKFrameRanges(qc.ackScratch[space][:0], 0, qc.ackRanges[space])
	qc.pendingAck[space] = qc.ackScratch[space]
	qc.writeMu.Unlock()
}

func (qc *QUICConn) flushPendingAck(space int) {
	qc.writeMu.Lock()
	ack := qc.pendingAck[space]
	qc.pendingAck[space] = nil
	if len(ack) > 0 {
		qc.sendFramesLocked(space, ack, false)
	}
	qc.writeMu.Unlock()
}

func (qc *QUICConn) handleCryptoFrame(space int, f quicCryptoFrame) {
	if qc.tlsState == nil {
		return
	}

	end := f.offset + uint64(len(f.data))
	if f.offset > quicMaxCryptoBuf || end > quicMaxCryptoBuf {
		return
	}
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
		if len(qc.streams) >= quicMaxTrackedStreams {
			qc.streamsMu.Unlock()
			return
		}
		s = getPooledStream(f.streamID, qc)
		s.refCount.Store(1)
		qc.streams[f.streamID] = s
	}
	s.refCount.Add(1)
	qc.streamsMu.Unlock()

	s.handleStreamFrame(f)

	if f.fin && qc.h3 != nil && quicStreamIsBidi(f.streamID) && !quicStreamIsLocal(f.streamID, true) {
		if qc.activeReqStreams.Add(1) > quicMaxConcurrentReqStreams {
			qc.activeReqStreams.Add(-1)
		} else if !s.dispatched.CompareAndSwap(false, true) {
			qc.activeReqStreams.Add(-1)
		} else {
			s.refCount.Add(1)
			select {
			case reqStreamWorkChs[qc.workShard] <- s:
			default:
				go qc.serveRequestStream(s)
			}
		}
	}
	qc.releaseStream(s)
}

func (qc *QUICConn) serveRequestStream(s *QUICStream) {
	defer qc.activeReqStreams.Add(-1)
	qc.h3.handleRequestStream(s)
	s.mu.Lock()
	s.awaitingCleanup = true
	drained := len(s.sendBuf) == 0
	s.mu.Unlock()
	if drained {
		qc.finishRequestStream(s)
	}
}

func (qc *QUICConn) finishRequestStream(s *QUICStream) {
	if !s.cleanupDone.CompareAndSwap(false, true) {
		return
	}
	qc.streamsMu.Lock()
	delete(qc.streams, s.id)
	qc.streamsMu.Unlock()
	qc.releaseStream(s)
	qc.releaseStream(s)
	retired := qc.bidiStreamsRetired.Add(1)
	if retired&127 == 0 {
		qc.sendMaxStreamsBidi(retired + quicMaxBidiStreams)
	}
}

func (qc *QUICConn) maybeFinishStream(s *QUICStream) {
	s.mu.Lock()
	done := s.awaitingCleanup && len(s.sendBuf) == 0
	s.mu.Unlock()
	if done {
		qc.finishRequestStream(s)
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
	if len(qc.ackRanges[space]) == 0 {
		return
	}
	var frames []byte
	frames = quicAppendACKFrameRanges(frames, 0, qc.ackRanges[space])
	qc.sendFrames(space, frames, false)
}

func (qc *QUICConn) sendFrames(space int, frames []byte, ackEliciting bool) {
	qc.writeMu.Lock()
	qc.sendFramesLocked(space, frames, ackEliciting)
	qc.writeMu.Unlock()
}

func (qc *QUICConn) sendFramesLocked(space int, frames []byte, ackEliciting bool) {
	keys := qc.sendKeys[space]
	if keys == nil || !keys.valid {
		keys = qc.keys[space]
	}
	if keys == nil || !keys.valid {
		return
	}

	if len(qc.pendingAck[space]) > 0 {
		qc.combineScratch = append(qc.combineScratch[:0], qc.pendingAck[space]...)
		qc.combineScratch = append(qc.combineScratch, frames...)
		frames = qc.combineScratch
		qc.pendingAck[space] = nil
	}

	pn := qc.sendPN[space]
	qc.sendPN[space]++
	largestAcked := qc.loss.largestAckedPN(space)

	var packet []byte
	var pbuf *[]byte
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
		pbuf = quicPktBufPool.Get().(*[]byte)
		packet = quicBuildShortPacket((*pbuf)[:0], qc.dstCID(), frames, pn, largestAcked, keys, qc.sendKeyPhase)
		if cap(packet) != quicPktBufCap {
			quicPktBufPool.Put(pbuf)
			pbuf = nil
		}
		if qc.packetsInEpoch.Add(1) >= quicKeyUpdateThreshold {
			qc.initiateKeyUpdate()
		}
	}

	if len(packet) > 0 {
		if !qc.addressValidated.Load() && qc.bytesSent.Load() >= 3*qc.bytesReceived.Load() {
			if pbuf != nil {
				quicPktBufPool.Put(pbuf)
			}
			return
		}
		var sendErr error
		if qc.uringUDP != nil && qc.udpAddr != nil {
			_, sendErr = qc.uringUDP.sendToPooled(packet, qc.udpAddr, pbuf)
		} else if qc.udpConn != nil {
			_, sendErr = qc.udpConn.WriteTo(packet, qc.remoteAddr)
			if pbuf != nil {
				quicPktBufPool.Put(pbuf)
			}
		} else if pbuf != nil {
			quicPktBufPool.Put(pbuf)
		}
		qc.bytesSent.Add(uint64(len(packet)))
		if debugFlag.Load() {
			log.Printf("[QUIC-DBG] sendFrames: space=%d pn=%d pktLen=%d framesLen=%d sendErr=%v dst=%v",
				space, pn, len(packet), len(frames), sendErr, qc.udpAddr)
		}
		qc.loss.onPacketSent(space, pn, len(packet), ackEliciting, frames)
	}
}

func (qc *QUICConn) sendStreamData(s *QUICStream) {
	qc.streamWriters.Add(1)
	qc.writeMu.Lock()
	defer func() {
		if qc.streamWriters.Add(-1) == 0 && len(qc.coalesceEnds) > 0 {
			qc.drainCoalescedLocked()
		}
		qc.writeMu.Unlock()
	}()
	for {
		var connAvail uint64
		if qc.maxDataRemote > qc.dataSent {
			connAvail = qc.maxDataRemote - qc.dataSent
		}

		s.mu.Lock()
		var streamAvail uint64
		if s.maxSend > s.sendOff {
			streamAvail = s.maxSend - s.sendOff
		}
		s.mu.Unlock()

		allowed := uint64(qc.pktBudget)
		if connAvail < allowed {
			allowed = connAvail
		}
		if streamAvail < allowed {
			allowed = streamAvail
		}
		if allowed == 0 {
			if streamAvail == 0 {
				s.mu.Lock()
				sendBlocked := len(s.sendBuf) > 0 && s.blockedSent != s.maxSend
				limit := s.maxSend
				if sendBlocked {
					s.blockedSent = s.maxSend
				}
				s.mu.Unlock()
				if sendBlocked {
					qc.frameScratch = quicAppendStreamDataBlockedFrame(qc.frameScratch[:0], s.id, limit)
					qc.queueStreamFrameLocked(qc.frameScratch)
				}
			}
			return
		}

		data, offset, fin := s.drainSendBuf(int(allowed))
		if len(data) == 0 && !fin {
			return
		}

		qc.dataSent += uint64(len(data))

		qc.frameScratch = quicAppendStreamFrame(qc.frameScratch[:0], s.id, offset, data, fin)
		qc.queueStreamFrameLocked(qc.frameScratch)

		if fin || len(data) == 0 {
			return
		}
	}
}

func (qc *QUICConn) queueStreamFrameLocked(frame []byte) {
	qc.coalesceBuf = append(qc.coalesceBuf, frame...)
	qc.coalesceEnds = append(qc.coalesceEnds, len(qc.coalesceBuf))
	if len(qc.coalesceBuf)-qc.coalesceStart >= qc.pktBudget {
		qc.drainCoalescedLocked()
	}
}

func (qc *QUICConn) drainCoalescedLocked() {
	for len(qc.coalesceEnds) > 0 && qc.loss.canSend() {
		start := qc.coalesceStart
		limit := start + qc.pktBudget
		k := 0
		for k < len(qc.coalesceEnds) && qc.coalesceEnds[k] <= limit {
			k++
		}
		if k == 0 {
			k = 1
		}
		end := qc.coalesceEnds[k-1]
		qc.sendFramesLocked(quicSpaceAppData, qc.coalesceBuf[start:end], true)
		qc.coalesceStart = end
		n := copy(qc.coalesceEnds, qc.coalesceEnds[k:])
		qc.coalesceEnds = qc.coalesceEnds[:n]
	}
	if len(qc.coalesceEnds) == 0 {
		qc.coalesceBuf = qc.coalesceBuf[:0]
		qc.coalesceStart = 0
	}
}

func (qc *QUICConn) applyPeerTransportParams(ch *ParsedClientHello) {
	qc.writeMu.Lock()
	if ch.InitialMaxData > 0 {
		qc.maxDataRemote = ch.InitialMaxData
	}
	if ch.InitialMaxStreamDataBidiLocal > 0 {
		qc.peerStreamWindow = ch.InitialMaxStreamDataBidiLocal
	}
	cfgCap := qc.server.config.QUICMaxUDPPayload
	if cfgCap > quicMaxPacketSize {
		peer := ch.MaxUDPPayload
		if peer == 0 {
			peer = 65527
		}
		limit := uint64(cfgCap)
		if peer < limit {
			limit = peer
		}
		if limit > quicPktBufCap-256 {
			limit = quicPktBufCap - 256
		}
		if limit > quicMaxPacketSize {
			qc.pktBudget = int(limit) - 100
		}
	}
	qc.writeMu.Unlock()
}


func (qc *QUICConn) deriveNextRecvKeys() {
	if qc.appSuite == nil || len(qc.recvSecret) == 0 {
		return
	}
	nextSecret := quicDeriveNextTrafficSecret(qc.appSuite.HashFn, qc.recvSecret, qc.appSuite.HashLen)
	nextKeys, err := quicDeriveKeys(qc.appSuite.HashFn, nextSecret, qc.appSuite)
	if err != nil {
		return
	}
	if qc.origHP != nil {
		nextKeys.hp = qc.origHP
	}
	qc.recvSecret = nextSecret
	qc.nextRecvKeys = nextKeys
}

func (qc *QUICConn) rotateSendKeysLocked() {
	if qc.appSuite == nil || len(qc.sendSecret) == 0 {
		return
	}
	nextSecret := quicDeriveNextTrafficSecret(qc.appSuite.HashFn, qc.sendSecret, qc.appSuite.HashLen)
	nextKeys, err := quicDeriveKeys(qc.appSuite.HashFn, nextSecret, qc.appSuite)
	if err != nil {
		return
	}
	if qc.origHP != nil {
		nextKeys.hp = qc.sendKeys[quicSpaceAppData].hp
	}
	qc.sendSecret = nextSecret
	qc.sendKeys[quicSpaceAppData] = nextKeys
	qc.sendKeyPhase ^= 1
	qc.packetsInEpoch.Store(0)
}

func (qc *QUICConn) initiateKeyUpdate() {
	qc.rotateSendKeysLocked()
}

func (qc *QUICConn) respondToPeerKeyUpdate(peerPhase uint32) {
	qc.writeMu.Lock()
	defer qc.writeMu.Unlock()
	if qc.sendKeyPhase == peerPhase {
		return
	}
	qc.rotateSendKeysLocked()
}

func (qc *QUICConn) sendMaxStreamsBidi(maxStreams uint64) {
	frames := quicAppendMaxStreamsFrame(nil, maxStreams, true)
	qc.sendFrames(quicSpaceAppData, frames, true)
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
		if !qc.addressValidated.Load() && qc.bytesSent.Load() >= 3*qc.bytesReceived.Load() {
			return
		}
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
	la0 := qc.loss.largestAckedPN(quicSpaceInitial)

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
	laHS := qc.loss.largestAckedPN(quicSpaceHandshake)
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
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-qc.done:
			return
		case <-ticker.C:
			if time.Duration(turbo.UnixNano()-qc.lastActive.Load()) > qc.idleTimeout {
				qc.close()
				return
			}
		}
	}
}

func (qc *QUICConn) runLossTimer() {
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-qc.done:
			return
		case <-ticker.C:
			qc.flushPendingAck(quicSpaceAppData)
			for _, frames := range qc.loss.ptoExpiredFrames(quicSpaceAppData) {
				qc.sendFrames(quicSpaceAppData, frames, true)
			}
			qc.writeMu.Lock()
			if len(qc.coalesceEnds) > 0 {
				qc.drainCoalescedLocked()
			}
			qc.writeMu.Unlock()
		}
	}
}
