//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guno1928/alosmap"
	"github.com/guno1928/turbo"
)

var quicAsyncDispatch = os.Getenv("ALOS_H2_ASYNC") != ""

type quicConnMap = alosmap.TypedMap[[20]byte, *QUICConn]

const (
	quicSpaceInitial   = 0
	quicSpaceHandshake = 1
	quicSpaceAppData   = 2

	quicPktBufCap        = 2048
	quicMaxPktBufCap     = 33280
	quicInboundQueueSize = 32

	quicDefaultIdleTimeout      = 30 * time.Second
	quicMaxPacketSize           = 1200
	quicConnIDLen               = 8
	quicInitialMaxData          = 10 << 20
	quicInitialMaxStreamData    = 1 << 20
	quicMaxCryptoBuf            = 64 << 10
	quicMaxInitialCryptoBuf     = 16 << 10
	quicMaxConcurrentReqStreams = 256
	quicKeyUpdateThreshold      = 1 << 20
	quicMaxBidiStreams          = quicMaxConcurrentReqStreams
	quicMaxUniStreams           = 16
	quicMaxTrackedStreams       = quicMaxBidiStreams + quicMaxUniStreams + 32
	quicMaxStreamsCreditBatch   = 128
	quicCoalesceBudget          = 1100
	quicMinInitialDatagram      = 1200
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
			reqStreamWorkChs[i] = make(chan *QUICStream)
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

var quicHandshakingConns atomic.Int64

const (
	quicMaxHandshakingConns        = 8192
	quicHandshakingShareOfMaxConns = 2
)

func quicHandshakingLimit(limits *Limits) int64 {
	if limits.MaxConns > 0 {
		return max(limits.MaxConns/quicHandshakingShareOfMaxConns, 1)
	}
	return quicMaxHandshakingConns
}

func tryAcquireQUICHandshakeSlot(limits *Limits) bool {
	if quicHandshakingConns.Add(1) > quicHandshakingLimit(limits) {
		quicHandshakingConns.Add(-1)
		return false
	}
	return true
}

func quicHandshakeDeadline(server *Server) int64 {
	timeout := server.limits.Load().handshakeTimeout()
	if timeout <= 0 {
		return 0
	}
	return turbo.UnixNano() + int64(timeout)
}

const quicPrevRecvKeyRetirePTOs = 3

func (qc *QUICConn) handshakeExpired(now int64) bool {
	return qc.handshakeDeadline != 0 && now > qc.handshakeDeadline && !qc.handshakeDone.Load()
}

const (
	quicDefaultStalledSendSoftCap = 8 << 20
	quicStalledSendHardFactor     = 8
	quicSendStallTimeout          = 10 * time.Second
)

func quicStalledSendSoftCap(server *Server) int64 {
	if server.config.MaxPendingWriteBytes > 0 {
		return server.config.MaxPendingWriteBytes
	}
	return quicDefaultStalledSendSoftCap
}

func (qc *QUICConn) trackStalledSend(s *QUICStream) {
	now := turbo.UnixNano()
	pending := s.beginStalledAccounting(now)
	if pending == 0 {
		return
	}
	total := qc.stalledSendBytes.Add(pending)
	if total == pending {
		qc.lastSendProgress.Store(now)
		return
	}
	if total > qc.stallHardCap {
		qc.resetStreamSend(s, h3ErrExcessiveLoad)
	}
}

func (qc *QUICConn) sendStalledTooLong(now int64) bool {
	return qc.stalledSendBytes.Load() > qc.stallSoftCap && time.Duration(now-qc.lastSendProgress.Load()) > quicSendStallTimeout
}

func (qc *QUICConn) resetStalledStreams(now int64) {
	var oldestKept int64
	kept := false
	qc.streamsMu.Lock()
	stalled := make([]*QUICStream, 0, len(qc.streams))
	for _, s := range qc.streams {
		since, held := s.stallStart()
		if !held {
			continue
		}
		if time.Duration(now-since) > quicSendStallTimeout {
			s.refCount.Add(1)
			stalled = append(stalled, s)
		} else if !kept || since < oldestKept {
			oldestKept = since
			kept = true
		}
	}
	qc.streamsMu.Unlock()
	for _, s := range stalled {
		qc.resetStreamSend(s, h3ErrExcessiveLoad)
		qc.maybeFinishStream(s)
		qc.releaseStream(s)
	}
	if kept {
		qc.lastSendProgress.Store(oldestKept)
	}
}

func (qc *QUICConn) clearHandshaking() {
	if qc.handshakeCounted.CompareAndSwap(true, false) {
		quicHandshakingConns.Add(-1)
	}
}

var quicPktBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, quicPktBufCap); return &b },
}

var quicRecvBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, quicPktBufCap); return &b },
}

type quicInboundPkt struct {
	data   []byte
	pbuf   *[]byte
	from   netip.AddrPort
	goAway bool
}

// QUICConn represents a single server-side QUIC connection. It tracks connection IDs
// and per-packet-number-space cryptographic state, drives the TLS handshake, multiplexes
// and flow-controls streams, and handles ACK/loss recovery and packet transmission for one client.
type QUICConn struct {
	srcConnID      [20]byte
	srcCIDLen      int
	dstConnID      [20]byte
	dstCIDLen      int
	origDstConnID  [20]byte
	origDstLen     int
	retrySrcConnID [20]byte
	retrySrcLen    int
	version        uint32

	keys             [3]*quicKeys
	sendKeys         [3]*quicKeys
	sendPN           [3]uint64
	recvLargest      [3]int64
	ackRanges        [3][]pnRange
	ackFloor         [3]uint64
	pendingAck       [3][]byte
	ackScratch       [3][]byte
	frameScratch     []byte
	combineScratch   []byte
	coalesceBuf      []byte
	coalesceEnds     []int
	coalesceStart    int
	pktBudget        int
	peerStreamWindow uint64
	peerUniWindow    uint64
	streamWriters    atomic.Int32
	workShard        uint8
	loss             *quicLossState
	cryptoBuf        [3][]byte
	cryptoRcv        [3][]bool
	cryptoContig     [3]int

	recvKeyPhase   uint32
	sendKeyPhase   uint32
	nextRecvKeys   *quicKeys
	prevRecvKeys   *quicKeys
	prevKeyRetire  int64
	keyUpdatePN    uint64
	packetsInEpoch atomic.Uint64
	recvSecret     []byte
	sendSecret     []byte
	appSuite       *CipherSuiteConfig
	origHP         headerProtector

	tlsState      *quicTLSState
	peerCerts     []*x509.Certificate
	tlsCertEntry  *CertEntry
	handshakeDone atomic.Bool
	firstFlight   struct {
		serverHello       []byte
		ee, cert, cv, fin []byte
		sent              bool
		initialOffset     uint64
	}

	streams        map[uint64]*QUICStream
	streamsMu      sync.Mutex
	nextBidiRemote uint64
	nextUniRemote  uint64
	nextBidiLocal  uint64
	nextUniLocal   uint64
	implicitRemote map[uint64]struct{}
	goAwayID       uint64
	draining       atomic.Bool
	maxBidiRemote  uint64
	maxUniRemote   uint64

	cidMu        sync.Mutex
	connMap      *quicConnMap
	issued       []quicIssuedCID
	nextIssueSeq uint64
	peerCIDs     []quicPeerCID
	peerCIDsInit bool
	peerRetirePT uint64
	peerCIDLimit uint64
	dstCIDSeq    uint64
	rxDCID       [quicConnIDLen]byte

	pathMu        sync.Mutex
	pathAddr      netip.AddrPort
	pathGen       atomic.Uint32
	rxPath        netip.AddrPort
	rxPathGen     uint32
	lastValidAddr netip.AddrPort
	probe         quicPathProbe
	probing       atomic.Bool
	rxFrom        netip.AddrPort
	rxLen         int
	rxNonProbing  bool

	maxDataLocal    uint64
	maxDataRemote   uint64
	dataSent        uint64
	dataRecv        uint64
	dataRecvGranted uint64

	bytesSent        atomic.Uint64
	bytesReceived    atomic.Uint64
	addressValidated atomic.Bool
	handshakeCounted atomic.Bool

	handshakeDeadline int64

	peerAckDelayExponent uint64

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

	h3      *H3Conn
	inbound chan quicInboundPkt

	bodyReserved       atomic.Int64
	recvFlowUsed       atomic.Uint64
	recvFlowLimit      atomic.Uint64
	stalledSendBytes   atomic.Int64
	lastSendProgress   atomic.Int64
	stallSoftCap       int64
	stallHardCap       int64
	activeReqStreams   atomic.Int32
	bidiStreamsRetired atomic.Uint64
	uniStreamsRetired  atomic.Uint64
	timerWork          atomic.Bool
}

func newQUICConn(server *Server, udpConn net.PacketConn, remoteAddr net.Addr, dcid, scid []byte) *QUICConn {
	maxData := uint64(quicInitialMaxData)
	if server.config.QUICMaxData > 0 {
		maxData = uint64(server.config.QUICMaxData)
	}
	qc := &QUICConn{
		version:         quicVersion1,
		server:          server,
		udpConn:         udpConn,
		remoteAddr:      remoteAddr,
		done:            make(chan struct{}),
		streams:         make(map[uint64]*QUICStream),
		loss:            newQuicLossState(),
		idleTimeout:     optionalDuration(server.limits.Load().IdleTimeout, quicDefaultIdleTimeout),
		maxDataLocal:    maxData,
		maxDataRemote:   maxData,
		dataRecvGranted: maxData,
		nextBidiRemote:  0,
		nextUniRemote:   2,
		nextBidiLocal:   1,
		nextUniLocal:    3,
		maxBidiRemote:   quicMaxBidiStreams,
		maxUniRemote:    quicMaxUniStreams,
	}
	qc.handshakeDeadline = quicHandshakeDeadline(server)
	qc.peerAckDelayExponent = quicDefaultAckDelayExponent
	qc.peerStreamWindow = quicDefaultStreamSendWindow
	qc.peerUniWindow = quicDefaultStreamSendWindow
	qc.recvFlowLimit.Store(maxData)
	qc.stallSoftCap = quicStalledSendSoftCap(server)
	qc.stallHardCap = qc.stallSoftCap * quicStalledSendHardFactor

	qc.workShard = uint8(connShardCounter.Add(1) % reqStreamShards)
	qc.pktBudget = quicCoalesceBudget
	qc.lastActive.Store(turbo.UnixNano())
	qc.inbound = make(chan quicInboundPkt, quicInboundQueueSize)
	qc.recvLargest[0] = -1
	qc.recvLargest[1] = -1
	qc.recvLargest[2] = -1
	qc.origDstLen = copy(qc.origDstConnID[:], dcid)

	var newCID [quicConnIDLen]byte
	rand.Read(newCID[:])
	qc.srcCIDLen = copy(qc.srcConnID[:], newCID[:])
	qc.dstCIDLen = copy(qc.dstConnID[:], scid)
	qc.initPath(remoteAddr)

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

func (qc *QUICConn) handlePacketPooled(data []byte, pbuf *[]byte) {
	qc.handlePacketFromPooled(data, pbuf, netip.AddrPort{})
}

func (qc *QUICConn) handlePacketFromPooled(data []byte, pbuf *[]byte, from netip.AddrPort) {
	if qc == nil || qc.closed.Load() {
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
		return
	}
	select {
	case qc.inbound <- quicInboundPkt{data: data, pbuf: pbuf, from: from}:
	default:
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
	}
}

func (qc *QUICConn) recvLoop() {
	defer func() {
		if r := recover(); r != nil {
			qc.server.reportPanic(nil, r)
			qc.close()
		}
	}()
	if debugFlag.Load() {
		Dbg("[QUIC-DBG] recvLoop started for %s", qc.remoteAddr.String())
	}
	for {
		select {
		case pkt := <-qc.inbound:
			if pkt.goAway {
				qc.beginGoAway()
				continue
			}
			qc.lastActive.Store(turbo.UnixNano())
			qc.processPacket(pkt.data, pkt.from)
			if pkt.pbuf != nil {
				quicRecvBufPool.Put(pkt.pbuf)
			}
		case <-qc.done:
			return
		}
	}
}

func (qc *QUICConn) processPacket(data []byte, from netip.AddrPort) {
	qc.notePacketSource(from, len(data))
	if len(data) == 0 {
		return
	}
	if debugFlag.Load() {
		Dbg("[QUIC-DBG] processPacket: %d bytes, first=0x%02x", len(data), data[0])
	}
	var datagramDCID []byte
	for len(data) > 0 {
		if quicIsLongHeader(data) {
			consumed := qc.handleLongHeaderPacket(data)
			if consumed <= 0 || consumed > len(data) {
				break
			}
			if datagramDCID == nil {
				datagramDCID = quicPacketDCID(data, qc.srcCIDLen)
			}
			data = data[consumed:]
			if len(data) > 0 && !bytes.Equal(quicPacketDCID(data, qc.srcCIDLen), datagramDCID) {
				break
			}
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
			Dbg("[QUIC-DBG] parseLongHeader failed: %v (dataLen=%d)", err, len(data))
		}
		return 0
	}
	packet := data[:total]
	if hdr.version != qc.version {
		return total
	}

	if debugFlag.Load() {
		Dbg("[QUIC-DBG] longHeader: type=%d ver=0x%08x dcid=%x scid=%x total=%d pnOff=%d payOff=%d payLen=%d",
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
	if !qc.handshakeDone.Load() {
		return
	}
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

	recvKeys, keyUpdate := qc.selectRecvKeys(keys, pktKeyPhase, pn)
	if recvKeys == nil {
		return
	}
	plaintext, err := recvKeys.decrypt(ciphertext[:0], header, ciphertext, pn)
	if err != nil {
		return
	}
	if keyUpdate {
		qc.commitPeerKeyUpdate(keys, pktKeyPhase, pn)
	}

	if qc.prevRecvKeys != nil && turbo.UnixNano() > qc.prevKeyRetire {
		qc.prevRecvKeys = nil
	}

	copy(qc.rxDCID[:], data[1:1+qc.srcCIDLen])
	qc.processFrames(quicSpaceAppData, hdr.pn, plaintext)
	qc.observePacketPath(hdr.pn)
}

func (qc *QUICConn) selectRecvKeys(current *quicKeys, phase uint32, pn uint64) (*quicKeys, bool) {
	if phase == qc.recvKeyPhase {
		return current, false
	}
	if pn < qc.keyUpdatePN {
		if qc.prevRecvKeys != nil && turbo.UnixNano() <= qc.prevKeyRetire {
			return qc.prevRecvKeys, false
		}
		return nil, false
	}
	return qc.nextRecvKeys, qc.nextRecvKeys != nil
}

func (qc *QUICConn) commitPeerKeyUpdate(previous *quicKeys, phase uint32, pn uint64) {
	qc.prevRecvKeys = previous
	qc.keys[quicSpaceAppData] = qc.nextRecvKeys
	qc.nextRecvKeys = nil
	qc.recvKeyPhase = phase
	qc.keyUpdatePN = pn
	qc.writeMu.Lock()
	pto := qc.loss.ptoTimeout()
	qc.writeMu.Unlock()
	qc.prevKeyRetire = turbo.UnixNano() + int64(quicPrevRecvKeyRetirePTOs*pto)
	qc.deriveNextRecvKeys()
	qc.respondToPeerKeyUpdate(phase)
}

func (qc *QUICConn) handleInitialPacket(packet []byte, hdr *quicPacketHeader) {
	keys := qc.keys[quicSpaceInitial]
	if keys == nil || !keys.valid {
		if debugFlag.Load() {
			Dbg("[QUIC-DBG] handleInitial: no keys (nil=%v)", keys == nil)
		}
		return
	}

	plaintext, err := quicDecryptPacket(packet, hdr, keys, qc.recvLargest[quicSpaceInitial])
	if err != nil {
		if debugFlag.Load() {
			Dbg("[QUIC-DBG] handleInitial: decrypt failed: %v (pktLen=%d pnOff=%d payOff=%d payLen=%d)", err, len(packet), hdr.pnOffset, hdr.payloadOff, hdr.payloadLen)
		}
		return
	}

	if debugFlag.Load() {
		Dbg("[QUIC-DBG] handleInitial: decrypted %d bytes, pn=%d", len(plaintext), hdr.pn)
	}
	qc.processFrames(quicSpaceInitial, hdr.pn, plaintext)
}

func (qc *QUICConn) handleHandshakePacket(packet []byte, hdr *quicPacketHeader) {
	keys := qc.keys[quicSpaceHandshake]
	if keys == nil || !keys.valid {
		if debugFlag.Load() {
			Dbg("[QUIC-DBG] handleHandshake: no keys (nil=%v valid=%v)", keys == nil, keys != nil && keys.valid)
		}
		return
	}

	plaintext, err := quicDecryptPacket(packet, hdr, keys, qc.recvLargest[quicSpaceHandshake])
	if err != nil {
		if debugFlag.Load() {
			Dbg("[QUIC-DBG] handleHandshake: decrypt failed: %v", err)
		}
		return
	}

	if debugFlag.Load() {
		Dbg("[QUIC-DBG] handleHandshake: decrypted %d bytes, pn=%d", len(plaintext), hdr.pn)
	}
	if qc.keys[quicSpaceInitial] != nil {
		qc.discardKeys(quicSpaceInitial)
	}
	qc.processFrames(quicSpaceHandshake, hdr.pn, plaintext)
}

func (qc *QUICConn) discardKeys(space int) {
	qc.writeMu.Lock()
	qc.keys[space] = nil
	qc.sendKeys[space] = nil
	qc.pendingAck[space] = nil
	qc.writeMu.Unlock()
	qc.loss.discardSpace(space)
}

func (qc *QUICConn) processFrames(space int, pn uint64, frames []byte) {
	qc.rxNonProbing = false
	if int64(pn) > qc.recvLargest[space] {
		qc.recvLargest[space] = int64(pn)
	}
	if !qc.recordRecvPN(space, pn) {
		if space != quicSpaceInitial || qc.handshakeDone.Load() {
			if space == quicSpaceAppData {
				qc.stashAck(space)
			} else {
				qc.sendACK(space)
			}
		}
		return
	}
	needsAck := false
	lossCheck := false

	visitor := &quicFrameVisitor{
		onACK: func(f quicAckFrame) {
			if qc.closed.Load() {
				return
			}
			qc.writeMu.Lock()
			lossPossible, ackErr := qc.loss.onAckReceived(space, f, qc.peerAckDelayLocked(space, f.ackDelay), qc.sendPN[space])
			if ackErr == nil && len(qc.coalesceEnds) > 0 {
				qc.drainCoalescedLocked()
			}
			qc.writeMu.Unlock()
			if ackErr != nil {
				qc.closeWithError(quicErrProtocolViolation, ackErr.Error())
				return
			}
			lossCheck = lossCheck || lossPossible
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
			grew := f.maxData > qc.maxDataRemote
			if grew {
				qc.maxDataRemote = f.maxData
			}
			qc.writeMu.Unlock()
			if grew {
				qc.resumeBlockedStreams()
			}
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
		onResetStream: func(f quicResetStreamFrame) {
			needsAck = true
			qc.handleResetStream(f)
		},
		onStopSending: func(f quicStopSendingFrame) {
			needsAck = true
			qc.handleStopSending(f)
		},
		onNewConnID: func(f quicNewConnIDFrame) {
			needsAck = true
			qc.handlePeerNewConnID(f)
		},
		onRetireConnID: func(seq uint64) {
			needsAck = true
			qc.handleRetireConnID(seq)
		},
		onPathChallenge: func(data [quicPathChallengeLen]byte) {
			needsAck = true
			qc.handlePathChallenge(data)
		},
		onPathResponse: func(data [quicPathChallengeLen]byte) {
			needsAck = true
			qc.handlePathResponse(data)
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

	if space != quicSpaceAppData {
		visitor.allowed = quicFrameAllowedInHandshakeSpaces
	}
	err := quicParseFrames(frames, visitor)
	qc.rxNonProbing = visitor.nonProbing
	if err != nil {
		if err == errQUICFrameNotAllowedInSpace {
			qc.closeWithError(quicErrProtocolViolation, err.Error())
			return
		}
		qc.closeWithError(quicErrFrameEncoding, err.Error())
		return
	}
	if qc.closed.Load() {
		return
	}
	if lossCheck {
		qc.recoverLostPackets(space)
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
	qc.timerWork.Store(true)
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

	maxBuf := uint64(quicMaxCryptoBuf)
	if space == quicSpaceInitial {
		maxBuf = quicMaxInitialCryptoBuf
	}
	end := f.offset + uint64(len(f.data))
	if f.offset > maxBuf || end > maxBuf {
		return
	}
	if end > uint64(len(qc.cryptoBuf[space])) {
		if uint64(cap(qc.cryptoBuf[space])) >= end {
			qc.cryptoBuf[space] = qc.cryptoBuf[space][:end]
			qc.cryptoRcv[space] = qc.cryptoRcv[space][:end]
		} else {
			grownCap := uint64(2 * cap(qc.cryptoBuf[space]))
			if grownCap < end {
				grownCap = end
			}
			if grownCap > maxBuf {
				grownCap = maxBuf
			}
			grownBuf := make([]byte, end, grownCap)
			copy(grownBuf, qc.cryptoBuf[space])
			grownRcv := make([]bool, end, grownCap)
			copy(grownRcv, qc.cryptoRcv[space])
			qc.cryptoBuf[space] = grownBuf
			qc.cryptoRcv[space] = grownRcv
		}
	}
	copy(qc.cryptoBuf[space][f.offset:], f.data)
	for i := f.offset; i < end; i++ {
		qc.cryptoRcv[space][i] = true
	}
	if int(f.offset) <= qc.cryptoContig[space] {
		contig := qc.cryptoContig[space]
		rcv := qc.cryptoRcv[space]
		for contig < len(rcv) && rcv[contig] {
			contig++
		}
		qc.cryptoContig[space] = contig
	}

	for !qc.closed.Load() {
		start := qc.tlsState.messageStart(space)
		if qc.cryptoContig[space] < start+4 {
			return
		}
		msg := qc.cryptoBuf[space][start:]
		msgLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
		needed := 4 + msgLen
		if qc.cryptoContig[space] < start+needed {
			return
		}
		if debugFlag.Load() {
			Dbg("[QUIC-DBG] handleCryptoFrame: space=%d complete message %d bytes, all bytes verified", space, needed)
		}
		qc.tlsState.handleCryptoData(qc, space, msg[:needed])
		if qc.tlsState.messageStart(space) == start {
			return
		}
	}
}

func (qc *QUICConn) handleStreamFrameIncoming(f quicStreamFrame) {
	if quicStreamIsLocal(f.streamID, true) && !quicStreamIsBidi(f.streamID) {
		qc.closeWithError(quicErrStreamState, "STREAM frame on a send-only stream")
		return
	}
	qc.streamsMu.Lock()
	if qc.closed.Load() {
		qc.streamsMu.Unlock()
		return
	}
	s, ok := qc.streams[f.streamID]
	if !ok {
		switch qc.openPeerStreamLocked(f.streamID) {
		case quicPeerStreamClosed:
			qc.streamsMu.Unlock()
			return
		case quicPeerStreamOverLimit:
			qc.streamsMu.Unlock()
			qc.closeWithError(quicErrStreamLimit, "stream ID beyond MAX_STREAMS")
			return
		case quicPeerStreamInvalid:
			qc.streamsMu.Unlock()
			qc.closeWithError(quicErrStreamState, "STREAM frame on a stream the peer cannot send on")
			return
		}
		if qc.rejectedByGoAwayLocked(f.streamID) {
			qc.streamsMu.Unlock()
			qc.refuseStream(f.streamID)
			return
		}
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

	acceptedBytes, flags := s.handleStreamFrame(f)
	if flags&quicRecvViolation != 0 {
		qc.releaseStream(s)
		qc.closeWithError(quicErrFlowControl, "stream data beyond advertised limit")
		return
	}
	if flags&quicRecvFinalSizeError != 0 {
		qc.releaseStream(s)
		qc.closeWithError(quicErrFinalSize, "STREAM frame contradicts the final size")
		return
	}
	if flags&quicRecvRejected != 0 {
		qc.rejectStreamBody(s)
		qc.releaseStream(s)
		return
	}
	if acceptedBytes > 0 {
		qc.grantReceiveCredit(s, uint64(acceptedBytes))
	}
	if flags != 0 && !quicStreamIsBidi(f.streamID) && qc.h3 != nil {
		qc.h3.readPeerStream(s)
	}

	if flags&quicRecvEndOfData != 0 && qc.h3 != nil && quicStreamIsBidi(f.streamID) && !quicStreamIsLocal(f.streamID, true) {
		if qc.activeReqStreams.Add(1) > quicMaxConcurrentReqStreams {
			qc.activeReqStreams.Add(-1)
			if s.dispatched.CompareAndSwap(false, true) {
				qc.resetStreamSend(s, h3ErrRequestRejected)
				qc.retireStream(s)
			}
		} else if !s.dispatched.CompareAndSwap(false, true) {
			qc.activeReqStreams.Add(-1)
		} else {
			s.refCount.Add(1)
			if quicAsyncDispatch {
				go qc.serveRequestStream(s)
			} else {
				select {
				case reqStreamWorkChs[qc.workShard] <- s:
				default:
					go qc.serveRequestStream(s)
				}
			}
		}
	}
	qc.releaseStream(s)
}

type quicPeerStreamState uint8

const (
	quicPeerStreamOpen quicPeerStreamState = iota
	quicPeerStreamClosed
	quicPeerStreamOverLimit
	quicPeerStreamInvalid
)

func (qc *QUICConn) openPeerStreamLocked(id uint64) quicPeerStreamState {
	if quicStreamIsLocal(id, true) {
		return quicPeerStreamInvalid
	}
	next, limit := &qc.nextBidiRemote, qc.maxBidiRemote
	if !quicStreamIsBidi(id) {
		next, limit = &qc.nextUniRemote, qc.maxUniRemote
	}
	if id < *next {
		if _, pending := qc.implicitRemote[id]; pending {
			delete(qc.implicitRemote, id)
			return quicPeerStreamOpen
		}
		return quicPeerStreamClosed
	}
	if id>>2 >= limit {
		return quicPeerStreamOverLimit
	}
	for skipped := *next; skipped < id; skipped += 4 {
		if qc.implicitRemote == nil {
			qc.implicitRemote = make(map[uint64]struct{})
		}
		qc.implicitRemote[skipped] = struct{}{}
	}
	*next = id + 4
	return quicPeerStreamOpen
}

func (qc *QUICConn) grantReceiveCredit(s *QUICStream, acceptedBytes uint64) {
	var creditBuf [32]byte
	frames := creditBuf[:0]
	if grant := s.streamCreditToGrant(); grant > 0 {
		frames = quicAppendMaxStreamDataFrame(frames, s.id, grant)
	}
	frames = qc.appendConnectionCredit(frames, acceptedBytes)
	if len(frames) > 0 {
		qc.sendFrames(quicSpaceAppData, frames, true)
	}
}

func (qc *QUICConn) appendConnectionCredit(frames []byte, consumed uint64) []byte {
	qc.streamsMu.Lock()
	qc.dataRecv += consumed
	if qc.dataRecv+qc.maxDataLocal/2 > qc.dataRecvGranted {
		qc.dataRecvGranted = qc.dataRecv + qc.maxDataLocal
		qc.recvFlowLimit.Store(qc.dataRecvGranted)
		frames = quicAppendMaxDataFrame(frames, qc.dataRecvGranted)
	}
	qc.streamsMu.Unlock()
	return frames
}

func (qc *QUICConn) rejectStreamBody(s *QUICStream) {
	if !quicStreamIsBidi(s.id) {
		qc.closeWithAppError(h3ErrExcessiveLoad, "cannot buffer data on a control stream")
		return
	}
	if !s.dispatched.CompareAndSwap(false, true) {
		return
	}
	var creditBuf [16]byte
	if frames := qc.appendConnectionCredit(creditBuf[:0], s.unreceivedCredit()); len(frames) > 0 {
		qc.sendFrames(quicSpaceAppData, frames, true)
	}
	qc.stopSending(s.id, h3ErrRequestRejected)
	qc.resetStreamSend(s, h3ErrRequestRejected)
	qc.retireStream(s)
}

func (qc *QUICConn) consumeRecvFlowCredit(n uint64) bool {
	return qc.recvFlowUsed.Add(n) <= qc.recvFlowLimit.Load()
}

func (qc *QUICConn) grantedRecvData() uint64 {
	qc.streamsMu.Lock()
	defer qc.streamsMu.Unlock()
	return qc.dataRecvGranted
}

func (qc *QUICConn) acquireStream(id uint64) *QUICStream {
	qc.streamsMu.Lock()
	s, ok := qc.streams[id]
	if ok {
		s.refCount.Add(1)
	}
	qc.streamsMu.Unlock()
	if !ok {
		return nil
	}
	return s
}

func (qc *QUICConn) localStreamOpened(id uint64) bool {
	if quicStreamIsBidi(id) {
		return false
	}
	qc.streamsMu.Lock()
	opened := id < qc.nextUniLocal
	qc.streamsMu.Unlock()
	return opened
}

func (qc *QUICConn) handleResetStream(f quicResetStreamFrame) {
	if quicStreamIsLocal(f.streamID, true) && !quicStreamIsBidi(f.streamID) {
		qc.closeWithError(quicErrStreamState, "RESET_STREAM on a send-only stream")
		return
	}
	s := qc.acquireStream(f.streamID)
	if s == nil {
		return
	}
	defer qc.releaseStream(s)
	uncounted, errCode := s.applyPeerReset(f.finalSize)
	if errCode != 0 {
		qc.closeWithError(errCode, "RESET_STREAM final size")
		return
	}
	if uncounted > 0 {
		var creditBuf [16]byte
		if frames := qc.appendConnectionCredit(creditBuf[:0], uncounted); len(frames) > 0 {
			qc.sendFrames(quicSpaceAppData, frames, true)
		}
	}
	s.abortHandler(ErrClientGone)
	if !quicStreamIsBidi(f.streamID) && qc.h3 != nil {
		qc.h3.peerStreamReset(f.streamID)
		if qc.closed.Load() {
			return
		}
	}
	if s.dispatched.CompareAndSwap(false, true) {
		if quicStreamIsBidi(f.streamID) {
			qc.resetStreamSend(s, h3ErrRequestIncomplete)
		}
		qc.retireStream(s)
	}
}

func (qc *QUICConn) acquirePeerUniStreams() []*QUICStream {
	qc.streamsMu.Lock()
	defer qc.streamsMu.Unlock()
	var peer []*QUICStream
	for id, s := range qc.streams {
		if !quicStreamIsBidi(id) && !quicStreamIsLocal(id, true) {
			s.refCount.Add(1)
			peer = append(peer, s)
		}
	}
	return peer
}

func (qc *QUICConn) stopSending(streamID, errorCode uint64) {
	qc.writeMu.Lock()
	qc.frameScratch = quicAppendStopSendingFrame(qc.frameScratch[:0], streamID, errorCode)
	qc.queueControlFrameLocked(qc.frameScratch)
	qc.writeMu.Unlock()
}

func (qc *QUICConn) closeWithAppError(errorCode uint64, reason string) {
	if qc.closed.Load() {
		return
	}
	qc.sendFrames(quicSpaceAppData, quicAppendAppCloseFrame(nil, errorCode, reason), false)
	qc.close()
}

func (qc *QUICConn) handleStopSending(f quicStopSendingFrame) {
	if quicStreamIsLocal(f.streamID, true) {
		if !qc.localStreamOpened(f.streamID) {
			qc.closeWithError(quicErrStreamState, "STOP_SENDING on a stream that was never opened")
			return
		}
	} else if !quicStreamIsBidi(f.streamID) {
		qc.closeWithError(quicErrStreamState, "STOP_SENDING on a receive-only stream")
		return
	}
	s := qc.acquireStream(f.streamID)
	if s == nil {
		return
	}
	defer qc.releaseStream(s)
	qc.resetStreamSend(s, f.errorCode)
	s.abortHandler(ErrClientGone)
	qc.maybeFinishStream(s)
}

func (qc *QUICConn) resetStreamSend(s *QUICStream, errorCode uint64) {
	finalSize, first := s.resetSend()
	if !first {
		return
	}
	qc.writeMu.Lock()
	qc.frameScratch = quicAppendResetStreamFrame(qc.frameScratch[:0], s.id, errorCode, finalSize)
	qc.queueControlFrameLocked(qc.frameScratch)
	qc.writeMu.Unlock()
}

func (qc *QUICConn) queueControlFrameLocked(frame []byte) {
	qc.queueStreamFrameLocked(frame)
	if qc.streamWriters.Load() == 0 {
		qc.drainCoalescedLocked()
	}
}

func (qc *QUICConn) closeWithError(errorCode uint64, reason string) {
	if qc.closed.Load() {
		return
	}
	qc.sendConnectionClose(errorCode, reason)
	qc.close()
}

func (qc *QUICConn) serveRequestStream(s *QUICStream) {
	defer qc.activeReqStreams.Add(-1)
	defer qc.releaseStream(s)
	qc.h3.handleRequestStream(s)
	s.mu.Lock()
	s.handlerFinishedLocked()
	s.awaitingCleanup = true
	drained := len(s.sendBuf) == 0
	s.mu.Unlock()
	if drained {
		qc.finishRequestStream(s)
	}
}

func (qc *QUICConn) finishRequestStream(s *QUICStream) {
	qc.retireStream(s)
}

func (qc *QUICConn) retireStream(s *QUICStream) {
	if !s.cleanupDone.CompareAndSwap(false, true) {
		return
	}
	id := s.id
	qc.streamsMu.Lock()
	ownsMapRef := qc.streams[id] == s
	if ownsMapRef {
		delete(qc.streams, id)
	}
	qc.streamsMu.Unlock()
	if ownsMapRef {
		qc.releaseStream(s)
	}
	if qc.closed.Load() {
		return
	}
	if !quicStreamIsBidi(id) {
		if !quicStreamIsLocal(id, true) {
			qc.grantUniStreams(qc.uniStreamsRetired.Add(1) + quicMaxUniStreams)
		}
		return
	}
	retired := qc.bidiStreamsRetired.Add(1)
	if retired%quicMaxStreamsCreditBatch == 0 {
		qc.grantBidiStreams(retired + quicMaxBidiStreams)
	}
}

func (qc *QUICConn) resumeBlockedStreams() {
	qc.streamsMu.Lock()
	pending := make([]*QUICStream, 0, len(qc.streams))
	for _, s := range qc.streams {
		s.mu.Lock()
		blocked := len(s.sendBuf) > 0
		s.mu.Unlock()
		if blocked {
			s.refCount.Add(1)
			pending = append(pending, s)
		}
	}
	qc.streamsMu.Unlock()
	for _, s := range pending {
		qc.sendStreamData(s)
		qc.maybeFinishStream(s)
		qc.releaseStream(s)
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

func (qc *QUICConn) openLocalUniStream() *QUICStream {
	qc.streamsMu.Lock()
	if qc.closed.Load() {
		qc.streamsMu.Unlock()
		return nil
	}
	id := qc.nextUniLocal
	qc.nextUniLocal += 4
	s := newQUICStream(id, qc)
	s.maxSend = qc.peerUniWindow
	s.refCount.Store(2)
	qc.streams[id] = s
	qc.streamsMu.Unlock()
	return s
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
	qc.sendFramesToLocked(space, frames, ackEliciting, nil)
}

func (qc *QUICConn) sendFramesToLocked(space int, frames []byte, ackEliciting bool, probeAddr *net.UDPAddr) {
	keys := qc.sendKeys[space]
	if keys == nil || !keys.valid {
		keys = qc.keys[space]
	}
	if keys == nil || !keys.valid {
		return
	}

	if len(qc.pendingAck[space]) > 0 && probeAddr == nil {
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
		dst, dstAddr := qc.udpAddr, qc.remoteAddr
		blocked := false
		if probeAddr != nil {
			dst, dstAddr = probeAddr, probeAddr
		} else {
			blocked = !qc.addressValidated.Load() && qc.bytesSent.Load()+uint64(len(packet)) > quicAmplificationFactor*qc.bytesReceived.Load()
		}
		var sendErr error
		switch {
		case blocked:
			if pbuf != nil {
				quicPktBufPool.Put(pbuf)
			}
		case qc.uringUDP != nil && dst != nil:
			_, sendErr = qc.uringUDP.sendToPooled(packet, dst, pbuf)
		case qc.udpConn != nil:
			_, sendErr = writeQUICDatagram(qc.udpConn, packet, dstAddr)
			if pbuf != nil {
				quicPktBufPool.Put(pbuf)
			}
		case pbuf != nil:
			quicPktBufPool.Put(pbuf)
		}
		if !blocked && probeAddr == nil && !qc.addressValidated.Load() {
			qc.bytesSent.Add(uint64(len(packet)))
		}
		if debugFlag.Load() {
			Dbg("[QUIC-DBG] sendFrames: space=%d pn=%d pktLen=%d framesLen=%d sendErr=%v dst=%v",
				space, pn, len(packet), len(frames), sendErr, qc.udpAddr)
		}
		qc.loss.onPacketSent(space, pn, len(packet), ackEliciting, frames)
		if ackEliciting {
			qc.timerWork.Store(true)
		}
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
	qc.timerWork.Store(true)
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
		if qc.ampBudgetLocked() < end-start+len(qc.pendingAck[quicSpaceAppData])+quicShortHeaderMaxOverhead {
			break
		}
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

func (qc *QUICConn) peerAckDelayLocked(space int, encoded uint64) time.Duration {
	if space != quicSpaceAppData {
		return 0
	}
	limit := qc.loss.peerMaxAckDelay
	if encoded > uint64(limit/time.Microsecond) {
		return limit
	}
	return min(time.Duration(encoded<<qc.peerAckDelayExponent)*time.Microsecond, limit)
}

func (qc *QUICConn) applyPeerTransportParams(ch *ParsedClientHello) {
	qc.writeMu.Lock()
	if ch.quicTP.seen {
		qc.peerAckDelayExponent = ch.quicTP.ackDelayExponent
		qc.loss.setPeerMaxAckDelay(time.Duration(ch.quicTP.maxAckDelayMs) * time.Millisecond)
	}
	qc.maxDataRemote = ch.InitialMaxData
	qc.peerStreamWindow = ch.InitialMaxStreamDataBidiLocal
	qc.peerUniWindow = ch.InitialMaxStreamDataUni
	qc.cidMu.Lock()
	qc.peerCIDLimit = ch.ActiveConnIDLimit
	qc.cidMu.Unlock()
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
		if limit > quicMaxPktBufCap-256 {
			limit = quicMaxPktBufCap - 256
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

func (qc *QUICConn) grantBidiStreams(maxStreams uint64) {
	qc.grantStreams(&qc.maxBidiRemote, maxStreams, true)
}

func (qc *QUICConn) grantUniStreams(maxStreams uint64) {
	qc.grantStreams(&qc.maxUniRemote, maxStreams, false)
}

func (qc *QUICConn) grantStreams(limit *uint64, maxStreams uint64, bidi bool) {
	qc.streamsMu.Lock()
	grew := maxStreams > *limit
	if grew {
		*limit = maxStreams
	}
	qc.streamsMu.Unlock()
	if !grew {
		return
	}
	qc.writeMu.Lock()
	qc.frameScratch = quicAppendMaxStreamsFrame(qc.frameScratch[:0], maxStreams, bidi)
	qc.queueControlFrameLocked(qc.frameScratch)
	qc.writeMu.Unlock()
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
			Dbg("[QUIC-DBG] sendFirstFlight: missing keys")
		}
		return
	}

	sendDatagram := func(data []byte) {
		if !qc.addressValidated.Load() && qc.bytesSent.Load()+uint64(len(data)) > quicAmplificationFactor*qc.bytesReceived.Load() {
			return
		}
		if qc.uringUDP != nil && qc.udpAddr != nil {
			qc.uringUDP.sendTo(data, qc.udpAddr)
		} else if qc.udpConn != nil {
			_, _ = writeQUICDatagram(qc.udpConn, data, qc.remoteAddr)
		}
		if !qc.addressValidated.Load() {
			qc.bytesSent.Add(uint64(len(data)))
		}
	}

	var hsMessages []byte
	hsMessages = append(hsMessages, ee...)
	hsMessages = append(hsMessages, cert...)
	hsMessages = append(hsMessages, cv...)
	hsMessages = append(hsMessages, fin...)

	const maxCryptoPerPacket = 1000

	largest := qc.recvLargest[quicSpaceInitial]
	la0 := qc.loss.largestAckedPN(quicSpaceInitial)
	laHS := qc.loss.largestAckedPN(quicSpaceHandshake)
	coalesceHandshake := len(serverHello) <= maxCryptoPerPacket
	hsSent := 0
	for shOff := 0; shOff < len(serverHello); {
		chunk := serverHello[shOff:min(len(serverHello), shOff+maxCryptoPerPacket)]
		var initialFrames []byte
		if shOff == 0 && largest >= 0 {
			initialFrames = quicAppendACKFrame(initialFrames, uint64(largest), 0, 0)
		}
		initialFrames = quicAppendCryptoFrame(initialFrames, qc.firstFlight.initialOffset+uint64(shOff), chunk)
		shOff += len(chunk)
		pn0 := qc.sendPN[quicSpaceInitial]
		qc.sendPN[quicSpaceInitial]++

		var hsPkt, hsFrames []byte
		pnHS0 := qc.sendPN[quicSpaceHandshake]
		if coalesceHandshake {
			firstHSChunk := hsMessages[:min(len(hsMessages), maxCryptoPerPacket)]
			hsFrames = quicAppendCryptoFrame(nil, 0, firstHSChunk)
			qc.sendPN[quicSpaceHandshake]++
			hsPkt = quicBuildHandshakePacket(nil, qc.dstCID(), qc.srcCID(), hsFrames, pnHS0, laHS, hsKeys)
			hsSent = len(firstHSChunk)
		}

		initialPkt := quicBuildInitialPacket(nil, qc.dstCID(), qc.srcCID(), nil, initialFrames, pn0, la0, initialKeys)
		if padNeeded := quicMaxPacketSize - len(initialPkt) - len(hsPkt); padNeeded > 0 {
			paddedFrames := make([]byte, len(initialFrames)+padNeeded)
			copy(paddedFrames, initialFrames)
			initialPkt = quicBuildInitialPacket(nil, qc.dstCID(), qc.srcCID(), nil, paddedFrames, pn0, la0, initialKeys)
		}
		if debugFlag.Load() {
			Dbg("[H3-DBG] sendFirstFlight: Initial pn=%d %d bytes, coalesced HS %d bytes", pn0, len(initialPkt), len(hsPkt))
		}
		datagram := make([]byte, 0, len(initialPkt)+len(hsPkt))
		datagram = append(datagram, initialPkt...)
		datagram = append(datagram, hsPkt...)
		sendDatagram(datagram)
		qc.loss.onPacketSent(quicSpaceInitial, pn0, quicMaxPacketSize, true, initialFrames)
		if hsPkt != nil {
			qc.loss.onPacketSent(quicSpaceHandshake, pnHS0, len(hsPkt), true, hsFrames)
		}
	}

	hsOffset := uint64(hsSent)
	remaining := hsMessages[hsSent:]
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
			Dbg("[H3-DBG] sendFirstFlight: datagram%d (HS%d) %d bytes, crypto offset=%d len=%d",
				chunkIdx+1, chunkIdx, len(hsPkt), hsOffset, len(chunk))
		}
		sendDatagram(hsPkt)
		qc.loss.onPacketSent(quicSpaceHandshake, pnHS, len(hsPkt), true, hsFrames)
		hsOffset += uint64(len(chunk))
		remaining = remaining[len(chunk):]
		chunkIdx++
	}

	if debugFlag.Load() {
		Dbg("[H3-DBG] sendFirstFlight: total %d datagrams, hsMessages=%d bytes across %d chunks",
			chunkIdx+1, len(hsMessages), chunkIdx)
	}
}

func (qc *QUICConn) retransmitFrames(space int, frames []byte) {
	qc.sendFrames(space, frames, true)
}

func (qc *QUICConn) recoverLostPackets(space int) {
	lost := qc.loss.detectLostPackets(space)
	if len(lost) == 0 {
		return
	}
	if space != quicSpaceAppData {
		for _, frames := range lost {
			qc.retransmitFrames(space, frames)
		}
		return
	}
	qc.writeMu.Lock()
	for _, frames := range lost {
		qc.queueStreamFrameLocked(frames)
	}
	if qc.streamWriters.Load() == 0 {
		qc.drainCoalescedLocked()
	}
	qc.writeMu.Unlock()
}

func (qc *QUICConn) close() {
	if !qc.closed.CompareAndSwap(false, true) {
		return
	}
	close(qc.done)
	if qc.server != nil {
		qc.server.quicTimers.remove(qc)
	}

	qc.streamsMu.Lock()
	streams := qc.streams
	qc.streams = nil
	qc.streamsMu.Unlock()
	for _, s := range streams {
		s.abortHandler(ErrClientGone)
		s.Close()
		qc.maybeFinishStream(s)
		qc.releaseStream(s)
	}
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

func writeQUICDatagram(pc net.PacketConn, data []byte, addr net.Addr) (int, error) {
	n, err := pc.WriteTo(data, addr)
	if n > 0 {
		Stats.BytesOut.Add(uint64(n))
	}
	return n, err
}
