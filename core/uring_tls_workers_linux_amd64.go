//go:build linux && amd64

package core

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	tlsUringOpAccept = 1
	tlsUringOpRead   = 2
	tlsUringOpWrite  = 3
	tlsUringOpClose  = 4
	tlsUringOpWake   = 5

	tlsConnStateFree    = 0
	tlsConnStateReading = 1
	tlsConnStateWriting = 2
	tlsConnStateClosing = 3

	tlsConnPhaseClientHello    = 0
	tlsConnPhaseClientFinished = 1
	tlsConnPhaseApplication    = 2
	tlsConnPhaseH2Native       = 3
	tlsConnPhaseH2Bridge       = 4

	tlsWorkerActionContinue = 0
	tlsWorkerActionNeedRead = 1
	tlsWorkerActionWrote    = 2
	tlsWorkerActionHanded   = 3
	tlsWorkerActionClose    = 4

	tlsAcceptDepth       = 64
	tlsWorkerRingEntries = 8192
	tlsReadMinFree       = 4096
	tlsAppMinFree        = 4096
	tlsRecvBufRingSize   = 512
	tlsRecvBufSize       = 4096
)

var errTLSWorkerPark = errors.New("tls worker park")

type tlsAcceptedConn struct {
	fd         int
	acceptedAt int64
}

type tlsWorkerConn struct {
	index      int32
	nextFree   int32
	fd         int
	generation uint16
	state      uint8
	phase      uint8

	closeAfter    bool
	requestCount  uint32
	readN         int
	readArmed     bool
	readPollFirst bool
	writeN        int
	writeSent     int
	lastActive    int64
	remoteAddr    string
	selectedALPN  string
	readBuf       []byte
	appBuf        []byte
	plainBuf      []byte
	writeBuf      []byte
	innerScratch  []byte
	req           Request
	resp          Response
	clientHello   ParsedClientHello
	hsReader      *TrafficAEAD
	appReader     *TrafficAEAD
	appWriter     *TrafficAEAD
	expectedFin   [64]byte
	expectedFinN  int
	h2           tlsWorkerH2State
	bridge        *tlsWorkerSharedBridge
}

type tlsUringWorker struct {
	id                 int
	listenerFD         int
	wakeupReadFD       int
	wakeupWriteFD      int
	handoffs           chan tlsAcceptedConn
	ring               *ioUring
	server             *Server
	connections        []tlsWorkerConn
	freeHead           int32
	completions        [64]ioUringCqe
	timeoutCursor      int
	acceptBackfill     int64
	nextAcceptRetry    int64
	localReqs          uint64
	wakeupBuf          [8]byte
	wakeupIovec        syscall.Iovec
	wakeArmed          bool
	parking            bool
	active             atomic.Int64
	bridgeRequests     chan int32
	acceptArmed        bool
	recvBufs           *ioUringBufferRing
	useMultishotAccept bool
	acceptInflight     int
}

type tlsUringBackend struct {
	server   *Server
	workers  []*tlsUringWorker
	dispatch atomic.Uint32
	wg       sync.WaitGroup
	errCh    chan error
}

func (s *Server) tryServeWithIOUringTLSWorkers(listeners []net.Listener) (bool, error) {
	backend, err := newTLSUringBackend(s, listeners)
	if err != nil {
		return false, nil
	}
	defer backend.closeResources()
	log.Printf("[INFO] io_uring TLS worker mode active on Linux amd64: workers=%d accept-shards=%d conns-per-shard=%d", len(backend.workers), minInt(len(listeners), len(backend.workers)), ioUringConnsPerShard)
	backend.start()
	return true, backend.wait()
}

func newTLSUringBackend(s *Server, listeners []net.Listener) (*tlsUringBackend, error) {
	if len(listeners) == 0 {
		return nil, errors.New("no listeners")
	}
	s.ensureTLSRuntime()
	shards, _ := ioUringShardLayout()
	workerCount := tlsUringWorkerCount(s.config, shards)
	acceptShards := minInt(len(listeners), workerCount)
	recvMultishotSupported, err := probeIOUringRecvMultishot()
	if err != nil {
		return nil, err
	}
	if !recvMultishotSupported {
		log.Printf("[INFO] io_uring multishot recv unavailable during startup probe, starting in classic recv mode")
	}
	backend := &tlsUringBackend{
		server:  s,
		workers: make([]*tlsUringWorker, 0, workerCount),
		errCh:   make(chan error, workerCount),
	}
	listenerFDs := make([]int, len(listeners))
	for i, listener := range listeners {
		fd, err := listenerFD(listener)
		if err != nil {
			return nil, err
		}
		listenerFDs[i] = fd
	}
	for workerID := 0; workerID < workerCount; workerID++ {
		ring, err := newOwnedIOUring(tlsWorkerRingEntries)
		if err != nil {
			return nil, err
		}
		wakeupPair, err := openWakePipeALOS()
		if err != nil {
			ring.close()
			return nil, err
		}
		worker := &tlsUringWorker{
			id:                 workerID,
			listenerFD:         -1,
			wakeupReadFD:       wakeupPair[0],
			wakeupWriteFD:      wakeupPair[1],
			handoffs:           make(chan tlsAcceptedConn, ioUringConnsPerShard),
			ring:               ring,
			server:             s,
			connections:        make([]tlsWorkerConn, ioUringConnsPerShard),
			freeHead:           0,
			bridgeRequests:     make(chan int32, ioUringConnsPerShard*2),
			useMultishotAccept: true,
		}
		if recvMultishotSupported {
			recvBufs, err := newIOUringBufferRing(tlsRecvBufRingSize, tlsRecvBufSize, uint16(workerID+1))
			if err != nil {
				ring.close()
				_ = syscall.Close(wakeupPair[0])
				_ = syscall.Close(wakeupPair[1])
				return nil, err
			}
			worker.recvBufs = recvBufs
		}
		if workerID < acceptShards {
			worker.listenerFD = listenerFDs[workerID]
			worker.acceptBackfill = tlsAcceptDepth
		}
		worker.wakeupIovec.Base = &worker.wakeupBuf[0]
		worker.wakeupIovec.Len = uint64(len(worker.wakeupBuf))
		worker.initConnections()
		backend.workers = append(backend.workers, worker)
	}
	return backend, nil
}

func (backend *tlsUringBackend) start() {
	for _, worker := range backend.workers {
		worker := worker
		backend.wg.Add(1)
		go func() {
			defer backend.wg.Done()
			backend.errCh <- worker.run(backend)
		}()
	}
}

func (backend *tlsUringBackend) wait() error {
	select {
	case <-backend.server.done:
		for _, worker := range backend.workers {
			worker.signalWake()
		}
		backend.wg.Wait()
		return nil
	case err := <-backend.errCh:
		for _, ln := range backend.server.listeners {
			_ = ln.Close()
		}
		for _, worker := range backend.workers {
			worker.signalWake()
		}
		backend.wg.Wait()
		return err
	}
}

func (backend *tlsUringBackend) closeResources() {
	for _, worker := range backend.workers {
		if worker.ring != nil {
			worker.ring.close()
			worker.ring = nil
		}
		if worker.wakeupReadFD >= 0 {
			_ = syscall.Close(worker.wakeupReadFD)
			worker.wakeupReadFD = -1
		}
		if worker.wakeupWriteFD >= 0 {
			_ = syscall.Close(worker.wakeupWriteFD)
			worker.wakeupWriteFD = -1
		}
		if worker.recvBufs != nil {
			worker.recvBufs.close()
			worker.recvBufs = nil
		}
	}
}

func (worker *tlsUringWorker) initConnections() {
	for index := range worker.connections {
		conn := &worker.connections[index]
		conn.index = int32(index)
		conn.fd = -1
		conn.req.Headers = make([][2]string, 0, 16)
		conn.req.Body = make([]byte, 0, 1024)
		conn.req.Proto = "HTTP/1.1"
		conn.resp.Headers = make([][2]string, 0, 8)
		conn.resp.body = make([]byte, 0, 4096)
		if index == len(worker.connections)-1 {
			conn.nextFree = -1
		} else {
			conn.nextFree = int32(index + 1)
		}
	}
}

func (worker *tlsUringWorker) run(backend *tlsUringBackend) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer worker.flushReqStats()
	if err := worker.ring.enable(); err != nil {
		return err
	}
	if worker.recvBufs != nil {
		if err := worker.recvBufs.register(worker.ring); err != nil {
			if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSYS) {
				log.Printf("[INFO] io_uring provided buffer ring unavailable on worker %d, falling back to classic recv path: %v", worker.id, err)
				worker.recvBufs.close()
				worker.recvBufs = nil
			} else {
				return err
			}
		}
	}
	if err := worker.fillAccepts(time.Now().UnixNano()); err != nil {
		return err
	}
	if err := worker.armWake(); err != nil {
		return err
	}
	if _, err := worker.ring.submitAndWait(0); err != nil {
		return err
	}
	lastSweep := time.Now()
	for {
		if worker.server.doneClosed() {
			worker.listenerFD = -1
			worker.closeAllConnections()
			if worker.active.Load() == 0 && len(worker.handoffs) == 0 {
				return nil
			}
		}
		now := time.Now().UnixNano()
		if err := worker.drainHandoffs(now); err != nil {
			return err
		}
		if err := worker.drainBridgeRequests(); err != nil {
			return err
		}
		if err := worker.fillAccepts(now); err != nil {
			return err
		}
		if worker.listenerFD < 0 && worker.active.Load() == 0 && len(worker.handoffs) == 0 {
			if err := worker.parkUntilWork(); err != nil {
				return err
			}
			lastSweep = time.Now()
			continue
		}
		count := worker.ring.peekBatch(worker.completions[:])
		if count == 0 {
			cqe, err := worker.ring.waitCqe()
			if err != nil {
				if worker.server.doneClosed() && (errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINVAL)) {
					return nil
				}
				return err
			}
			worker.completions[0] = cqe
			count = 1
		}
		nowTime := time.Now()
		for i := 0; i < count; i++ {
			if err := worker.handleCompletion(backend, worker.completions[i], nowTime.UnixNano()); err != nil {
				if errors.Is(err, errTLSWorkerPark) {
					if err := worker.parkUntilWork(); err != nil {
						return err
					}
					lastSweep = time.Now()
					count = 0
					break
				}
				return err
			}
		}
		if count == 0 {
			continue
		}
		if nowTime.Sub(lastSweep) >= time.Second {
			worker.sweepIdle(nowTime.UnixNano())
			lastSweep = nowTime
		}
		if err := worker.drainHandoffs(nowTime.UnixNano()); err != nil {
			return err
		}
		if err := worker.drainBridgeRequests(); err != nil {
			return err
		}
		if err := worker.fillAccepts(nowTime.UnixNano()); err != nil {
			return err
		}
		if worker.listenerFD < 0 && worker.active.Load() == 0 && len(worker.handoffs) == 0 {
			continue
		}
		if _, err := worker.ring.submitAndWait(0); err != nil {
			if worker.server.doneClosed() && (errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINVAL)) {
				return nil
			}
			return err
		}
	}
}

func (worker *tlsUringWorker) closeAllConnections() {
	for i := range worker.connections {
		conn := &worker.connections[i]
		if conn.fd >= 0 && conn.state != tlsConnStateClosing {
			_ = worker.closeConnection(conn)
		}
	}
}

func (worker *tlsUringWorker) handleCompletion(backend *tlsUringBackend, cqe ioUringCqe, now int64) error {
	op := tlsDecodeOp(cqe.UserData)
	connIndex := tlsDecodeConn(cqe.UserData)
	generation := tlsDecodeGeneration(cqe.UserData)
	switch op {
	case tlsUringOpAccept:
		return worker.handleAccept(backend, cqe.Res, cqe.Flags, now)
	case tlsUringOpWake:
		return worker.handleWake(now, cqe.Res)
	case tlsUringOpRead, tlsUringOpWrite, tlsUringOpClose:
		if connIndex < 0 || connIndex >= len(worker.connections) {
			if op == tlsUringOpRead {
				worker.recycleReadBuffer(cqe.Flags)
			}
			return nil
		}
		conn := &worker.connections[connIndex]
		if conn.fd < 0 || conn.generation != generation {
			if op == tlsUringOpRead {
				worker.recycleReadBuffer(cqe.Flags)
			}
			return nil
		}
		switch op {
		case tlsUringOpRead:
			return worker.handleRead(conn, cqe.Res, cqe.Flags, now)
		case tlsUringOpWrite:
			return worker.handleWrite(conn, cqe.Res, now)
		case tlsUringOpClose:
			worker.finishClose(conn)
		}
	}
	return nil
}

func (worker *tlsUringWorker) handleWake(now int64, result int32) error {
	if result < 0 && worker.server.IsDebug() {
		Dbg("tls worker %d wake completion result=%d", worker.id, result)
	}
	if result >= 0 {
		if err := worker.drainHandoffs(now); err != nil {
			return err
		}
		if err := worker.drainBridgeRequests(); err != nil {
			return err
		}
	}
	if worker.server.doneClosed() {
		worker.wakeArmed = false
		return nil
	}
	if result < 0 {
		worker.wakeArmed = false
		return worker.armWake()
	}
	if worker.parking && worker.listenerFD < 0 && worker.active.Load() == 0 && len(worker.handoffs) == 0 {
		worker.parking = false
		worker.wakeArmed = false
		return errTLSWorkerPark
	}
	worker.parking = false
	return worker.queueWake()
}

func (worker *tlsUringWorker) handleAccept(backend *tlsUringBackend, result int32, flags uint32, now int64) error {
	if !worker.useMultishotAccept && worker.acceptInflight > 0 {
		worker.acceptInflight--
	}
	worker.acceptArmed = flags&ioUringCqeMore != 0
	if result < 0 {
		if worker.server.IsDebug() {
			Dbg("tls worker %d accept completion result=%d flags=0x%x multishot=%v", worker.id, result, flags, worker.useMultishotAccept)
		}
		if worker.server.doneClosed() || worker.listenerFD < 0 || result == -int32(syscall.EBADF) {
			return nil
		}
		if worker.useMultishotAccept && (result == -int32(syscall.EINVAL) || result == -int32(syscall.ENOSYS)) {
			worker.useMultishotAccept = false
			worker.acceptArmed = false
			atomic.StoreInt64(&worker.acceptBackfill, tlsAcceptDepth)
			log.Printf("[INFO] io_uring multishot accept unavailable on worker %d, falling back to one-shot accepts: %v", worker.id, syscall.Errno(-result))
			return nil
		}
		if result == -int32(syscall.EINVAL) {
			return fmt.Errorf("tls io_uring accept invalid argument (multishot=%v)", worker.useMultishotAccept)
		}
		if result == -int32(syscall.EAGAIN) || result == -int32(syscall.EINTR) || result == -int32(syscall.ECONNABORTED) {
			atomic.StoreInt64(&worker.nextAcceptRetry, now+int64(5*time.Millisecond))
			return nil
		}
		return fmt.Errorf("tls io_uring accept failed: %w", syscall.Errno(-result))
	}
	atomic.StoreInt64(&worker.nextAcceptRetry, 0)
	fd := int(result)
	if worker.server.IsDebug() {
		Dbg("tls worker %d accepted fd=%d multishot=%v", worker.id, fd, worker.useMultishotAccept)
	}
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	backend.dispatchAccepted(worker, fd, now)
	return nil
}

func (worker *tlsUringWorker) handleRead(conn *tlsWorkerConn, result int32, flags uint32, now int64) error {
	if worker.recvBufs != nil && flags&ioUringCqeBuffer != 0 {
		return worker.handleBufferedRead(conn, result, flags, now)
	}
	conn.readArmed = false
	if conn.phase == tlsConnPhaseH2Bridge {
		return worker.handleBridgeRead(conn, result, now)
	}
	if result < 0 {
		if worker.server.IsDebug() {
			Dbg("[%s] worker read completion result=%d flags=0x%x", conn.remoteAddr, result, flags)
		}
		if worker.recvBufs != nil && (result == -int32(syscall.EINVAL) || result == -int32(syscall.ENOSYS)) {
			log.Printf("[INFO] io_uring multishot recv unavailable on worker %d, falling back to classic recv path: %v", worker.id, syscall.Errno(-result))
			worker.recvBufs.close()
			worker.recvBufs = nil
			conn.readArmed = false
			return worker.queueRead(conn)
		}
		err := syscall.Errno(-result)
		if isIOUringTransient(err) {
			return worker.queueRead(conn)
		}
		return worker.closeConnection(conn)
	}
	if result == 0 {
		if worker.server.IsDebug() {
			Dbg("[%s] worker read completion EOF", conn.remoteAddr)
		}
		return worker.closeConnection(conn)
	}
	conn.lastActive = now
	conn.readPollFirst = flags&ioUringCqeSockNonEmpty == 0
	conn.readN += int(result)
	if worker.server.IsDebug() {
		Dbg("[%s] worker read %d bytes flags=0x%x phase=%d state=%d", conn.remoteAddr, result, flags, conn.phase, conn.state)
	}
	if len(conn.readBuf) < conn.readN {
		conn.readBuf = conn.readBuf[:conn.readN]
	}
	if conn.state == tlsConnStateWriting {
		return nil
	}
	return worker.processTLSConn(conn)
}

func (worker *tlsUringWorker) handleWrite(conn *tlsWorkerConn, result int32, now int64) error {
	if conn.phase == tlsConnPhaseH2Bridge {
		return worker.handleBridgeWrite(conn, result, now)
	}
	if result < 0 {
		err := syscall.Errno(-result)
		if isIOUringTransient(err) {
			remaining := conn.writeBuf[conn.writeSent:conn.writeN]
			return worker.ring.prepSendUserWithFlags(conn.fd, remaining, tlsEncodeUserData(tlsUringOpWrite, int(conn.index), conn.generation), true)
		}
		return worker.closeConnection(conn)
	}
	conn.lastActive = now
	conn.writeSent += int(result)
	if conn.writeSent < conn.writeN {
		remaining := conn.writeBuf[conn.writeSent:conn.writeN]
		return worker.ring.prepSendUserWithFlags(conn.fd, remaining, tlsEncodeUserData(tlsUringOpWrite, int(conn.index), conn.generation), true)
	}
	conn.writeSent = 0
	conn.writeN = 0
	conn.writeBuf = conn.writeBuf[:0]
	if conn.closeAfter {
		return worker.closeConnection(conn)
	}
	return worker.processTLSConn(conn)
}

func (worker *tlsUringWorker) handleBufferedRead(conn *tlsWorkerConn, result int32, flags uint32, now int64) error {
	conn.readArmed = flags&ioUringCqeMore != 0
	bufferID := cqeBufferID(flags)
	buf := worker.recvBufs.buffer(bufferID)
	defer worker.recvBufs.recycle(bufferID)
	if result < 0 {
		if worker.server.IsDebug() {
			Dbg("tls worker %d buffered read completion result=%d flags=0x%x", worker.id, result, flags)
		}
		if result == -int32(syscall.EINVAL) || result == -int32(syscall.ENOSYS) {
			log.Printf("[INFO] io_uring multishot recv unavailable on worker %d, falling back to classic recv path: %v", worker.id, syscall.Errno(-result))
			if worker.recvBufs != nil {
				worker.recvBufs.close()
				worker.recvBufs = nil
			}
			conn.readArmed = false
			return worker.queueRead(conn)
		}
		err := syscall.Errno(-result)
		if isIOUringTransient(err) && !conn.readArmed {
			return worker.queueRead(conn)
		}
		return worker.closeConnection(conn)
	}
	if result == 0 {
		return worker.closeConnection(conn)
	}
	conn.lastActive = now
	conn.readPollFirst = flags&ioUringCqeSockNonEmpty == 0
	n := int(result)
	if n > len(buf) {
		n = len(buf)
	}
	if conn.phase == tlsConnPhaseH2Bridge {
		bridge := conn.bridge
		if bridge == nil {
			return worker.closeConnection(conn)
		}
		bridge.mu.Lock()
		bridge.inbound = append(bridge.inbound, buf[:n]...)
		bridge.mu.Unlock()
		bridge.signalReadReady()
		if !conn.readArmed {
			return worker.queueRead(conn)
		}
		return nil
	}
	maxRead := int(defaultInt64(worker.server.config.MaxReadSize, 2<<20))
	if !worker.ensureReadCapacity(conn, n, maxRead) {
		return worker.closeConnection(conn)
	}
	if len(conn.readBuf) < conn.readN {
		conn.readBuf = conn.readBuf[:conn.readN]
	}
	conn.readBuf = append(conn.readBuf, buf[:n]...)
	conn.readN = len(conn.readBuf)
	if conn.state == tlsConnStateWriting {
		return nil
	}
	return worker.processTLSConn(conn)
}

func (worker *tlsUringWorker) recycleReadBuffer(flags uint32) {
	if worker.recvBufs == nil || flags&ioUringCqeBuffer == 0 {
		return
	}
	worker.recvBufs.recycle(cqeBufferID(flags))
}

func (worker *tlsUringWorker) processTLSConn(conn *tlsWorkerConn) error {
	for {
		var action int
		var err error
		switch conn.phase {
		case tlsConnPhaseClientHello:
			action, err = worker.processClientHello(conn)
		case tlsConnPhaseClientFinished:
			action, err = worker.processClientFinished(conn)
		case tlsConnPhaseH2Native:
			action, err = worker.processHTTP2(conn)
		case tlsConnPhaseH2Bridge:
			return nil
		default:
			action, err = worker.processApplication(conn)
		}
		if err != nil {
			return err
		}
		switch action {
		case tlsWorkerActionContinue:
			continue
		case tlsWorkerActionNeedRead:
			return worker.queueRead(conn)
		case tlsWorkerActionWrote, tlsWorkerActionHanded:
			return nil
		case tlsWorkerActionClose:
			return worker.closeConnection(conn)
		default:
			return nil
		}
	}
}

func (worker *tlsUringWorker) processClientHello(conn *tlsWorkerConn) (int, error) {
	ct, payload, totalLen, ok, err := nextTLSRecord(conn.readBuf[:conn.readN])
	if err != nil {
		Dbg("[%s] worker read ClientHello: %v", conn.remoteAddr, err)
		return tlsWorkerActionClose, nil
	}
	if !ok {
		return tlsWorkerActionNeedRead, nil
	}
	if ct != 0x16 {
		Dbg("[%s] worker expected handshake, got 0x%02x", conn.remoteAddr, ct)
		return tlsWorkerActionClose, nil
	}
	if err := ParseClientHello(payload, &conn.clientHello); err != nil {
		Dbg("[%s] worker parse ClientHello: %v", conn.remoteAddr, err)
		return tlsWorkerActionClose, nil
	}
	selectedALPN := NegotiateALPN(conn.clientHello.ALPNProtos)
	certEntry := worker.server.certStore.Lookup(conn.clientHello.ServerName)
	if certEntry == nil {
		Dbg("[%s] worker no cert for SNI=%q", conn.remoteAddr, conn.clientHello.ServerName)
		return tlsWorkerActionClose, nil
	}
	if !conn.clientHello.SupportsTLS13() || certEntry.PrivKey == nil || conn.clientHello.X25519PubKey == nil {
		Dbg("[%s] worker handing off TLS fallback", conn.remoteAddr)
		return worker.handoffTLSFallback(conn)
	}
	cs := NegotiateSuite(conn.clientHello.CipherSuites)
	if cs == nil {
		Dbg("[%s] worker no common cipher suite", conn.remoteAddr)
		return tlsWorkerActionClose, nil
	}
	transcript := cs.HashFn()
	transcript.Write(payload)

	serverKey, err := worker.server.x25519Pool.Get()
	if err != nil {
		return tlsWorkerActionClose, err
	}
	defer serverKey.zero()

	var shared [32]byte
	curve25519.ScalarMult(&shared, &serverKey.priv, &conn.clientHello.x25519PubKeyBuf)
	allZero := true
	for _, b := range shared {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		Dbg("[%s] worker bad X25519 key share", conn.remoteAddr)
		return tlsWorkerActionClose, nil
	}
	defer func() {
		for i := range shared {
			shared[i] = 0
		}
	}()

	var srvRandom [32]byte
	if _, err := rand.Read(srvRandom[:]); err != nil {
		Dbg("[%s] worker rand.Read server random: %v", conn.remoteAddr, err)
		return tlsWorkerActionClose, err
	}
	shMsg := BuildServerHello(srvRandom[:], conn.clientHello.SessionID, cs.ID, serverKey.pub[:])
	transcript.Write(shMsg)

	var handshakeSecretBuf [64]byte
	handshakeSecret := TLSExtractTo(cs.HashFn, cs.derivedFromEarly, shared[:], handshakeSecretBuf[:0])
	var hsHashBuf [64]byte
	hsHash := transcript.Sum(hsHashBuf[:0])
	var clientHSSecretBuf [64]byte
	clientHSSecret := cs.DeriveSecretTo(&cs.labelClientHSTraffic, handshakeSecret, hsHash, clientHSSecretBuf[:0])
	var serverHSSecretBuf [64]byte
	serverHSSecret := cs.DeriveSecretTo(&cs.labelServerHSTraffic, handshakeSecret, hsHash, serverHSSecretBuf[:0])

	serverHSWriter, err := NewTrafficAEAD(cs.HashFn, serverHSSecret, cs)
	if err != nil {
		Dbg("[%s] worker server HS AEAD: %v", conn.remoteAddr, err)
		return tlsWorkerActionClose, nil
	}
	clientHSReader, err := NewTrafficAEAD(cs.HashFn, clientHSSecret, cs)
	if err != nil {
		Dbg("[%s] worker client HS AEAD: %v", conn.remoteAddr, err)
		return tlsWorkerActionClose, nil
	}

	eeCert := certEntry.CachedEECert(selectedALPN)
	transcript.Write(eeCert)
	var cvHashBuf [64]byte
	sig, err := SignCertificateVerify(certEntry.PrivKey, transcript.Sum(cvHashBuf[:0]))
	if err != nil {
		Dbg("[%s] worker sign CertificateVerify: %v", conn.remoteAddr, err)
		return tlsWorkerActionClose, nil
	}

	inner := conn.plainBuf[:0]
	inner = append(inner, eeCert...)
	cvStart := len(inner)
	inner = appendCertificateVerify(inner, sig)
	cv := inner[cvStart:]
	transcript.Write(cv)
	var finHashBuf [64]byte
	var srvVerifyBuf [64]byte
	srvVerifyData := cs.ComputeFinishedTo(serverHSSecret, transcript.Sum(finHashBuf[:0]), srvVerifyBuf[:0])
	finStart := len(inner)
	inner = appendFinished(inner, srvVerifyData)
	fin := inner[finStart:]
	transcript.Write(fin)
	inner = append(inner, 0x16)
	conn.plainBuf = inner

	flight := conn.writeBuf[:0]
	flight = AppendRecord(flight, 0x16, shMsg)
	flight = AppendRecord(flight, 0x14, []byte{0x01})
	flight = appendTLSInnerRecord(flight, serverHSWriter, inner)

	var derivedFromHSBuf [64]byte
	derivedFromHS := cs.DeriveSecretTo(&cs.labelDerived, handshakeSecret, cs.emptyTranscriptHash, derivedFromHSBuf[:0])
	var masterSecretBuf [64]byte
	masterSecret := TLSExtractTo(cs.HashFn, derivedFromHS, cs.zeroHashInput, masterSecretBuf[:0])
	var appHashBuf [64]byte
	appHash := transcript.Sum(appHashBuf[:0])
	var clientAppSecretBuf [64]byte
	clientAppSecret := cs.DeriveSecretTo(&cs.labelClientAppTraffic, masterSecret, appHash, clientAppSecretBuf[:0])
	var serverAppSecretBuf [64]byte
	serverAppSecret := cs.DeriveSecretTo(&cs.labelServerAppTraffic, masterSecret, appHash, serverAppSecretBuf[:0])
	clientAppReader, err := NewTrafficAEAD(cs.HashFn, clientAppSecret, cs)
	if err != nil {
		Dbg("[%s] worker client app AEAD: %v", conn.remoteAddr, err)
		return tlsWorkerActionClose, nil
	}
	serverAppWriter, err := NewTrafficAEAD(cs.HashFn, serverAppSecret, cs)
	if err != nil {
		Dbg("[%s] worker server app AEAD: %v", conn.remoteAddr, err)
		return tlsWorkerActionClose, nil
	}
	if selectedALPN == "h2" {
		conn.plainBuf = appendH2ServerSettingsFlight(conn.plainBuf[:0])
		flight = buildTLSAppDataRecords(flight, serverAppWriter, conn.plainBuf, &conn.innerScratch)
		conn.plainBuf = conn.plainBuf[:0]
	}
	conn.writeBuf = flight
	conn.writeN = len(flight)
	conn.writeSent = 0
	if conn.writeN == 0 {
		return tlsWorkerActionClose, nil
	}
	verify := cs.ComputeFinishedTo(clientHSSecret, appHash, conn.expectedFin[:0])
	conn.expectedFinN = len(verify)
	conn.hsReader = clientHSReader
	conn.appReader = clientAppReader
	conn.appWriter = serverAppWriter
	conn.selectedALPN = selectedALPN
	conn.phase = tlsConnPhaseClientFinished
	worker.compactCipherBuffer(conn, totalLen)
	conn.state = tlsConnStateWriting
	if err := worker.ring.prepSendUserWithFlags(conn.fd, conn.writeBuf[:conn.writeN], tlsEncodeUserData(tlsUringOpWrite, int(conn.index), conn.generation), worker.shouldPollFirstSend()); err != nil {
		return tlsWorkerActionClose, nil
	}
	return tlsWorkerActionWrote, nil
}

func (worker *tlsUringWorker) processClientFinished(conn *tlsWorkerConn) (int, error) {
	for {
		ct, payload, totalLen, ok, err := nextTLSRecord(conn.readBuf[:conn.readN])
		if err != nil {
			Dbg("[%s] worker read client Finished: %v", conn.remoteAddr, err)
			return tlsWorkerActionClose, nil
		}
		if !ok {
			return tlsWorkerActionNeedRead, nil
		}
		worker.compactCipherBuffer(conn, totalLen)
		if ct == 0x14 {
			continue
		}
		if ct == 0x15 || ct != 0x17 {
			Dbg("[%s] worker unexpected client Finished record type 0x%02x", conn.remoteAddr, ct)
			return tlsWorkerActionClose, nil
		}
		finPt, err := conn.hsReader.Decrypt(payload)
		if err != nil {
			Dbg("[%s] worker decrypt client Finished: %v", conn.remoteAddr, err)
			return tlsWorkerActionClose, nil
		}
		finContent, finCT, err := StripInnerPlaintext(finPt)
		if err != nil || finCT != 0x16 {
			Dbg("[%s] worker bad Finished inner type 0x%02x err=%v", conn.remoteAddr, finCT, err)
			return tlsWorkerActionClose, nil
		}
		if len(finContent) < 4 || finContent[0] != 0x14 {
			Dbg("[%s] worker not a Finished message", conn.remoteAddr)
			return tlsWorkerActionClose, nil
		}
		clientVerify := finContent[4:]
		if !hmac.Equal(clientVerify, conn.expectedFin[:conn.expectedFinN]) {
			Dbg("[%s] worker client Finished verification failed", conn.remoteAddr)
			return tlsWorkerActionClose, nil
		}
		conn.hsReader = nil
		if conn.selectedALPN == "h2" {
			return worker.initHTTP2(conn)
		}
		conn.phase = tlsConnPhaseApplication
		Stats.H1Conns.Add(1)
		return tlsWorkerActionContinue, nil
	}
}

func (worker *tlsUringWorker) processApplication(conn *tlsWorkerConn) (int, error) {
	for {
		if action, err := worker.processHTTPRequests(conn); action != tlsWorkerActionContinue || err != nil {
			return action, err
		}
		ct, payload, totalLen, ok, err := nextTLSRecord(conn.readBuf[:conn.readN])
		if err != nil {
			return tlsWorkerActionClose, nil
		}
		if !ok {
			return tlsWorkerActionNeedRead, nil
		}
		worker.compactCipherBuffer(conn, totalLen)
		switch ct {
		case 0x14:
			continue
		case 0x15:
			return tlsWorkerActionClose, nil
		case 0x17:
			pt, err := conn.appReader.Decrypt(payload)
			if err != nil {
				return tlsWorkerActionClose, nil
			}
			appContent, appCT, err := StripInnerPlaintext(pt)
			if err != nil {
				return tlsWorkerActionClose, nil
			}
			switch appCT {
			case 0x15:
				return tlsWorkerActionClose, nil
			case 0x17:
				maxRead := int(defaultInt64(worker.server.config.MaxReadSize, 2<<20))
				if !worker.ensureAppCapacity(conn, len(appContent), maxRead) {
					return tlsWorkerActionClose, nil
				}
				conn.appBuf = append(conn.appBuf, appContent...)
				if action, err := worker.processHTTPRequests(conn); action != tlsWorkerActionContinue || err != nil {
					return action, err
				}
			default:
				continue
			}
		default:
			continue
		}
	}
}

func (worker *tlsUringWorker) processHTTPRequests(conn *tlsWorkerConn) (int, error) {
	if len(conn.appBuf) == 0 {
		return tlsWorkerActionContinue, nil
	}
	if worker.server.plainRootFast.enabled {
		if _, consumed, closeConn, ok := worker.server.matchPlainRootFastRequest(conn.appBuf); ok {
			worker.bumpReqStats()
			conn.requestCount++
			payload := worker.server.plainRootFast.getKeepAliveTLS
			if closeConn {
				payload = worker.server.plainRootFast.getCloseTLS
			}
			conn.closeAfter = closeConn
			conn.writeBuf = appendTLSInnerRecord(conn.writeBuf[:0], conn.appWriter, payload)
			conn.writeN = len(conn.writeBuf)
			conn.writeSent = 0
			worker.compactAppBuffer(conn, consumed)
			if conn.writeN == 0 {
				return tlsWorkerActionClose, nil
			}
			conn.state = tlsConnStateWriting
			if err := worker.ring.prepSendUserWithFlags(conn.fd, conn.writeBuf[:conn.writeN], tlsEncodeUserData(tlsUringOpWrite, int(conn.index), conn.generation), worker.shouldPollFirstSend()); err != nil {
				return tlsWorkerActionClose, nil
			}
			return tlsWorkerActionWrote, nil
		}
	}

	conn.req.resetFastH1()
	headerEnd, contentLength, hasContentLength, closeConn, badTransferEncoding, ok := ParseH1RequestHead(conn.appBuf, &conn.req)
	if !ok {
		return tlsWorkerActionContinue, nil
	}
	consumed := headerEnd
	if badTransferEncoding {
		conn.resp.Reset()
		conn.resp.Status(400).String("Bad Request")
		return worker.queueTLSResponse(conn, false, consumed)
	}
	if hasContentLength {
		if contentLength < 0 {
			conn.resp.Reset()
			conn.resp.Status(400).String("Bad Request")
			return worker.queueTLSResponse(conn, false, consumed)
		}
		if worker.server.config.MaxBodySize > 0 && int64(contentLength) > worker.server.config.MaxBodySize {
			conn.resp.Reset()
			conn.resp.Status(413).String("Payload Too Large")
			return worker.queueTLSResponse(conn, false, consumed)
		}
		bodyEnd := headerEnd + contentLength
		if bodyEnd > len(conn.appBuf) {
			return tlsWorkerActionContinue, nil
		}
		conn.req.Body = conn.appBuf[headerEnd:bodyEnd]
		consumed = bodyEnd
	} else {
		conn.req.Body = conn.req.Body[:0]
	}

	conn.requestCount++
	worker.bumpReqStats()
	conn.resp.resetFastH1()
	conn.req.StreamWriter = nil
	conn.req.conn = nil
	conn.req.server = worker.server
	conn.req.Host = conn.req.cachedHost
	conn.req.RemoteAddr = conn.remoteAddr
	conn.req.tlsReader = nil
	conn.req.tlsWriter = nil
	conn.req.hdrBuf = nil
	conn.resp.SetSW(nil)
	conn.resp.lazyReq = &conn.req
	if worker.server.fastDispatch.Load() {
		handler := worker.server.Router.Lookup(conn.req.Method, conn.req.Path, &conn.req)
		handler(&conn.req, &conn.resp)
	} else {
		worker.server.dispatch(&conn.req, &conn.resp)
	}
	if conn.req.hijacked || conn.resp.IsStreamed() {
		conn.resp.Reset()
		conn.resp.Status(500).String("Streaming/Hijack unsupported in TLS io_uring worker backend")
		closeConn = true
	}
	if worker.server.config.MaxWriteSize > 0 && int64(conn.resp.BodyLen()) > worker.server.config.MaxWriteSize {
		conn.resp.resetFastH1()
		conn.resp.Status(500).String("Response Too Large")
		closeConn = true
	}
	return worker.queueTLSResponse(conn, !closeConn, consumed)
}

func (worker *tlsUringWorker) queueTLSResponse(conn *tlsWorkerConn, keepAlive bool, consumed int) (int, error) {
	conn.closeAfter = !keepAlive
	conn.plainBuf = appendPlainResponse(&conn.resp, conn.plainBuf[:0])
	conn.writeBuf = buildTLSAppDataRecords(conn.writeBuf[:0], conn.appWriter, conn.plainBuf, &conn.innerScratch)
	conn.writeN = len(conn.writeBuf)
	conn.writeSent = 0
	worker.compactAppBuffer(conn, consumed)
	if conn.writeN == 0 {
		return tlsWorkerActionClose, nil
	}
	conn.state = tlsConnStateWriting
	if err := worker.ring.prepSendUserWithFlags(conn.fd, conn.writeBuf[:conn.writeN], tlsEncodeUserData(tlsUringOpWrite, int(conn.index), conn.generation), worker.shouldPollFirstSend()); err != nil {
		return tlsWorkerActionClose, nil
	}
	return tlsWorkerActionWrote, nil
}

func (worker *tlsUringWorker) bumpReqStats() {
	worker.localReqs++
	if worker.localReqs&63 == 0 {
		Stats.TotalReqs.Add(64)
		worker.localReqs = 0
	}
}

func (worker *tlsUringWorker) shouldPollFirstSend() bool {
	return Stats.ActiveConns.Load() >= 1024
}

func (worker *tlsUringWorker) acceptDepthTarget() int {
	return tlsAcceptDepth
}

func (worker *tlsUringWorker) flushReqStats() {
	if worker.localReqs > 0 {
		Stats.TotalReqs.Add(worker.localReqs)
		worker.localReqs = 0
	}
}

func (worker *tlsUringWorker) fillAccepts(now int64) error {
	if worker.server.doneClosed() || worker.listenerFD < 0 {
		return nil
	}
	retryAt := atomic.LoadInt64(&worker.nextAcceptRetry)
	if retryAt != 0 && now < retryAt {
		return nil
	}
	if worker.useMultishotAccept {
		if worker.acceptArmed {
			return nil
		}
		if err := worker.ring.prepAcceptMultishotUser(worker.listenerFD, tlsEncodeUserData(tlsUringOpAccept, 0, 0), uint32(sockCloexec|sockNonblock)); err != nil {
			return err
		}
		worker.acceptArmed = true
		return nil
	}
	target := worker.acceptDepthTarget()
	for worker.acceptInflight < target {
		if err := worker.ring.prepAcceptUser(worker.listenerFD, tlsEncodeUserData(tlsUringOpAccept, 0, 0), uint32(sockCloexec|sockNonblock)); err != nil {
			return err
		}
		worker.acceptInflight++
	}
	return nil
}

func (worker *tlsUringWorker) drainHandoffs(now int64) error {
	for {
		select {
		case accepted := <-worker.handoffs:
			if accepted.acceptedAt == 0 {
				accepted.acceptedAt = now
			}
			if err := worker.attachAccepted(accepted.fd, accepted.acceptedAt); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

func (worker *tlsUringWorker) drainBridgeRequests() error {
	for {
		select {
		case index := <-worker.bridgeRequests:
			if index < 0 || int(index) >= len(worker.connections) {
				continue
			}
			conn := &worker.connections[index]
			if conn.fd < 0 || conn.bridge == nil {
				continue
			}
			if err := worker.processBridge(conn); err != nil {
				return err
			}
		default:
			for i := range worker.connections {
				conn := &worker.connections[i]
				if conn.fd < 0 || conn.bridge == nil || !conn.bridge.notifyPending.Load() {
					continue
				}
				if err := worker.processBridge(conn); err != nil {
					return err
				}
			}
			return nil
		}
	}
}

func (worker *tlsUringWorker) processBridge(conn *tlsWorkerConn) error {
	bridge := conn.bridge
	if bridge == nil {
		return nil
	}
	bridge.notifyPending.Store(false)
	bridge.mu.Lock()
	if bridge.closeRequested {
		bridge.mu.Unlock()
		return worker.closeConnection(conn)
	}
	if bridge.writeActive != nil || len(bridge.writeQueue) == 0 {
		bridge.mu.Unlock()
		return nil
	}
	req := bridge.writeQueue[0]
	bridge.writeQueue = bridge.writeQueue[1:]
	bridge.writeActive = req
	data := req.data
	bridge.mu.Unlock()

	conn.writeBuf = data
	conn.writeN = len(conn.writeBuf)
	conn.writeSent = 0
	conn.state = tlsConnStateWriting
	return worker.ring.prepSendUserWithFlags(conn.fd, conn.writeBuf[:conn.writeN], tlsEncodeUserData(tlsUringOpWrite, int(conn.index), conn.generation), worker.shouldPollFirstSend())
}

func (worker *tlsUringWorker) attachAccepted(fd int, now int64) error {
	attached, err := worker.tryAttachAccepted(fd, now)
	if attached {
		return err
	}
	_ = syscall.Close(fd)
	return nil
}

func (worker *tlsUringWorker) tryAttachAccepted(fd int, now int64) (bool, error) {
	conn := worker.acquireConnection()
	if conn == nil {
		return false, nil
	}
	conn.fd = fd
	conn.state = tlsConnStateReading
	conn.phase = tlsConnPhaseClientHello
	conn.readN = 0
	conn.readArmed = false
	conn.readPollFirst = false
	conn.writeN = 0
	conn.writeSent = 0
	conn.requestCount = 0
	conn.closeAfter = false
	conn.lastActive = now
	conn.selectedALPN = ""
	conn.expectedFinN = 0
	conn.bridge = nil
	if conn.readBuf == nil {
		conn.readBuf = make([]byte, 0, 8192)
	}
	if conn.appBuf == nil {
		conn.appBuf = make([]byte, 0, 8192)
	}
	if conn.plainBuf == nil {
		conn.plainBuf = make([]byte, 0, 16384)
	}
	if conn.writeBuf == nil {
		conn.writeBuf = make([]byte, 0, 16384)
	}
	if conn.innerScratch == nil {
		conn.innerScratch = make([]byte, 0, MaxRecordPayload)
	}
	_, remote := socketAddrs(fd)
	if remote != nil {
		conn.remoteAddr = remote.String()
	}
	worker.active.Add(1)
	worker.server.activeConns.Add(1)
	Stats.ActiveConns.Add(1)
	Stats.TotalConns.Add(1)
	if err := worker.queueRead(conn); err != nil {
		if worker.server.IsDebug() {
			Dbg("[%s] worker initial queueRead failed: %v", conn.remoteAddr, err)
		}
		return true, err
	}
	return true, nil
}

func (worker *tlsUringWorker) queueRead(conn *tlsWorkerConn) error {
	conn.state = tlsConnStateReading
	if conn.readArmed {
		return nil
	}
	if worker.recvBufs != nil {
		conn.readArmed = true
		if err := worker.ring.prepRecvMultishotUser(conn.fd, worker.recvBufs.bgid, tlsEncodeUserData(tlsUringOpRead, int(conn.index), conn.generation), conn.readPollFirst); err != nil {
			conn.readArmed = false
			return err
		}
		return nil
	}
	if !worker.ensureReadCapacity(conn, tlsReadMinFree, int(defaultInt64(worker.server.config.MaxReadSize, 2<<20))) {
		return worker.closeConnection(conn)
	}
	return worker.ring.prepRecvUserWithFlags(conn.fd, conn.readBuf[conn.readN:cap(conn.readBuf)], tlsEncodeUserData(tlsUringOpRead, int(conn.index), conn.generation), conn.readPollFirst)
}

func (worker *tlsUringWorker) ensureReadCapacity(conn *tlsWorkerConn, minFree int, maxRead int) bool {
	if cap(conn.readBuf)-conn.readN >= minFree {
		return true
	}
	buf, ok := growPlainReadBuffer(conn.readBuf[:conn.readN], minFree, maxRead)
	if !ok {
		return false
	}
	conn.readBuf = buf[:len(buf)]
	return true
}

func (worker *tlsUringWorker) ensureAppCapacity(conn *tlsWorkerConn, addN int, maxRead int) bool {
	if addN <= 0 {
		return true
	}
	minFree := addN
	if minFree < tlsAppMinFree {
		minFree = tlsAppMinFree
	}
	if cap(conn.appBuf)-len(conn.appBuf) >= minFree {
		return true
	}
	buf, ok := growPlainReadBuffer(conn.appBuf, minFree, maxRead)
	if !ok {
		return false
	}
	conn.appBuf = buf[:len(buf)]
	return true
}

func (worker *tlsUringWorker) closeConnection(conn *tlsWorkerConn) error {
	if conn.fd < 0 {
		return nil
	}
	conn.state = tlsConnStateClosing
	conn.readArmed = false
	if err := worker.ring.prepCloseUser(conn.fd, tlsEncodeUserData(tlsUringOpClose, int(conn.index), conn.generation)); err != nil {
		_ = syscall.Close(conn.fd)
		worker.finishClose(conn)
	}
	return nil
}

func (worker *tlsUringWorker) finishClose(conn *tlsWorkerConn) {
	conn.fd = -1
	worker.releaseConnection(conn)
}

func (worker *tlsUringWorker) releaseConnection(conn *tlsWorkerConn) {
	conn.state = tlsConnStateFree
	conn.phase = tlsConnPhaseClientHello
	conn.readN = 0
	conn.readArmed = false
	conn.readPollFirst = false
	conn.writeN = 0
	conn.writeSent = 0
	conn.nextFree = worker.freeHead
	worker.freeHead = conn.index
	worker.active.Add(-1)
	worker.server.activeConns.Done()
	Stats.ActiveConns.Add(-1)
	conn.generation++
	if conn.generation == 0 {
		conn.generation = 1
	}
	conn.lastActive = 0
	conn.requestCount = 0
	conn.remoteAddr = ""
	conn.selectedALPN = ""
	conn.expectedFinN = 0
	conn.hsReader = nil
	conn.appReader = nil
	conn.appWriter = nil
	if conn.bridge != nil {
		conn.bridge.shutdown()
		conn.bridge = nil
	}
	conn.clientHello.Reset()
	conn.h2.reset()
	conn.req.Reset()
	conn.resp.Reset()
	conn.readBuf = conn.readBuf[:0]
	conn.appBuf = conn.appBuf[:0]
	conn.plainBuf = conn.plainBuf[:0]
	conn.writeBuf = conn.writeBuf[:0]
	conn.innerScratch = conn.innerScratch[:0]
}

func (worker *tlsUringWorker) acquireConnection() *tlsWorkerConn {
	if worker.freeHead < 0 {
		return nil
	}
	index := worker.freeHead
	conn := &worker.connections[index]
	worker.freeHead = conn.nextFree
	if conn.generation == 0 {
		conn.generation = 1
	}
	return conn
}

func (worker *tlsUringWorker) compactCipherBuffer(conn *tlsWorkerConn, consumed int) {
	if consumed <= 0 {
		return
	}
	remaining := conn.readN - consumed
	if remaining > 0 {
		copy(conn.readBuf[:remaining], conn.readBuf[consumed:conn.readN])
	}
	conn.readN = remaining
	conn.readBuf = conn.readBuf[:remaining]
}

func (worker *tlsUringWorker) compactAppBuffer(conn *tlsWorkerConn, consumed int) {
	if consumed <= 0 {
		return
	}
	remaining := len(conn.appBuf) - consumed
	if remaining > 0 {
		copy(conn.appBuf[:remaining], conn.appBuf[consumed:])
	}
	conn.appBuf = conn.appBuf[:remaining]
}

func (worker *tlsUringWorker) sweepIdle(now int64) {
	if len(worker.connections) == 0 {
		return
	}
	idleTimeout := worker.server.config.IdleTimeout
	handshakeTimeout := worker.server.config.HandshakeTimeout
	if idleTimeout <= 0 && handshakeTimeout <= 0 {
		return
	}
	for budget := 64; budget > 0; budget-- {
		conn := &worker.connections[worker.timeoutCursor]
		if conn.fd >= 0 && conn.state != tlsConnStateClosing {
			timeout := idleTimeout
			if conn.phase != tlsConnPhaseApplication && handshakeTimeout > 0 {
				timeout = handshakeTimeout
			}
			if timeout > 0 && now-conn.lastActive > timeout.Nanoseconds() {
				_ = worker.closeConnection(conn)
			}
		}
		worker.timeoutCursor++
		if worker.timeoutCursor >= len(worker.connections) {
			worker.timeoutCursor = 0
		}
	}
}

func (backend *tlsUringBackend) dispatchAccepted(source *tlsUringWorker, fd int, now int64) {
	if backend.server.doneClosed() {
		_ = syscall.Close(fd)
		return
	}
	workerCount := len(backend.workers)
	if workerCount == 0 {
		_ = syscall.Close(fd)
		return
	}
	if source.active.Load() < 96 {
		if attached, err := source.tryAttachAccepted(fd, now); attached {
			if err != nil {
				log.Printf("[INFO] io_uring source attach failed on worker %d: %v", source.id, err)
			}
			return
		}
	}
	start := int(backend.dispatch.Add(1)-1) % workerCount
	for offset := 0; offset < workerCount; offset++ {
		target := backend.workers[(start+offset)%workerCount]
		if target == source {
			continue
		}
		if target.enqueueAccepted(tlsAcceptedConn{fd: fd, acceptedAt: now}) {
			return
		}
	}
	_ = source.attachAccepted(fd, now)
}

func (worker *tlsUringWorker) enqueueAccepted(conn tlsAcceptedConn) bool {
	select {
	case worker.handoffs <- conn:
		worker.signalWake()
		return true
	default:
		return false
	}
}

func (worker *tlsUringWorker) armWake() error {
	if worker.wakeArmed {
		return nil
	}
	if err := worker.queueWake(); err != nil {
		return err
	}
	worker.wakeArmed = true
	return nil
}

func (worker *tlsUringWorker) queueWake() error {
	return worker.ring.prepReadvUser(worker.wakeupReadFD, &worker.wakeupIovec, tlsEncodeUserData(tlsUringOpWake, 0, 0))
}

func (worker *tlsUringWorker) signalWake() {
	if worker.wakeupWriteFD < 0 {
		return
	}
	_, err := syscall.Write(worker.wakeupWriteFD, []byte{1})
	if err != nil && !errors.Is(err, syscall.EAGAIN) {
		return
	}
}

func (worker *tlsUringWorker) parkUntilWork() error {
	if worker.server.doneClosed() {
		return nil
	}
	if worker.wakeArmed {
		worker.parking = true
		worker.signalWake()
		for {
			cqe, err := worker.ring.waitCqe()
			if err != nil {
				if worker.server.doneClosed() {
					return nil
				}
				return err
			}
			if err := worker.handleCompletion(nil, cqe, time.Now().UnixNano()); err != nil {
				if errors.Is(err, errTLSWorkerPark) {
					break
				}
				return err
			}
			if worker.listenerFD >= 0 || worker.active.Load() != 0 || len(worker.handoffs) != 0 {
				worker.parking = false
				return nil
			}
		}
	}
	var buffer [8]byte
	for {
		if worker.server.doneClosed() {
			return nil
		}
		_, err := syscall.Read(worker.wakeupReadFD, buffer[:])
		if err == nil {
			now := time.Now().UnixNano()
			if err := worker.drainHandoffs(now); err != nil {
				return err
			}
			if worker.server.doneClosed() {
				return nil
			}
			if worker.listenerFD >= 0 || worker.active.Load() != 0 || len(worker.handoffs) != 0 {
				if err := worker.armWake(); err != nil {
					return err
				}
				if _, err := worker.ring.submitAndWait(0); err != nil {
					return err
				}
				worker.parking = false
				return nil
			}
			continue
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if worker.server.doneClosed() && (errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINVAL)) {
			return nil
		}
		return err
	}
}

func (worker *tlsUringWorker) handleBridgeRead(conn *tlsWorkerConn, result int32, now int64) error {
	bridge := conn.bridge
	if bridge == nil {
		return worker.closeConnection(conn)
	}
	if result < 0 {
		err := syscall.Errno(-result)
		if isIOUringTransient(err) {
			return worker.queueRead(conn)
		}
		return worker.closeConnection(conn)
	}
	if result == 0 {
		return worker.closeConnection(conn)
	}
	conn.lastActive = now
	n := int(result)
	if len(conn.readBuf) < n {
		conn.readBuf = conn.readBuf[:n]
	}
	bridge.mu.Lock()
	bridge.inbound = append(bridge.inbound, conn.readBuf[:n]...)
	bridge.mu.Unlock()
	bridge.signalReadReady()
	conn.readN = 0
	conn.readBuf = conn.readBuf[:0]
	return worker.queueRead(conn)
}

func (worker *tlsUringWorker) handleBridgeWrite(conn *tlsWorkerConn, result int32, now int64) error {
	bridge := conn.bridge
	if bridge == nil {
		return worker.closeConnection(conn)
	}
	if result < 0 {
		err := syscall.Errno(-result)
		if isIOUringTransient(err) {
			remaining := conn.writeBuf[conn.writeSent:conn.writeN]
			return worker.ring.prepSendUserWithFlags(conn.fd, remaining, tlsEncodeUserData(tlsUringOpWrite, int(conn.index), conn.generation), true)
		}
		return worker.closeConnection(conn)
	}
	conn.lastActive = now
	conn.writeSent += int(result)
	if conn.writeSent < conn.writeN {
		remaining := conn.writeBuf[conn.writeSent:conn.writeN]
		return worker.ring.prepSendUserWithFlags(conn.fd, remaining, tlsEncodeUserData(tlsUringOpWrite, int(conn.index), conn.generation), true)
	}
	conn.writeSent = 0
	conn.writeN = 0
	conn.writeBuf = conn.writeBuf[:0]

	bridge.mu.Lock()
	active := bridge.writeActive
	bridge.writeActive = nil
	bridge.mu.Unlock()
	if active != nil && active.resp != nil {
		active.resp <- nil
	}
	releaseTLSBridgeWriteReq(active)
	return worker.processBridge(conn)
}

func (worker *tlsUringWorker) handoffTLSHTTP2(conn *tlsWorkerConn) (int, error) {
	prefix := append([]byte(nil), conn.readBuf[:conn.readN]...)
	shared := newTLSWorkerSharedConn(worker, conn, prefix)
	conn.phase = tlsConnPhaseH2Bridge
	conn.readN = 0
	conn.readBuf = conn.readBuf[:0]
	Stats.H2Conns.Add(1)
	if err := worker.queueRead(conn); err != nil {
		return tlsWorkerActionClose, err
	}
	go worker.server.serveH2SharedConn(shared, conn.appReader, conn.appWriter)
	return tlsWorkerActionHanded, nil
}

func (worker *tlsUringWorker) handoffTLSFallback(conn *tlsWorkerConn) (int, error) {
	prefix := append([]byte(nil), conn.readBuf[:conn.readN]...)
	addr := conn.remoteAddr
	fd := conn.fd
	wrapped, err := netConnFromFD(fd)
	if err != nil {
		conn.fd = -1
		worker.releaseConnection(conn)
		return tlsWorkerActionClose, nil
	}
	conn.fd = -1
	worker.releaseConnection(conn)
	worker.server.activeConns.Add(1)
	go worker.server.serveTLSFallbackWithPrefix(wrapped, prefix, addr)
	return tlsWorkerActionHanded, nil
}

func netConnFromFD(fd int) (net.Conn, error) {
	file := os.NewFile(uintptr(fd), "alos-tls-fallback")
	if file == nil {
		return nil, syscall.EBADF
	}
	conn, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		_ = conn.Close()
		return nil, closeErr
	}
	return conn, nil
}

func nextTLSRecord(buf []byte) (byte, []byte, int, bool, error) {
	if len(buf) < 5 {
		return 0, nil, 0, false, nil
	}
	ct := buf[0]
	length := int(buf[3])<<8 | int(buf[4])
	if length > MaxRecordSize {
		return 0, nil, 0, false, ErrRecordTooLarge
	}
	totalLen := 5 + length
	if len(buf) < totalLen {
		return 0, nil, 0, false, nil
	}
	return ct, buf[5:totalLen], totalLen, true, nil
}

func appendTLSInnerRecord(dst []byte, writer *TrafficAEAD, innerPayload []byte) []byte {
	ciphertextLen := len(innerPayload) + writer.Overhead()
	dst = append(dst, 0x17, 0x03, 0x03, byte(ciphertextLen>>8), byte(ciphertextLen))
	return writer.EncryptAppend(dst, innerPayload)
}

func buildTLSAppDataRecords(dst []byte, writer *TrafficAEAD, payload []byte, scratch *[]byte) []byte {
	if writer == nil {
		return dst
	}
	const maxContent = MaxRecordPayload - 1
	if len(payload) == 0 {
		return dst
	}
	if cap(*scratch) < MaxRecordPayload {
		*scratch = make([]byte, 0, MaxRecordPayload)
	}
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > maxContent {
			chunk = chunk[:maxContent]
		}
		payload = payload[len(chunk):]
		inner := (*scratch)[:len(chunk)+1]
		copy(inner, chunk)
		inner[len(chunk)] = 0x17
		dst = appendTLSInnerRecord(dst, writer, inner)
	}
	return dst
}

func tlsEncodeUserData(op uint8, connIndex int, generation uint16) uint64 {
	return uint64(op)<<56 | uint64(generation)<<32 | uint64(uint32(connIndex))
}

func tlsDecodeOp(userData uint64) uint8 {
	return uint8(userData >> 56)
}

func tlsDecodeGeneration(userData uint64) uint16 {
	return uint16((userData >> 32) & 0xffff)
}

func tlsDecodeConn(userData uint64) int {
	return int(uint32(userData))
}

func tlsUringWorkerCount(cfg Config, maxShards int) int {
	if cfg.WorkerCount > 0 {
		if maxShards > 0 && cfg.WorkerCount > maxShards {
			return maxShards
		}
		return cfg.WorkerCount
	}
	workers := runtime.GOMAXPROCS(0) * 2
	if workers < 1 {
		workers = 1
	}
	if maxShards > 0 && workers > maxShards {
		workers = maxShards
	}
	return workers
}
