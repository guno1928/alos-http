//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
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
	tlsConnPhase12CKE          = 5
	tlsConnPhaseApplication12  = 6

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
var errTLSPbufUnavailable = errors.New("tls provided buffer ring unavailable")

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
	tracked    bool
	closeDone  bool

	closeAfter    bool
	requestCount  uint32
	readN         int
	readArmed     bool
	readPollFirst bool
	writeN        int
	writeSent     int
	writeZeroCopy bool
	zcPending     int
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
	h2            tlsWorkerH2State
	bridge        *tlsWorkerSharedBridge

	tls12           bool
	tls12Suite      *tls12Suite
	tls12Curve      tls12Curve
	tls12Priv       *ecdh.PrivateKey
	tls12Read       *tls12AEAD
	tls12Write      *tls12AEAD
	tls12Transcript hash.Hash
	clientRandom    [32]byte
	serverRandom    [32]byte
	masterSecret    [48]byte
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
	completions        [ioUringCompletionBatchSize]ioUringCqe
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
	activeBridgeCount  int
	pendingMissed      atomic.Int64
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
	if recvMultishotSupported {
		tlsRecvPath := probeIOUringTLSRecvPathDetailed(workerCount)
		if !tlsRecvPath.ok {
			recvMultishotSupported = false
			if debugFlag.Load() {
				log.Printf("[INFO] io_uring TLS provided buffer rings unavailable during live-size startup probe, starting in classic recv mode: %v", tlsRecvPath.err)
			}
		}
	}
	if !recvMultishotSupported {
		if debugFlag.Load() {
			log.Printf("[INFO] io_uring multishot recv unavailable during startup probe, starting in classic recv mode")
		}
	}
	if recvMultishotSupported {
		if debugFlag.Load() {
			log.Printf("[INFO] io_uring TLS worker handoff paths require single-owner recv state, starting in classic recv mode")
		}
		recvMultishotSupported = false
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
			return nil, fmt.Errorf("tls listener fd %d: %w", i, err)
		}
		listenerFDs[i] = fd
	}
	for workerID := 0; workerID < workerCount; workerID++ {
		ring, err := newIOUring(tlsWorkerRingEntries)
		if err != nil {
			return nil, fmt.Errorf("tls worker %d ring create: %w", workerID, err)
		}
		wakeupPair, err := openWakePipeALOS()
		if err != nil {
			ring.close()
			return nil, fmt.Errorf("tls worker %d wake pipe: %w", workerID, err)
		}
		worker := &tlsUringWorker{
			id:                 workerID,
			listenerFD:         -1,
			wakeupReadFD:       wakeupPair[0],
			wakeupWriteFD:      wakeupPair[1],
			handoffs:           make(chan tlsAcceptedConn, ioUringInitialConnsPerShard),
			ring:               ring,
			server:             s,
			connections:        make([]tlsWorkerConn, ioUringInitialConnsPerShard),
			freeHead:           0,
			bridgeRequests:     make(chan int32, ioUringInitialConnsPerShard*2),
			useMultishotAccept: true,
		}
		if recvMultishotSupported {
			recvBufs, err := newIOUringBufferRing(tlsRecvBufRingSize, tlsRecvBufSize, uint16(workerID+1))
			if err != nil {
				ring.close()
				_ = syscall.Close(wakeupPair[0])
				_ = syscall.Close(wakeupPair[1])
				return nil, fmt.Errorf("tls worker %d recv buf ring create: %w", workerID, err)
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
	pbufDisabled := false
	for _, worker := range backend.workers {
		if pbufDisabled && worker.recvBufs != nil {
			_ = worker.recvBufs.unregister(worker.ring)
			worker.recvBufs.close()
			worker.recvBufs = nil
		}
		if err := worker.prepare(); err != nil {
			if errors.Is(err, errTLSPbufUnavailable) {
				if !pbufDisabled {
					pbufDisabled = true
					if debugFlag.Load() {
						log.Printf("[INFO] io_uring TLS provided buffer rings unavailable during worker startup, disabling buffered recv for all TLS workers: %v", err)
					}
					backend.disableBufferedRecv()
				}
				continue
			}
			backend.errCh <- err
			return
		}
	}
	for _, worker := range backend.workers {
		worker := worker
		backend.wg.Add(1)
		go func() {
			defer backend.wg.Done()
			backoff := 50 * time.Millisecond
			firstAttempt := true
			for {
				start := time.Now()
				err := worker.run(backend)
				if err == nil || backend.server.doneClosed() {
					return
				}
				if firstAttempt && time.Since(start) < 2*time.Second {
					log.Printf("[ERROR] io_uring TLS worker %d failed to start: %v", worker.id, err)
					backend.errCh <- err
					return
				}
				firstAttempt = false
				if time.Since(start) > 5*time.Second {
					backoff = 50 * time.Millisecond
				}
				log.Printf("[WARN] io_uring TLS worker %d exited, restarting in %v: %v", worker.id, backoff, err)
				select {
				case <-backend.server.done:
					return
				case <-time.After(backoff):
				}
				if backoff < 2*time.Second {
					backoff *= 2
				}
			}
		}()
	}
}

func (backend *tlsUringBackend) disableBufferedRecv() {
	for _, worker := range backend.workers {
		if worker.recvBufs == nil {
			continue
		}
		_ = worker.recvBufs.unregister(worker.ring)
		worker.recvBufs.close()
		worker.recvBufs = nil
	}
}

func (worker *tlsUringWorker) prepare() error {
	if err := worker.ring.enable(); err != nil {
		return err
	}
	if worker.recvBufs != nil {
		if err := worker.recvBufs.register(worker.ring); err != nil {
			if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EEXIST) {
				worker.recvBufs.close()
				worker.recvBufs = nil
				return fmt.Errorf("%w on worker %d: %v", errTLSPbufUnavailable, worker.id, err)
			}
			return err
		}
	}
	return nil
}

func (backend *tlsUringBackend) stop() {
	for _, ln := range backend.server.listeners {
		_ = ln.Close()
	}
	for _, worker := range backend.workers {
		worker.signalWake()
	}
	backend.wg.Wait()
}

func (backend *tlsUringBackend) wait() error {
	select {
	case <-backend.server.done:
		backend.stop()
		return nil
	case err := <-backend.errCh:
		backend.stop()
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
			_ = worker.recvBufs.unregister(worker.ring)
			worker.recvBufs.close()
			worker.recvBufs = nil
		}
	}
}

func (worker *tlsUringWorker) initConnectionSlot(index int, nextFree int32) {
	conn := &worker.connections[index]
	conn.index = int32(index)
	conn.fd = -1
	conn.req.Headers = make([][2]string, 0, 16)
	conn.req.Body = make([]byte, 0, 1024)
	conn.req.Proto = "HTTP/1.1"
	conn.resp.Headers = make([][2]string, 0, 8)
	conn.resp.body = make([]byte, 0, 4096)
	conn.nextFree = nextFree
}

func (worker *tlsUringWorker) initConnections() {
	for index := range worker.connections {
		nextFree := int32(index + 1)
		if index == len(worker.connections)-1 {
			nextFree = -1
		}
		worker.initConnectionSlot(index, nextFree)
	}
}

func (worker *tlsUringWorker) growConnections() {
	oldLen := len(worker.connections)
	growBy := oldLen
	if growBy < ioUringInitialConnsPerShard {
		growBy = ioUringInitialConnsPerShard
	}
	if growBy == 0 {
		growBy = ioUringInitialConnsPerShard
	}
	prevHead := worker.freeHead
	worker.connections = append(worker.connections, make([]tlsWorkerConn, growBy)...)
	for index := oldLen; index < len(worker.connections); index++ {
		nextFree := int32(index + 1)
		if index == len(worker.connections)-1 {
			nextFree = prevHead
		}
		worker.initConnectionSlot(index, nextFree)
	}
	worker.freeHead = int32(oldLen)
}

func (worker *tlsUringWorker) run(backend *tlsUringBackend) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer worker.flushReqStats()
	if err := worker.fillAccepts(MonotonicNanotime()); err != nil {
		return fmt.Errorf("tls worker %d initial fillAccepts: %w", worker.id, err)
	}
	if err := worker.armWake(); err != nil {
		return fmt.Errorf("tls worker %d initial armWake: %w", worker.id, err)
	}
	if _, err := worker.ring.submitAndWait(0); err != nil {
		return fmt.Errorf("tls worker %d initial submit: %w", worker.id, err)
	}
	lastSweep := MonotonicNanotime()
	for {
		if worker.server.doneClosed() {
			worker.listenerFD = -1
			worker.closeAllConnections()
			if worker.active.Load() == 0 && len(worker.handoffs) == 0 {
				return nil
			}
		}
		now := MonotonicNanotime()
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
			lastSweep = MonotonicNanotime()
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
		nowTime := MonotonicNanotime()
		for i := 0; i < count; i++ {
			if err := worker.handleCompletionGuarded(backend, worker.completions[i], nowTime); err != nil {
				if errors.Is(err, errTLSWorkerPark) {
					if err := worker.parkUntilWork(); err != nil {
						return err
					}
					lastSweep = MonotonicNanotime()
					count = 0
					break
				}
				return err
			}
		}
		if count == 0 {
			continue
		}
		if nowTime-lastSweep >= int64(time.Second) {
			worker.sweepIdle(nowTime)
			lastSweep = nowTime
		}
		if err := worker.drainHandoffs(nowTime); err != nil {
			return err
		}
		if err := worker.drainBridgeRequests(); err != nil {
			return err
		}
		if err := worker.fillAccepts(nowTime); err != nil {
			return err
		}
		if worker.listenerFD < 0 && worker.active.Load() == 0 && len(worker.handoffs) == 0 {
			continue
		}
		if _, err := worker.ring.submitIfNeeded(); err != nil {
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

func (worker *tlsUringWorker) handleCompletionGuarded(backend *tlsUringBackend, cqe ioUringCqe, now int64) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TLS-PANIC] worker %d recovered in completion handler: %v", worker.id, r)
			if op := tlsDecodeOp(cqe.UserData); op != tlsUringOpAccept && op != tlsUringOpWake {
				connIndex := tlsDecodeConn(cqe.UserData)
				if connIndex >= 0 && connIndex < len(worker.connections) {
					_ = worker.closeConnection(&worker.connections[connIndex])
				}
			}
			err = nil
		}
	}()
	return worker.handleCompletion(backend, cqe, now)
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
				worker.recycleReadBuffer(cqe.Flags, cqe.Res)
			}
			return nil
		}
		conn := &worker.connections[connIndex]
		if (conn.fd < 0 && !(op == tlsUringOpWrite && cqe.Flags&ioUringCqeNotif != 0)) || conn.generation != generation {
			if op == tlsUringOpRead {
				worker.recycleReadBuffer(cqe.Flags, cqe.Res)
			}
			return nil
		}
		if conn.state == tlsConnStateClosing && op != tlsUringOpClose {
			if op == tlsUringOpWrite && cqe.Flags&ioUringCqeNotif != 0 {
				return worker.handleWriteNotification(conn)
			}
			if op == tlsUringOpRead {
				worker.recycleReadBuffer(cqe.Flags, cqe.Res)
			}
			return nil
		}
		switch op {
		case tlsUringOpRead:
			return worker.handleRead(conn, cqe.Res, cqe.Flags, now)
		case tlsUringOpWrite:
			if cqe.Flags&ioUringCqeNotif != 0 {
				return worker.handleWriteNotification(conn)
			}
			return worker.handleWrite(conn, cqe.Res, cqe.Flags, now)
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
			if debugFlag.Load() {
				log.Printf("[INFO] io_uring multishot accept unavailable on worker %d, falling back to one-shot accepts: %v", worker.id, syscall.Errno(-result))
			}
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
	prepareAcceptedFD(fd)
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
			if debugFlag.Load() {
				log.Printf("[INFO] io_uring multishot recv unavailable on worker %d, falling back to classic recv path: %v", worker.id, syscall.Errno(-result))
			}
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

func (worker *tlsUringWorker) handleWrite(conn *tlsWorkerConn, result int32, flags uint32, now int64) error {
	if conn.phase == tlsConnPhaseH2Bridge {
		return worker.handleBridgeWrite(conn, result, now)
	}
	if result < 0 {
		if worker.server.IsDebug() {
			Dbg("[%s] worker write completion result=%d phase=%d state=%d sent=%d/%d", conn.remoteAddr, result, conn.phase, conn.state, conn.writeSent, conn.writeN)
		}
		err := syscall.Errno(-result)
		if conn.writeZeroCopy && (errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP)) {
			worker.ring.markSendZCUnsupported()
			conn.writeZeroCopy = false
			remaining := conn.writeBuf[conn.writeSent:conn.writeN]
			return worker.queueWrite(conn, remaining, true)
		}
		if isIOUringTransient(err) {
			remaining := conn.writeBuf[conn.writeSent:conn.writeN]
			return worker.queueWrite(conn, remaining, true)
		}
		return worker.closeConnection(conn)
	}
	if conn.writeZeroCopy && flags&ioUringCqeMore != 0 {
		conn.zcPending++
		worker.ring.markSendZCSupported()
	}
	conn.lastActive = now
	conn.writeSent += int(result)
	if worker.server.IsDebug() {
		Dbg("[%s] worker wrote %d bytes phase=%d state=%d progress=%d/%d", conn.remoteAddr, result, conn.phase, conn.state, conn.writeSent, conn.writeN)
	}
	if conn.writeSent < conn.writeN {
		remaining := conn.writeBuf[conn.writeSent:conn.writeN]
		return worker.queueWrite(conn, remaining, true)
	}
	conn.writeSent = 0
	conn.writeN = 0
	conn.writeBuf = conn.writeBuf[:0]
	if conn.closeAfter && len(conn.plainBuf) == 0 {
		return worker.closeConnection(conn)
	}
	return worker.processTLSConn(conn)
}

func (worker *tlsUringWorker) handleWriteNotification(conn *tlsWorkerConn) error {
	if conn.zcPending > 0 {
		conn.zcPending--
	}
	if conn.zcPending == 0 {
		conn.writeZeroCopy = false
		if conn.closeDone {
			worker.releaseConnection(conn)
		}
	}
	return nil
}

func (worker *tlsUringWorker) handleBufferedRead(conn *tlsWorkerConn, result int32, flags uint32, now int64) error {
	conn.readArmed = flags&ioUringCqeMore != 0
	bufferID := cqeBufferID(flags)
	buf := worker.recvBufs.buffer(bufferID)
	defer worker.recycleReadBuffer(flags, result)
	if result < 0 {
		if worker.server.IsDebug() {
			Dbg("tls worker %d buffered read completion result=%d flags=0x%x", worker.id, result, flags)
		}
		if result == -int32(syscall.EINVAL) || result == -int32(syscall.ENOSYS) {
			if debugFlag.Load() {
				log.Printf("[INFO] io_uring multishot recv unavailable on worker %d, falling back to classic recv path: %v", worker.id, syscall.Errno(-result))
			}
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
	if worker.server.IsDebug() {
		Dbg("[%s] worker buffered read %d bytes flags=0x%x phase=%d state=%d more=%v", conn.remoteAddr, n, flags, conn.phase, conn.state, conn.readArmed)
	}
	if conn.phase == tlsConnPhaseH2Bridge {
		bridge := conn.bridge
		if bridge == nil {
			return worker.closeConnection(conn)
		}
		bridge.mu.Lock()
		worker.appendBufferedRead(&bridge.inbound, bufferID, n)
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
	worker.appendBufferedRead(&conn.readBuf, bufferID, n)
	conn.readN = len(conn.readBuf)
	if conn.state == tlsConnStateWriting {
		return nil
	}
	return worker.processTLSConn(conn)
}

func (worker *tlsUringWorker) appendBufferedRead(dst *[]byte, startID uint16, total int) {
	if worker.recvBufs == nil || total <= 0 {
		return
	}
	buf := worker.recvBufs.buffer(startID)
	if total > len(buf) {
		total = len(buf)
	}
	*dst = append(*dst, buf[:total]...)
}

func (worker *tlsUringWorker) recycleReadBuffer(flags uint32, result int32) {
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
		case tlsConnPhase12CKE:
			action, err = worker.processClient12KeyExchange(conn)
		case tlsConnPhaseApplication12:
			action, err = worker.processApplication12(conn)
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
	if worker.server.IsDebug() {
		Dbg("[%s] worker ClientHello parsed sni=%q alpn=%v tls13=%v", conn.remoteAddr, conn.clientHello.ServerName, conn.clientHello.ALPNProtos, conn.clientHello.SupportsTLS13())
	}
	selectedALPN := worker.server.negotiateALPN(conn.clientHello.ALPNProtos)
	certEntry := worker.server.certStore.Lookup(conn.clientHello.ServerName)
	if certEntry == nil {
		Dbg("[%s] worker no cert for SNI=%q loaded-certs=%d default=%q", conn.remoteAddr, conn.clientHello.ServerName, len(worker.server.certStore.ListCerts()), worker.server.config.DefaultDomain)
		return tlsWorkerActionClose, nil
	}
	if !conn.clientHello.SupportsTLS13() || certEntry.PrivKey == nil || conn.clientHello.X25519PubKey == nil {
		return worker.startTLS12(conn, certEntry, selectedALPN, payload, totalLen)
	}
	cs := NegotiateSuite(conn.clientHello.CipherSuites)
	if cs == nil {
		Dbg("[%s] worker no common cipher suite", conn.remoteAddr)
		return tlsWorkerActionClose, nil
	}
	if worker.server.IsDebug() {
		Dbg("[%s] worker negotiated ALPN=%q cipher=0x%04x", conn.remoteAddr, selectedALPN, cs.ID)
	}
	transcript := cs.HashFn()
	transcript.Write(payload)

	serverKey, err := worker.server.x25519Pool.Get()
	if err != nil {
		return tlsWorkerActionClose, err
	}
	defer serverKey.zero()

	shared, ok := deriveX25519SharedSecret(&serverKey.priv, &conn.clientHello.x25519PubKeyBuf)
	if !ok {
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
	cvScheme, sig, err := SignCertificateVerify(certEntry.PrivKey, transcript.Sum(cvHashBuf[:0]))
	if err != nil {
		Dbg("[%s] worker sign CertificateVerify: %v", conn.remoteAddr, err)
		return tlsWorkerActionClose, nil
	}

	inner := conn.plainBuf[:0]
	inner = append(inner, eeCert...)
	cvStart := len(inner)
	inner = appendCertificateVerify(inner, cvScheme, sig)
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
	conn.writeZeroCopy = false
	if err := worker.queueWrite(conn, conn.writeBuf[:conn.writeN], worker.shouldPollFirstSend()); err != nil {
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
		remainingRead := conn.readN - totalLen
		if worker.server.IsDebug() {
			Dbg("[%s] worker client Finished record ct=0x%02x payload=%d remaining-read=%d", conn.remoteAddr, ct, len(payload), remainingRead)
		}
		if ct == 0x14 {
			worker.compactCipherBuffer(conn, totalLen)
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
		worker.compactCipherBuffer(conn, totalLen)
		conn.hsReader = nil
		if conn.selectedALPN == "h2" {
			if worker.server.IsDebug() {
				Dbg("[%s] worker TLS handshake complete; entering HTTP/2", conn.remoteAddr)
			}
			return worker.handoffHTTP2(conn)
		}
		conn.phase = tlsConnPhaseApplication
		Stats.H1Conns.Add(1)
		if worker.server.IsDebug() {
			Dbg("[%s] worker TLS handshake complete; entering HTTP/1.1", conn.remoteAddr)
		}
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
		switch ct {
		case 0x14:
			worker.compactCipherBuffer(conn, totalLen)
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
				worker.compactCipherBuffer(conn, totalLen)
				if action, err := worker.processHTTPRequests(conn); action != tlsWorkerActionContinue || err != nil {
					return action, err
				}
			default:
				worker.compactCipherBuffer(conn, totalLen)
				continue
			}
		default:
			worker.compactCipherBuffer(conn, totalLen)
			continue
		}
	}
}

func (worker *tlsUringWorker) processHTTPRequests(conn *tlsWorkerConn) (int, error) {
	if len(conn.appBuf) == 0 {
		return tlsWorkerActionContinue, nil
	}
	if !conn.tls12 && worker.server.plainRootFast.enabled {
		if _, consumed, closeConn, ok := worker.server.matchPlainRootFastRequest(conn.appBuf); ok {
			if worker.server.tryAcquireRequestSlot() {
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
				worker.server.releaseRequestSlot()
				if conn.writeN == 0 {
					return tlsWorkerActionClose, nil
				}
				conn.state = tlsConnStateWriting
				conn.writeZeroCopy = false
				if err := worker.queueWrite(conn, conn.writeBuf[:conn.writeN], worker.shouldPollFirstSend()); err != nil {
					return tlsWorkerActionClose, nil
				}
				return tlsWorkerActionWrote, nil
			}
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
		if bodyEnd < headerEnd {
			conn.resp.Reset()
			conn.resp.Status(400).String("Bad Request")
			return worker.queueTLSResponse(conn, false, consumed)
		}
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
	conn.req.attachConn = worker.newH1RequestConnAttacher(conn, consumed)
	conn.req.connTakenOver = false
	conn.req.server = worker.server
	conn.req.Host = conn.req.cachedHost
	conn.req.RemoteAddr = conn.remoteAddr
	conn.req.tlsReader = nil
	conn.req.tlsWriter = nil
	conn.req.hdrBuf = nil
	conn.req.hijackReadBuf = nil
	conn.resp.SetSW(nil)
	conn.resp.lazyReq = &conn.req
	if worker.server.fastDispatch.Load() {
		handler := worker.server.Router.Lookup(conn.req.Method, conn.req.Path, &conn.req)
		handler(&conn.req, &conn.resp)
	} else {
		worker.server.dispatch(&conn.req, &conn.resp)
	}
	if conn.req.connTakenOver {
		if conn.req.hijacked {
			worker.releaseConnection(conn)
			return tlsWorkerActionHanded, nil
		}
		if conn.resp.IsStreamed() {
			releaseStreamWriter(conn.req.StreamWriter)
		}
		if conn.req.conn != nil {
			_ = conn.req.conn.Close()
		}
		worker.releaseConnection(conn)
		return tlsWorkerActionHanded, nil
	}
	if worker.server.config.MaxWriteSize > 0 && int64(conn.resp.transmittedBodyLen()) > worker.server.config.MaxWriteSize {
		conn.resp.resetFastH1()
		conn.resp.Status(500).String("Response Too Large")
		closeConn = true
	}
	return worker.queueTLSResponse(conn, !closeConn, consumed)
}

func (worker *tlsUringWorker) queueTLSResponse(conn *tlsWorkerConn, keepAlive bool, consumed int) (int, error) {
	conn.closeAfter = !keepAlive
	conn.plainBuf = appendPlainResponse(&conn.resp, conn.plainBuf[:0])
	if conn.tls12 {
		conn.writeBuf = buildTLS12AppDataRecords(conn.writeBuf[:0], conn.tls12Write, conn.plainBuf)
		conn.plainBuf = conn.plainBuf[:0]
	} else {
		conn.writeBuf = buildTLSAppDataRecords(conn.writeBuf[:0], conn.appWriter, conn.plainBuf, &conn.innerScratch)
	}
	conn.writeN = len(conn.writeBuf)
	conn.writeSent = 0
	conn.writeZeroCopy = worker.shouldUseZeroCopySend(conn)
	worker.compactAppBuffer(conn, consumed)
	if conn.writeN == 0 {
		return tlsWorkerActionClose, nil
	}
	conn.state = tlsConnStateWriting
	if err := worker.queueWrite(conn, conn.writeBuf[:conn.writeN], worker.shouldPollFirstSend()); err != nil {
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

func (worker *tlsUringWorker) newH1RequestConnAttacher(conn *tlsWorkerConn, consumed int) func(*Request) net.Conn {
	reader := conn.appReader
	writer := conn.appWriter
	var once sync.Once
	return func(req *Request) net.Conn {
		once.Do(func() {
			if conn.fd < 0 {
				return
			}
			wrapped, err := newIOUringConn(conn.fd)
			if err != nil {
				return
			}
			conn.fd = -1
			req.tlsReader = reader
			req.tlsWriter = writer
			req.hdrBuf = make([]byte, 5)
			// Copy the buffered ciphertext/plaintext tails only here, on the
			// rare hijack/streaming path. once.Do runs synchronously inside the
			// handler (before buffer compaction), so conn.readBuf/appBuf are
			// still valid — avoiding two per-request copies on the common path
			// where the connection is never hijacked.
			req.hijackReadBuf = append([]byte(nil), conn.appBuf[consumed:]...)
			handed := net.Conn(wrapped)
			if rawPrefix := conn.readBuf[:conn.readN]; len(rawPrefix) > 0 {
				handed = &prefixConn{Conn: wrapped, reader: io.MultiReader(bytes.NewReader(append([]byte(nil), rawPrefix...)), wrapped)}
			}
			handed = worker.server.trackHandoffConn(handed)
			if handed == nil {
				return
			}
			req.connTakenOver = true
			req.attachConn = nil
			req.conn = handed
		})
		return req.conn
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
			if worker.activeBridgeCount == 0 || worker.pendingMissed.Load() == 0 {
				return nil
			}
			worker.pendingMissed.Store(0)
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
	conn.writeZeroCopy = false
	return worker.queueWrite(conn, conn.writeBuf[:conn.writeN], worker.shouldPollFirstSend())
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
	conn.writeZeroCopy = false
	conn.zcPending = 0
	conn.requestCount = 0
	conn.closeAfter = false
	conn.closeDone = false
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
	if !worker.server.tryTrackConn() {
		_ = syscall.Close(fd)
		conn.fd = -1
		worker.recycleConnection(conn)
		return false, nil
	}
	conn.tracked = true
	worker.active.Add(1)
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
	if conn.fd < 0 || conn.state == tlsConnStateClosing {
		return nil
	}
	conn.state = tlsConnStateReading
	if conn.readArmed {
		return nil
	}
	if worker.recvBufs != nil {
		conn.readArmed = true
		if err := worker.ring.prepRecvMultishotUser(conn.fd, worker.recvBufs.bgid, tlsEncodeUserData(tlsUringOpRead, int(conn.index), conn.generation), conn.readPollFirst, false); err != nil {
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
	if conn.fd < 0 || conn.state == tlsConnStateClosing {
		return nil
	}
	conn.state = tlsConnStateClosing
	conn.closeDone = false
	conn.readArmed = false
	_ = worker.ring.cancelFD(conn.fd, 0)
	if err := worker.ring.prepCloseUser(conn.fd, tlsEncodeUserData(tlsUringOpClose, int(conn.index), conn.generation)); err != nil {
		_ = syscall.Close(conn.fd)
		worker.finishClose(conn)
	}
	return nil
}

func (worker *tlsUringWorker) finishClose(conn *tlsWorkerConn) {
	conn.fd = -1
	conn.closeDone = true
	if conn.zcPending > 0 {
		return
	}
	worker.releaseConnection(conn)
}

func (worker *tlsUringWorker) releaseConnection(conn *tlsWorkerConn) {
	if conn.tracked {
		worker.active.Add(-1)
		worker.server.releaseTrackedConn()
		Stats.ActiveConns.Add(-1)
		conn.tracked = false
	}
	worker.recycleConnection(conn)
}

func (worker *tlsUringWorker) recycleConnection(conn *tlsWorkerConn) {
	conn.state = tlsConnStateFree
	conn.phase = tlsConnPhaseClientHello
	conn.readN = 0
	conn.readArmed = false
	conn.readPollFirst = false
	conn.writeN = 0
	conn.writeSent = 0
	conn.nextFree = worker.freeHead
	worker.freeHead = conn.index
	conn.generation++
	if conn.generation == 0 {
		conn.generation = 1
	}
	conn.lastActive = 0
	conn.requestCount = 0
	conn.remoteAddr = ""
	conn.selectedALPN = ""
	conn.expectedFinN = 0
	conn.closeDone = false
	conn.tracked = false
	conn.writeZeroCopy = false
	conn.zcPending = 0
	conn.hsReader = nil
	conn.appReader = nil
	conn.appWriter = nil
	conn.tls12 = false
	conn.tls12Suite = nil
	conn.tls12Priv = nil
	conn.tls12Read = nil
	conn.tls12Write = nil
	conn.tls12Transcript = nil
	for i := range conn.masterSecret {
		conn.masterSecret[i] = 0
	}
	if conn.bridge != nil {
		conn.bridge.shutdown()
		conn.bridge = nil
		worker.activeBridgeCount--
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

func (worker *tlsUringWorker) shouldUseZeroCopySend(conn *tlsWorkerConn) bool {
	return conn.closeAfter && conn.writeN >= ioUringSendZCThreshold && worker.ring.canUseSendZC()
}

func (worker *tlsUringWorker) queueWrite(conn *tlsWorkerConn, buf []byte, pollFirst bool) error {
	userData := tlsEncodeUserData(tlsUringOpWrite, int(conn.index), conn.generation)
	if conn.writeZeroCopy {
		return worker.ring.prepSendZCUser(conn.fd, buf, userData, pollFirst)
	}
	return worker.ring.prepSendUserWithFlags(conn.fd, buf, userData, pollFirst)
}

func (worker *tlsUringWorker) acquireConnection() *tlsWorkerConn {
	if worker.freeHead < 0 {
		worker.growConnections()
		if worker.freeHead < 0 {
			return nil
		}
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
			switch conn.phase {
			case tlsConnPhaseClientHello, tlsConnPhaseClientFinished, tlsConnPhase12CKE:
				if handshakeTimeout > 0 {
					timeout = handshakeTimeout
				}
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
			if err != nil && debugFlag.Load() {
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
	return worker.ring.prepReadUser(worker.wakeupReadFD, worker.wakeupBuf[:], tlsEncodeUserData(tlsUringOpWake, 0, 0))
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
			if err := worker.handleCompletion(nil, cqe, MonotonicNanotime()); err != nil {
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
			now := MonotonicNanotime()
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
			return worker.queueWrite(conn, remaining, true)
		}
		return worker.closeConnection(conn)
	}
	conn.lastActive = now
	conn.writeSent += int(result)
	if conn.writeSent < conn.writeN {
		remaining := conn.writeBuf[conn.writeSent:conn.writeN]
		return worker.queueWrite(conn, remaining, true)
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

func (worker *tlsUringWorker) handoffHTTP2(conn *tlsWorkerConn) (int, error) {
	prefix := append([]byte(nil), conn.readBuf[:conn.readN]...)
	reader := conn.appReader
	writer := conn.appWriter

	sharedConn := newTLSWorkerSharedConn(worker, conn, prefix)
	conn.readN = 0
	conn.readBuf = conn.readBuf[:0]
	conn.phase = tlsConnPhaseH2Bridge
	Stats.H2Conns.Add(1)

	go func() {
		defer sharedConn.Close()
		worker.server.ServeH2(sharedConn, reader, writer, make([]byte, 5))
	}()

	return tlsWorkerActionNeedRead, nil
}

func pickTLS12Curve(groups []uint16) (tls12Curve, bool) {
	for _, g := range groups {
		if g == uint16(curveP256) {
			return curveP256, true
		}
	}
	for _, g := range groups {
		if g == uint16(curveX25519) {
			return curveX25519, true
		}
	}
	return 0, false
}

func (worker *tlsUringWorker) startTLS12(conn *tlsWorkerConn, certEntry *CertEntry, alpn string, chPayload []byte, totalLen int) (int, error) {
	if certEntry.PrivKey == nil {
		return tlsWorkerActionClose, nil
	}
	// The native TLS 1.2 path serves HTTP/1.1 only. Never negotiate h2 over 1.2.
	alpn = ""
	for _, p := range conn.clientHello.ALPNProtos {
		if p == "http/1.1" {
			alpn = "http/1.1"
			break
		}
	}
	kt := keyTypeECDSA
	if _, ok := certEntry.PrivKey.(*rsa.PrivateKey); ok {
		kt = keyTypeRSA
	}
	suite := negotiateTLS12Suite(conn.clientHello.CipherSuites, kt)
	if suite == nil {
		Dbg("[%s] tls1.2 no common suite", conn.remoteAddr)
		return tlsWorkerActionClose, nil
	}
	curve, ok := pickTLS12Curve(conn.clientHello.SupportedGroups)
	if !ok {
		Dbg("[%s] tls1.2 no common curve", conn.remoteAddr)
		return tlsWorkerActionClose, nil
	}
	priv, srvPub, err := tls12GenerateECDHE(curve)
	if err != nil {
		return tlsWorkerActionClose, nil
	}
	if _, err := rand.Read(conn.serverRandom[:]); err != nil {
		return tlsWorkerActionClose, err
	}
	copy(conn.clientRandom[:], conn.clientHello.Random[:])

	transcript := suite.newHash()
	transcript.Write(chPayload)

	sh := buildTLS12ServerHello(conn.serverRandom[:], suite.id, alpn)
	certMsg := buildTLS12Certificate(certEntry.ChainDER)
	ske, err := buildTLS12ServerKeyExchange(certEntry.PrivKey, conn.clientRandom[:], conn.serverRandom[:], curve, srvPub)
	if err != nil {
		Dbg("[%s] tls1.2 SKE sign: %v", conn.remoteAddr, err)
		return tlsWorkerActionClose, nil
	}
	shd := buildTLS12ServerHelloDone()
	transcript.Write(sh)
	transcript.Write(certMsg)
	transcript.Write(ske)
	transcript.Write(shd)

	flight := conn.writeBuf[:0]
	flight = AppendRecord(flight, 0x16, sh)
	flight = AppendRecord(flight, 0x16, certMsg)
	flight = AppendRecord(flight, 0x16, ske)
	flight = AppendRecord(flight, 0x16, shd)

	conn.tls12 = true
	conn.tls12Suite = suite
	conn.tls12Curve = curve
	conn.tls12Priv = priv
	conn.tls12Transcript = transcript
	conn.selectedALPN = alpn
	conn.phase = tlsConnPhase12CKE
	conn.writeBuf = flight
	conn.writeN = len(flight)
	conn.writeSent = 0
	conn.writeZeroCopy = false
	worker.compactCipherBuffer(conn, totalLen)
	if conn.writeN == 0 {
		return tlsWorkerActionClose, nil
	}
	conn.state = tlsConnStateWriting
	if err := worker.queueWrite(conn, conn.writeBuf[:conn.writeN], worker.shouldPollFirstSend()); err != nil {
		return tlsWorkerActionClose, nil
	}
	return tlsWorkerActionWrote, nil
}

func (worker *tlsUringWorker) processClient12KeyExchange(conn *tlsWorkerConn) (int, error) {
	buf := conn.readBuf[:conn.readN]
	ct1, cke, n1, ok, err := nextTLSRecord(buf)
	if err != nil {
		return tlsWorkerActionClose, nil
	}
	if !ok {
		return tlsWorkerActionNeedRead, nil
	}
	if ct1 != 0x16 {
		return tlsWorkerActionClose, nil
	}
	clientPub, ok := parseTLS12ClientKeyExchange(cke)
	if !ok {
		return tlsWorkerActionClose, nil
	}
	ct2, _, n2, ok, err := nextTLSRecord(buf[n1:])
	if err != nil {
		return tlsWorkerActionClose, nil
	}
	if !ok {
		return tlsWorkerActionNeedRead, nil
	}
	if ct2 != 0x14 {
		return tlsWorkerActionClose, nil
	}
	_, finRecord, n3, ok, err := nextTLSRecordRaw(buf[n1+n2:])
	if err != nil {
		return tlsWorkerActionClose, nil
	}
	if !ok {
		return tlsWorkerActionNeedRead, nil
	}

	suite := conn.tls12Suite
	pms, ok := tls12ECDHEShared(conn.tls12Curve, conn.tls12Priv, clientPub)
	if !ok {
		Dbg("[%s] tls1.2 bad client key share", conn.remoteAddr)
		return tlsWorkerActionClose, nil
	}
	conn.tls12Transcript.Write(cke)

	master := tls12MasterSecret(suite.newHash, pms, conn.clientRandom[:], conn.serverRandom[:])
	copy(conn.masterSecret[:], master)
	for i := range pms {
		pms[i] = 0
	}
	cwk, swk, civ, siv := tls12KeyBlock(suite.newHash, master, conn.clientRandom[:], conn.serverRandom[:], suite.keyLen, suite.ivLen)
	cAEAD, err := suite.aead(cwk)
	if err != nil {
		return tlsWorkerActionClose, nil
	}
	sAEAD, err := suite.aead(swk)
	if err != nil {
		return tlsWorkerActionClose, nil
	}
	conn.tls12Read = &tls12AEAD{aead: cAEAD, iv: civ, isChaCha: suite.isChaCha}
	conn.tls12Write = &tls12AEAD{aead: sAEAD, iv: siv, isChaCha: suite.isChaCha}

	typ, finPT, ok := conn.tls12Read.open(finRecord)
	if !ok || typ != 0x16 || len(finPT) < 4 || finPT[0] != 0x14 {
		Dbg("[%s] tls1.2 finished decrypt failed", conn.remoteAddr)
		return tlsWorkerActionClose, nil
	}
	clientVerify := finPT[4:]
	expect := tls12Finished(suite.newHash, master, "client finished", conn.tls12Transcript.Sum(nil))
	if subtle.ConstantTimeCompare(clientVerify, expect) != 1 {
		Dbg("[%s] tls1.2 client Finished mismatch", conn.remoteAddr)
		return tlsWorkerActionClose, nil
	}
	conn.tls12Transcript.Write(finPT)

	serverVerify := tls12Finished(suite.newHash, master, "server finished", conn.tls12Transcript.Sum(nil))
	serverFin := tls12Handshake(0x14, serverVerify)

	consumed := n1 + n2 + n3
	flight := conn.writeBuf[:0]
	flight = AppendRecord(flight, 0x14, []byte{0x01})
	flight = append(flight, conn.tls12Write.seal(0x16, serverFin)...)

	conn.phase = tlsConnPhaseApplication12
	conn.writeBuf = flight
	conn.writeN = len(flight)
	conn.writeSent = 0
	conn.writeZeroCopy = false
	worker.compactCipherBuffer(conn, consumed)
	if conn.writeN == 0 {
		return tlsWorkerActionClose, nil
	}
	conn.state = tlsConnStateWriting
	if err := worker.queueWrite(conn, conn.writeBuf[:conn.writeN], false); err != nil {
		return tlsWorkerActionClose, nil
	}
	return tlsWorkerActionWrote, nil
}

func (worker *tlsUringWorker) processApplication12(conn *tlsWorkerConn) (int, error) {
	for {
		if action, err := worker.processHTTPRequests(conn); action != tlsWorkerActionContinue || err != nil {
			return action, err
		}
		_, rec, totalLen, ok, err := nextTLSRecordRaw(conn.readBuf[:conn.readN])
		if err != nil {
			return tlsWorkerActionClose, nil
		}
		if !ok {
			return tlsWorkerActionNeedRead, nil
		}
		typ, pt, ok := conn.tls12Read.open(rec)
		if !ok {
			return tlsWorkerActionClose, nil
		}
		worker.compactCipherBuffer(conn, totalLen)
		switch typ {
		case 0x15:
			return tlsWorkerActionClose, nil
		case 0x17:
			maxRead := int(defaultInt64(worker.server.config.MaxReadSize, 2<<20))
			if !worker.ensureAppCapacity(conn, len(pt), maxRead) {
				return tlsWorkerActionClose, nil
			}
			conn.appBuf = append(conn.appBuf, pt...)
		default:
			continue
		}
	}
}

func nextTLSRecordRaw(buf []byte) (byte, []byte, int, bool, error) {
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
	return ct, buf[:totalLen], totalLen, true, nil
}

func buildTLS12AppDataRecords(dst []byte, w *tls12AEAD, payload []byte) []byte {
	if w == nil || len(payload) == 0 {
		return dst
	}
	const maxContent = MaxRecordPayload
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > maxContent {
			chunk = chunk[:maxContent]
		}
		payload = payload[len(chunk):]
		dst = append(dst, w.seal(0x17, chunk)...)
	}
	return dst
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
	workers := autoWorkerCount()
	if maxShards > 0 && workers > maxShards {
		workers = maxShards
	}
	return workers
}
