//go:build linux && amd64

package core

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	plainUringOpAccept = 1
	plainUringOpRead   = 2
	plainUringOpWrite  = 3
	plainUringOpClose  = 4
	plainUringOpWake   = 5

	plainConnStateFree        = 0
	plainConnStateReading     = 1
	plainConnStateWriting     = 2
	plainConnStateClosing     = 3
	plainConnStateForwarding  = 4
	plainConnStateDispatching = 5

	plainAcceptRetryBackoffNs = int64(50 * time.Millisecond)
	plainDispatchQueueSize    = 8192

	plainConnProtoUnknown = 0
	plainConnProtoH1      = 1
	plainConnProtoH2      = 2

	plainAcceptDepth       = 64
	plainWorkerRingEntries = 4096
	plainReadMinFree       = 4096
	plainRecvBufRingSize   = 512
	plainRecvBufSize       = 4096

	splitSendMinBody = 16 << 10
)

var errPlainWorkerPark = errors.New("plain worker park")

type plainAcceptedConn struct {
	fd         int
	acceptedAt int64
}

type plainWorkerConn struct {
	index         int32
	nextFree      int32
	fd            int
	generation    uint16
	state         uint8
	tracked       bool
	closeDone     bool
	writeBorrowed bool
	writeZeroCopy bool
	keepAlive     bool
	readArmed     bool
	readPollFirst bool
	readN         int
	writeN        int
	writeSent     int
	zcPending     int
	requestCount  uint32
	lastActive    int64
	remoteAddr    string
	protocol      uint8
	readBuf       []byte
	writeBuf      []byte
	bodyBuf       []byte
	bodySent      int
	writingBody   bool
	req           Request
	resp          Response
	consumed      int
	closeAfter    bool
	h2            tlsWorkerH2State
	fwdIndex      int32
	fwdGen        uint16
}

type plainUringWorker struct {
	id              int
	listenerFD      int
	wakeupReadFD    int
	wakeupWriteFD   int
	handoffs        chan plainAcceptedConn
	ring            *ioUring
	recvBufs        *ioUringBufferRing
	server          *Server
	connections     []plainWorkerConn
	freeHead        int32
	completions     [ioUringCompletionBatchSize]ioUringCqe
	sweepIntervalNs    int64
	acceptBackfill     int64
	nextAcceptRetry    int64
	acceptPausedUntil  int64
	lastAcceptPauseLog int64
	localReqs          uint64
	wakeupBuf          [8]byte
	wakeupIovec        syscall.Iovec
	wakeArmed          bool
	parking            bool
	active             atomic.Int64
	asyncFwd           *asyncForwardPool
	dispatchTasks      chan func()
}

type plainUringBackend struct {
	server   *Server
	workers  []*plainUringWorker
	dispatch atomic.Uint32
	wg       sync.WaitGroup
	errCh    chan error
}

func (s *Server) tryServeWithIOUringPlainWorkers(listeners []net.Listener) (bool, error) {
	backend, err := newPlainUringBackend(s, listeners)
	if err != nil {
		return false, fmt.Errorf("plain new backend: %w", err)
	}
	defer backend.closeResources()
	prevProcs := runtime.GOMAXPROCS(len(backend.workers))
	defer runtime.GOMAXPROCS(prevProcs)
	log.Printf("[INFO] io_uring plain worker mode active on Linux amd64: workers=%d accept-shards=%d initial-conn-pool=%d", len(backend.workers), minInt(len(listeners), len(backend.workers)), ioUringInitialConnsPerShard)
	backend.start()
	if err := backend.wait(); err != nil {
		return true, fmt.Errorf("plain backend wait: %w", err)
	}
	return true, nil
}

func newPlainUringBackend(s *Server, listeners []net.Listener) (*plainUringBackend, error) {
	if len(listeners) == 0 {
		return nil, errors.New("no listeners")
	}
	shards, _ := ioUringShardLayout()
	workerCount := plainUringWorkerCount(s.config, shards)
	acceptShards := minInt(len(listeners), workerCount)
	if len(listeners) > acceptShards {
		log.Printf("[WARN] plain io_uring: %d listeners but only %d accept workers; closing %d excess listeners", len(listeners), acceptShards, len(listeners)-acceptShards)
		for i := acceptShards; i < len(listeners); i++ {
			_ = listeners[i].Close()
		}
		listeners = listeners[:acceptShards]
	}
	recvMultishotSupported, _ := probeIOUringRecvMultishot()
	backend := &plainUringBackend{
		server:  s,
		workers: make([]*plainUringWorker, 0, workerCount),
		errCh:   make(chan error, workerCount),
	}
	listenerFDs := make([]int, len(listeners))
	for i, listener := range listeners {
		fd, err := listenerFD(listener)
		if err != nil {
			return nil, fmt.Errorf("plain listener fd %d: %w", i, err)
		}
		listenerFDs[i] = fd
	}
	for workerID := 0; workerID < workerCount; workerID++ {
		wakeupPair, err := openWakePipeALOS()
		if err != nil {
			return nil, fmt.Errorf("plain worker %d wake pipe: %w", workerID, err)
		}
		worker := &plainUringWorker{
			id:            workerID,
			listenerFD:    -1,
			wakeupReadFD:  wakeupPair[0],
			wakeupWriteFD: wakeupPair[1],
			handoffs:      make(chan plainAcceptedConn, ioUringInitialConnsPerShard),
			server:        s,
			connections:   make([]plainWorkerConn, ioUringInitialConnsPerShard),
			freeHead:      0,
			dispatchTasks: make(chan func(), plainDispatchQueueSize),
		}
		if recvMultishotSupported {
			recvBufs, err := newIOUringBufferRing(plainRecvBufRingSize, plainRecvBufSize, uint16(workerID+1))
			if err != nil {
				_ = syscall.Close(wakeupPair[0])
				_ = syscall.Close(wakeupPair[1])
				return nil, fmt.Errorf("plain worker %d recv buf ring create: %w", workerID, err)
			}
			worker.recvBufs = recvBufs
		}
		if workerID < acceptShards {
			worker.listenerFD = listenerFDs[workerID]
			worker.acceptBackfill = plainAcceptDepth
		}
		worker.wakeupIovec.Base = &worker.wakeupBuf[0]
		worker.wakeupIovec.Len = uint64(len(worker.wakeupBuf))
		worker.initConnections()
		backend.workers = append(backend.workers, worker)
	}
	return backend, nil
}

func (backend *plainUringBackend) start() {
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
					log.Printf("[ERROR] io_uring plain worker %d failed to start: %v", worker.id, err)
					backend.errCh <- err
					return
				}
				firstAttempt = false
				if time.Since(start) > 5*time.Second {
					backoff = 50 * time.Millisecond
				}
				log.Printf("[WARN] io_uring plain worker %d exited, restarting in %v: %v", worker.id, backoff, err)
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

func (backend *plainUringBackend) stop() {
	for _, ln := range backend.server.listeners {
		_ = ln.Close()
	}
	for _, worker := range backend.workers {
		worker.signalWake()
	}
	backend.wg.Wait()
}

func (backend *plainUringBackend) wait() error {
	select {
	case <-backend.server.done:
		backend.stop()
		return nil
	case err := <-backend.errCh:
		backend.stop()
		return err
	}
}

func (backend *plainUringBackend) closeResources() {
	for _, worker := range backend.workers {
		if worker.recvBufs != nil {
			_ = worker.recvBufs.unregister(worker.ring)
			worker.recvBufs.close()
			worker.recvBufs = nil
		}
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
	}
}

func listenerFD(listener net.Listener) (int, error) {
	rawListener, ok := listener.(syscallConnListener)
	if !ok {
		return -1, fmt.Errorf("listener %T does not expose SyscallConn", listener)
	}
	rawConn, err := rawListener.SyscallConn()
	if err != nil {
		return -1, err
	}
	fd := -1
	err = rawConn.Control(func(value uintptr) {
		fd = int(value)
	})
	if err != nil {
		return -1, err
	}
	if fd < 0 {
		return -1, errors.New("listener fd unavailable")
	}
	return fd, nil
}

func (worker *plainUringWorker) initConnectionSlot(index int, nextFree int32) {
	conn := &worker.connections[index]
	conn.index = int32(index)
	conn.fd = -1
	conn.req.Headers = make([][2]string, 0, 16)
	conn.req.Proto = "HTTP/1.1"
	conn.resp.Headers = make([][2]string, 0, 8)
	conn.nextFree = nextFree
}

func (worker *plainUringWorker) initConnections() {
	for index := range worker.connections {
		nextFree := int32(index + 1)
		if index == len(worker.connections)-1 {
			nextFree = -1
		}
		worker.initConnectionSlot(index, nextFree)
	}
}

func (worker *plainUringWorker) growConnections() {
	oldLen := len(worker.connections)
	growBy := oldLen
	if growBy < ioUringInitialConnsPerShard {
		growBy = ioUringInitialConnsPerShard
	}
	if growBy == 0 {
		growBy = ioUringInitialConnsPerShard
	}
	prevHead := worker.freeHead
	worker.connections = append(worker.connections, make([]plainWorkerConn, growBy)...)
	for index := oldLen; index < len(worker.connections); index++ {
		nextFree := int32(index + 1)
		if index == len(worker.connections)-1 {
			nextFree = prevHead
		}
		worker.initConnectionSlot(index, nextFree)
	}
	worker.freeHead = int32(oldLen)
}

func (worker *plainUringWorker) run(backend *plainUringBackend) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer worker.flushReqStats()
	worker.reclaimPreviousRun()
	ring, err := newOwnedIOUring(plainWorkerRingEntries)
	if err != nil {
		return fmt.Errorf("plain worker %d ring create: %w", worker.id, err)
	}
	worker.ring = ring
	if err := worker.ring.enable(); err != nil {
		return fmt.Errorf("plain ring enable: %w", err)
	}
	if worker.recvBufs != nil {
		if err := worker.recvBufs.register(worker.ring); err != nil {
			worker.recvBufs.close()
			worker.recvBufs = nil
		}
	}
	worker.sweepIntervalNs = sweepIntervalNsFor(worker.server.config.IdleTimeout, worker.server.config.ReadTimeout, worker.server.config.WriteTimeout)
	stopSweeper := make(chan struct{})
	defer close(stopSweeper)
	go worker.runIdleSweeper(stopSweeper)
	if err := worker.fillAccepts(MonotonicNanotime()); err != nil {
		return fmt.Errorf("plain initial fill accepts: %w", err)
	}
	if worker.listenerFD >= 0 {
		if err := worker.armWake(); err != nil {
			return fmt.Errorf("plain initial arm wake: %w", err)
		}
		if _, err := worker.ring.submitAndWait(0); err != nil {
			return fmt.Errorf("plain initial submit: %w", err)
		}
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
		worker.drainDispatchTasks()
		if err := worker.drainHandoffs(now); err != nil {
			return fmt.Errorf("plain drain handoffs: %w", err)
		}
		if err := worker.fillAccepts(now); err != nil {
			return fmt.Errorf("plain refill accepts: %w", err)
		}
		if worker.listenerFD < 0 && worker.active.Load() == 0 && len(worker.handoffs) == 0 {
			if err := worker.parkUntilWork(); err != nil {
				return fmt.Errorf("plain park until work: %w", err)
			}
			lastSweep = MonotonicNanotime()
			continue
		}
		if err := worker.armWake(); err != nil {
			return fmt.Errorf("plain arm wake: %w", err)
		}
		count := worker.ring.peekBatch(worker.completions[:])
		if count == 0 {
			cqe, err := worker.ring.waitCqe()
			if err != nil {
				if worker.server.doneClosed() && (errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINVAL)) {
					return nil
				}
				return fmt.Errorf("plain wait cqe: %w", err)
			}
			worker.completions[0] = cqe
			count = 1
		}
		nowTime := MonotonicNanotime()
		for i := 0; i < count; i++ {
			if err := worker.handleCompletionGuarded(backend, worker.completions[i], nowTime); err != nil {
				if errors.Is(err, errPlainWorkerPark) {
					if err := worker.parkUntilWork(); err != nil {
						return fmt.Errorf("plain park after completion: %w", err)
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
		if nowTime-lastSweep >= worker.sweepIntervalNs {
			worker.sweepIdle(nowTime)
			worker.sweepForwards(nowTime)
			lastSweep = nowTime
		}
		worker.drainDispatchTasks()
		if err := worker.drainHandoffs(nowTime); err != nil {
			return fmt.Errorf("plain drain handoffs after cqe: %w", err)
		}
		if err := worker.fillAccepts(nowTime); err != nil {
			return fmt.Errorf("plain refill accepts after cqe: %w", err)
		}
		if worker.listenerFD < 0 && worker.active.Load() == 0 && len(worker.handoffs) == 0 {
			continue
		}
		if _, err := worker.ring.submitIfNeeded(); err != nil {
			if worker.server.doneClosed() && (errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINVAL)) {
				return nil
			}
			return fmt.Errorf("plain submit after cqe: %w", err)
		}
	}
}

func (worker *plainUringWorker) closeAllConnections() {
	for i := range worker.connections {
		conn := &worker.connections[i]
		if conn.fd >= 0 && conn.state != plainConnStateClosing {
			_ = worker.closeConnection(conn)
		}
	}
}

func (worker *plainUringWorker) reclaimPreviousRun() {
	if worker.ring == nil {
		return
	}
	for i := range worker.connections {
		conn := &worker.connections[i]
		if conn.fd >= 0 {
			_ = syscall.Close(conn.fd)
			conn.fd = -1
		}
		if conn.tracked {
			worker.active.Add(-1)
			worker.server.releaseTrackedConn()
			Stats.ActiveConns.Add(-1)
			conn.tracked = false
		}
		conn.state = plainConnStateFree
		conn.generation++
		if conn.generation == 0 {
			conn.generation = 1
		}
	}
	if worker.recvBufs != nil {
		_ = worker.recvBufs.unregister(worker.ring)
	}
	worker.ring.close()
	worker.ring = nil
	for {
		select {
		case <-worker.dispatchTasks:
		default:
			worker.initConnections()
			worker.freeHead = 0
			worker.acceptPausedUntil = 0
			return
		}
	}
}

func (worker *plainUringWorker) handleCompletionGuarded(backend *plainUringBackend, cqe ioUringCqe, now int64) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PLAIN-PANIC] worker %d recovered in completion handler: %v", worker.id, r)
			if op := plainDecodeOp(cqe.UserData); op != plainUringOpAccept && op != plainUringOpWake {
				connIndex := plainDecodeConn(cqe.UserData)
				if connIndex >= 0 && connIndex < len(worker.connections) {
					_ = worker.closeConnection(&worker.connections[connIndex])
				}
			}
			err = nil
		}
	}()
	return worker.handleCompletion(backend, cqe, now)
}

func (worker *plainUringWorker) handleCompletion(backend *plainUringBackend, cqe ioUringCqe, now int64) error {
	op := plainDecodeOp(cqe.UserData)
	connIndex := plainDecodeConn(cqe.UserData)
	generation := plainDecodeGeneration(cqe.UserData)
	switch op {
	case plainUringOpAccept:
		return worker.handleAccept(backend, cqe.Res, now)
	case plainUringOpWake:
		return worker.handleWake(now, cqe.Res)
	case plainUringOpBackendConnect, plainUringOpBackendSend, plainUringOpBackendRecv, plainUringOpBackendClose:
		return worker.handleBackendCompletion(op, cqe.UserData, cqe.Res)
	case plainUringOpRead, plainUringOpWrite, plainUringOpClose:
		if connIndex < 0 || connIndex >= len(worker.connections) {
			if op == plainUringOpRead {
				worker.recycleReadBuffer(cqe.Flags)
			}
			return nil
		}
		conn := &worker.connections[connIndex]
		if (conn.fd < 0 && !(op == plainUringOpWrite && cqe.Flags&ioUringCqeNotif != 0)) || conn.generation != generation {
			if op == plainUringOpRead {
				worker.recycleReadBuffer(cqe.Flags)
			}
			return nil
		}
		if conn.state == plainConnStateClosing && op != plainUringOpClose {
			if op == plainUringOpWrite && cqe.Flags&ioUringCqeNotif != 0 {
				return worker.handleWriteNotification(conn)
			}
			if op == plainUringOpRead {
				worker.recycleReadBuffer(cqe.Flags)
			}
			return nil
		}
		switch op {
		case plainUringOpRead:
			return worker.handleRead(conn, cqe.Res, cqe.Flags, now)
		case plainUringOpWrite:
			if cqe.Flags&ioUringCqeNotif != 0 {
				return worker.handleWriteNotification(conn)
			}
			return worker.handleWrite(conn, cqe.Res, cqe.Flags, now)
		case plainUringOpClose:
			worker.finishClose(conn)
		}
	}
	return nil
}

func (worker *plainUringWorker) handleWake(now int64, result int32) error {
	if result >= 0 {
		if err := worker.drainHandoffs(now); err != nil {
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
		return errPlainWorkerPark
	}
	worker.parking = false
	return worker.queueWake()
}

func (worker *plainUringWorker) handleAccept(backend *plainUringBackend, result int32, now int64) error {
	atomic.AddInt64(&worker.acceptBackfill, 1)
	if result < 0 {
		if worker.server.doneClosed() || worker.listenerFD < 0 || result == -int32(syscall.EBADF) || result == -int32(syscall.EINVAL) {
			return nil
		}
		if result == -int32(syscall.EAGAIN) || result == -int32(syscall.EINTR) || result == -int32(syscall.ECONNABORTED) {
			return nil
		}
		if result == -int32(syscall.EMFILE) || result == -int32(syscall.ENFILE) || result == -int32(syscall.ENOMEM) || result == -int32(syscall.ENOBUFS) {
			worker.acceptPausedUntil = now + plainAcceptRetryBackoffNs
			if now-worker.lastAcceptPauseLog > int64(time.Second) {
				worker.lastAcceptPauseLog = now
				log.Printf("[WARN] io_uring plain worker %d accept backpressure (%v); pausing accepts %v", worker.id, syscall.Errno(-result), time.Duration(plainAcceptRetryBackoffNs))
			}
			return nil
		}
		return fmt.Errorf("plain io_uring accept failed: %w", syscall.Errno(-result))
	}
	atomic.StoreInt64(&worker.nextAcceptRetry, 0)
	fd := int(result)
	prepareAcceptedFD(fd)
	backend.dispatchAccepted(worker, fd, now)
	return nil
}

func (worker *plainUringWorker) handleRead(conn *plainWorkerConn, result int32, flags uint32, now int64) error {
	if worker.recvBufs != nil && flags&ioUringCqeBuffer != 0 {
		return worker.handleBufferedRead(conn, result, flags, now)
	}
	conn.readArmed = false
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
	conn.readN += int(result)
	if len(conn.readBuf) < conn.readN {
		conn.readBuf = conn.readBuf[:conn.readN]
	}
	if conn.state == plainConnStateForwarding || conn.state == plainConnStateDispatching {
		return nil
	}
	if conn.protocol == plainConnProtoH2 {
		return worker.processHTTP2(conn)
	}
	return worker.processRequests(conn)
}

func (worker *plainUringWorker) handleBufferedRead(conn *plainWorkerConn, result int32, flags uint32, now int64) error {
	conn.readArmed = flags&ioUringCqeMore != 0
	bufferID := cqeBufferID(flags)
	defer worker.recycleReadBuffer(flags)
	if result < 0 {
		if result == -int32(syscall.EINVAL) || result == -int32(syscall.ENOSYS) {
			worker.recvBufs.close()
			worker.recvBufs = nil
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
	if conn.readBuf == nil {
		conn.readBuf = acquirePooledBuf(&connReadBufPool)
	}
	maxRead := resolveReadCap(worker.server.config.MaxReadSize)
	if !worker.ensureReadCapacity(conn, n, maxRead) {
		return worker.closeConnection(conn)
	}
	if len(conn.readBuf) < conn.readN {
		conn.readBuf = conn.readBuf[:conn.readN]
	}
	worker.appendBufferedRead(&conn.readBuf, bufferID, n)
	conn.readN = len(conn.readBuf)
	if conn.state == plainConnStateWriting || conn.state == plainConnStateForwarding || conn.state == plainConnStateDispatching {
		return nil
	}
	if conn.protocol == plainConnProtoH2 {
		return worker.processHTTP2(conn)
	}
	return worker.processRequests(conn)
}

func (worker *plainUringWorker) appendBufferedRead(dst *[]byte, startID uint16, total int) {
	if worker.recvBufs == nil || total <= 0 {
		return
	}
	buf := worker.recvBufs.buffer(startID)
	if total > len(buf) {
		total = len(buf)
	}
	*dst = append(*dst, buf[:total]...)
}

func (worker *plainUringWorker) recycleReadBuffer(flags uint32) {
	if worker.recvBufs == nil || flags&ioUringCqeBuffer == 0 {
		return
	}
	worker.recvBufs.recycle(cqeBufferID(flags))
}

func (worker *plainUringWorker) processRequests(conn *plainWorkerConn) error {
	if conn.protocol == plainConnProtoH2 {
		return worker.processHTTP2(conn)
	}
	if worker.shouldHandoffHTTP2(conn) {
		return worker.handoffHTTP2(conn)
	}
	if worker.maybeInitHTTP2(conn) {
		return worker.queueRead(conn)
	}
	maxRead := worker.server.config.MaxReadSize
	if maxRead <= 0 {
		maxRead = 2 << 20
	}
	for {
		if fastResp, consumed, closeConn, ok := worker.server.matchPlainRootFastRequest(conn.readBuf[:conn.readN]); ok {
			if worker.server.tryAcquireRequestSlot() {
				conn.requestCount++
				worker.bumpReqStats()
				worker.server.releaseRequestSlot()
				batched := 0
				for !closeConn && consumed < conn.readN {
					nextResp, nextConsumed, nextClose, nextOK := worker.server.matchPlainRootFastRequest(conn.readBuf[consumed:conn.readN])
					if !nextOK || !worker.server.tryAcquireRequestSlot() {
						break
					}
					conn.requestCount++
					worker.bumpReqStats()
					worker.server.releaseRequestSlot()
					if batched == 0 {
						worker.beginBatchedWrite(conn, fastResp)
					}
					conn.writeBuf = append(conn.writeBuf, nextResp...)
					consumed += nextConsumed
					closeConn = nextClose
					batched++
				}
				if batched > 0 {
					return worker.queueBatchedResponses(conn, !closeConn, consumed)
				}
				return worker.queuePrebuiltResponse(conn, fastResp, !closeConn, consumed)
			}
		}

		conn.req.resetFastH1()
		headerEnd, contentLength, hasContentLength, closeConn, badTransferEncoding, chunkedEncoding, tooLarge, ok := ParseH1RequestHead(conn.readBuf[:conn.readN], &conn.req, worker.server.config.MaxHeaderSize, worker.server.config.MaxHeaderCount)
		if tooLarge {
			conn.resp.Reset()
			conn.resp.Status(431).String("Request Header Fields Too Large")
			return worker.queueResponse(conn, false, conn.readN)
		}
		if !ok {
			return worker.queueRead(conn)
		}
		consumed := headerEnd
		if badTransferEncoding {
			conn.resp.Reset()
			conn.resp.Status(400).String("Bad Request")
			return worker.queueResponse(conn, false, consumed)
		}
		if chunkedEncoding {
			conn.resp.Reset()
			conn.resp.Status(501).String("Not Implemented")
			return worker.queueResponse(conn, false, consumed)
		}
		if hasContentLength {
			if contentLength < 0 {
				conn.resp.Reset()
				conn.resp.Status(400).String("Bad Request")
				return worker.queueResponse(conn, false, consumed)
			}
			if worker.server.config.MaxBodySize > 0 && int64(contentLength) > worker.server.config.MaxBodySize {
				conn.resp.Reset()
				conn.resp.Status(413).String("Payload Too Large")
				return worker.queueResponse(conn, false, consumed)
			}
			bodyEnd := headerEnd + contentLength
			if bodyEnd < headerEnd {
				conn.resp.Reset()
				conn.resp.Status(400).String("Bad Request")
				return worker.queueResponse(conn, false, consumed)
			}
			if bodyEnd > conn.readN {
				if !worker.ensureReadCapacity(conn, bodyEnd-conn.readN, int(maxRead)) {
					return worker.closeConnection(conn)
				}
				return worker.queueRead(conn)
			}
			conn.req.Body = conn.readBuf[headerEnd:bodyEnd]
			consumed = bodyEnd
		}
		if conn.protocol == plainConnProtoUnknown {
			conn.protocol = plainConnProtoH1
			Stats.H1Conns.Add(1)
		}
		conn.requestCount++
		worker.bumpReqStats()
		conn.resp.resetFastH1()
		conn.req.StreamWriter = nil
		conn.req.conn = nil
		conn.req.attachConn = worker.newH1RequestConnAttacher(conn, consumed)
		conn.req.connTakenOver = false
		conn.req.hijackReadBuf = nil
		conn.req.server = worker.server
		conn.req.Host = conn.req.cachedHost
		conn.req.RemoteAddr = conn.remoteAddr
		conn.resp.SetSW(nil)
		conn.resp.lazyReq = &conn.req
		if worker.tryAsyncForward(conn, consumed, closeConn) {
			return nil
		}
		return worker.startAsyncDispatch(conn, consumed, closeConn)
	}
}

func (worker *plainUringWorker) startAsyncDispatch(conn *plainWorkerConn, consumed int, closeConn bool) error {
	conn.state = plainConnStateDispatching
	idx := conn.index
	gen := conn.generation
	req := &conn.req
	resp := &conn.resp
	srv := worker.server
	go func() {
		defer func() {
			if r := recover(); r != nil && !req.connTakenOver {
				resp.resetFastH1()
				resp.Status(500).String("Internal Server Error")
			}
			worker.postTask(func() {
				worker.finishAsyncDispatch(idx, gen, consumed, closeConn)
			})
		}()
		if srv.fastDispatch.Load() {
			handler := srv.Router.Lookup(req.Method, req.Path, req)
			handler(req, resp)
		} else {
			srv.dispatch(req, resp)
		}
	}()
	return nil
}

func (worker *plainUringWorker) finishAsyncDispatch(idx int32, gen uint16, consumed int, closeConn bool) {
	if idx < 0 || int(idx) >= len(worker.connections) {
		return
	}
	conn := &worker.connections[idx]
	if conn.generation != gen || conn.state != plainConnStateDispatching {
		return
	}
	if conn.req.connTakenOver {
		if conn.req.hijacked {
			worker.releaseConnection(conn)
			return
		}
		if conn.resp.IsStreamed() {
			releaseStreamWriter(conn.req.StreamWriter)
		}
		if conn.req.conn != nil {
			_ = conn.req.conn.Close()
		}
		worker.releaseConnection(conn)
		return
	}
	if worker.server.config.MaxWriteSize > 0 && int64(conn.resp.transmittedBodyLen()) > worker.server.config.MaxWriteSize {
		conn.resp.resetFastH1()
		conn.resp.Status(500).String("Response Too Large")
		closeConn = true
	}
	_ = worker.queueResponse(conn, !closeConn, consumed)
}

func (worker *plainUringWorker) postTask(fn func()) {
	worker.dispatchTasks <- fn
	worker.signalWake()
}

func (worker *plainUringWorker) drainDispatchTasks() {
	for {
		select {
		case fn := <-worker.dispatchTasks:
			fn()
		default:
			return
		}
	}
}

func (worker *plainUringWorker) bumpReqStats() {
	worker.localReqs++
	if worker.localReqs&63 == 0 {
		Stats.TotalReqs.Add(64)
		worker.localReqs = 0
	}
}

func (worker *plainUringWorker) flushReqStats() {
	if worker.localReqs > 0 {
		Stats.TotalReqs.Add(worker.localReqs)
		worker.localReqs = 0
	}
}

func (worker *plainUringWorker) newH1RequestConnAttacher(conn *plainWorkerConn, consumed int) func(*Request) net.Conn {
	prefix := append([]byte(nil), conn.readBuf[consumed:conn.readN]...)
	var once sync.Once
	return func(req *Request) net.Conn {
		once.Do(func() {
			done := make(chan struct{})
			worker.postTask(func() {
				defer close(done)
				if conn.fd < 0 {
					return
				}
				_ = worker.ring.cancelFD(conn.fd, ioUringOpRecv)
				wrapped, err := newIOUringConn(conn.fd)
				if err != nil {
					return
				}
				conn.fd = -1
				handed := net.Conn(wrapped)
				if len(prefix) > 0 {
					handed = &prefixConn{Conn: wrapped, reader: io.MultiReader(bytes.NewReader(prefix), wrapped)}
				}
				handed = worker.server.trackHandoffConn(handed)
				if handed == nil {
					return
				}
				req.connTakenOver = true
				req.attachConn = nil
				req.conn = handed
			})
			<-done
		})
		return req.conn
	}
}

func (worker *plainUringWorker) shouldHandoffHTTP2(conn *plainWorkerConn) bool {
	if conn.protocol != plainConnProtoUnknown || conn.readN < H2PrefaceLen {
		return false
	}
	for i := 0; i < H2PrefaceLen; i++ {
		if conn.readBuf[i] != H2ClientPreface[i] {
			return false
		}
	}
	return true
}

func (worker *plainUringWorker) handoffHTTP2(conn *plainWorkerConn) error {
	prefix := append([]byte(nil), conn.readBuf[:conn.readN]...)
	wrapped, err := newIOUringConn(conn.fd)
	if err != nil {
		conn.fd = -1
		worker.releaseConnection(conn)
		return nil
	}
	conn.fd = -1
	worker.releaseConnection(conn)
	if !worker.server.tryTrackConn() {
		wrapped.Close()
		return nil
	}
	Stats.ActiveConns.Add(1)
	go func() {
		defer worker.server.releaseTrackedConn()
		defer Stats.ActiveConns.Add(-1)
		defer wrapped.Close()
		bridgeConn := net.Conn(wrapped)
		if len(prefix) > 0 {
			bridgeConn = &prefixConn{Conn: wrapped, reader: io.MultiReader(bytes.NewReader(prefix), wrapped)}
		}
		worker.server.ServeH2Plain(bridgeConn)
	}()
	return nil
}

func (worker *plainUringWorker) queueResponse(conn *plainWorkerConn, keepAlive bool, consumed int) error {
	conn.keepAlive = keepAlive
	conn.closeAfter = !keepAlive
	conn.consumed = consumed
	if conn.writeBorrowed {
		conn.writeBorrowed = false
		conn.writeBuf = acquirePooledBuf(&connWriteBufPool)
	} else if conn.writeBuf == nil {
		conn.writeBuf = acquirePooledBuf(&connWriteBufPool)
	}
	base := conn.writeBuf[:0]
	if conn.resp.transmittedBodyLen() <= splitSendMinBody {
		conn.writeBuf = appendPlainResponse(&conn.resp, base)
		conn.bodyBuf = nil
	} else {
		conn.writeBuf = appendPlainResponseHeaders(&conn.resp, base)
		conn.bodyBuf = conn.resp.transmittedBodyBytes()
	}
	conn.writeN = len(conn.writeBuf)
	conn.writeSent = 0
	conn.bodySent = 0
	conn.writingBody = false
	worker.compactReadBuffer(conn, consumed)
	if conn.writeN == 0 {
		return worker.closeConnection(conn)
	}
	conn.writeZeroCopy = false
	conn.state = plainConnStateWriting
	if err := worker.queueWrite(conn, conn.writeBuf[:conn.writeN]); err != nil {
		return worker.closeConnection(conn)
	}
	return nil
}

func (worker *plainUringWorker) beginBatchedWrite(conn *plainWorkerConn, first []byte) {
	if conn.writeBorrowed || conn.writeBuf == nil {
		conn.writeBorrowed = false
		conn.writeBuf = acquirePooledBuf(&connWriteBufPool)
	}
	conn.writeBuf = append(conn.writeBuf[:0], first...)
}

func (worker *plainUringWorker) queueBatchedResponses(conn *plainWorkerConn, keepAlive bool, consumed int) error {
	conn.keepAlive = keepAlive
	conn.closeAfter = !keepAlive
	conn.consumed = consumed
	conn.writeN = len(conn.writeBuf)
	conn.writeSent = 0
	conn.bodyBuf = nil
	conn.bodySent = 0
	conn.writingBody = false
	worker.compactReadBuffer(conn, consumed)
	if conn.writeN == 0 {
		return worker.closeConnection(conn)
	}
	conn.writeZeroCopy = false
	conn.state = plainConnStateWriting
	if err := worker.queueWrite(conn, conn.writeBuf[:conn.writeN]); err != nil {
		return worker.closeConnection(conn)
	}
	return nil
}

func (worker *plainUringWorker) queuePrebuiltResponse(conn *plainWorkerConn, payload []byte, keepAlive bool, consumed int) error {
	conn.keepAlive = keepAlive
	conn.closeAfter = !keepAlive
	conn.consumed = consumed
	conn.writeBorrowed = true
	conn.writeBuf = payload
	conn.writeN = len(payload)
	conn.writeSent = 0
	conn.bodyBuf = nil
	conn.bodySent = 0
	conn.writingBody = false
	worker.compactReadBuffer(conn, consumed)
	if conn.writeN == 0 {
		return worker.closeConnection(conn)
	}
	conn.writeZeroCopy = worker.shouldUseZeroCopySend(conn)
	conn.state = plainConnStateWriting
	if err := worker.queueWrite(conn, conn.writeBuf[:conn.writeN]); err != nil {
		return worker.closeConnection(conn)
	}
	return nil
}

func (worker *plainUringWorker) currentWriteChunk(conn *plainWorkerConn) []byte {
	if conn.writingBody {
		return conn.bodyBuf[conn.bodySent:]
	}
	return conn.writeBuf[conn.writeSent:conn.writeN]
}

func (worker *plainUringWorker) handleWrite(conn *plainWorkerConn, result int32, flags uint32, now int64) error {
	if result < 0 {
		err := syscall.Errno(-result)
		if conn.writeZeroCopy && (errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP)) {
			worker.ring.markSendZCUnsupported()
			conn.writeZeroCopy = false
			return worker.queueWrite(conn, worker.currentWriteChunk(conn))
		}
		if isIOUringTransient(err) {
			return worker.queueWrite(conn, worker.currentWriteChunk(conn))
		}
		return worker.closeConnection(conn)
	}
	if conn.writeZeroCopy && flags&ioUringCqeMore != 0 {
		conn.zcPending++
		worker.ring.markSendZCSupported()
	}
	conn.lastActive = now
	if conn.writingBody {
		conn.bodySent += int(result)
		if conn.bodySent < len(conn.bodyBuf) {
			return worker.queueWrite(conn, conn.bodyBuf[conn.bodySent:])
		}
		conn.writingBody = false
		conn.bodyBuf = nil
	} else {
		conn.writeSent += int(result)
		if conn.writeSent < conn.writeN {
			return worker.queueWrite(conn, conn.writeBuf[conn.writeSent:conn.writeN])
		}
		if conn.protocol == plainConnProtoH2 {
			conn.writeBuf = conn.writeBuf[:0]
		}
		if len(conn.bodyBuf) > 0 {
			conn.writingBody = true
			conn.bodySent = 0
			worker.releaseIdleWriteBuf(conn)
			worker.releaseIdleReadBuf(conn)
			return worker.queueWrite(conn, conn.bodyBuf)
		}
	}
	if conn.closeAfter {
		return worker.closeConnection(conn)
	}
	if conn.readN > 0 {
		if conn.protocol == plainConnProtoH2 {
			return worker.processHTTP2(conn)
		}
		return worker.processRequests(conn)
	}
	if conn.protocol != plainConnProtoH2 {
		worker.releaseIdleWriteBuf(conn)
		worker.releaseIdleReadBuf(conn)
	}
	return worker.queueRead(conn)
}

func (worker *plainUringWorker) releaseIdleReadBuf(conn *plainWorkerConn) {
	if worker.recvBufs == nil || conn.readN != 0 {
		return
	}
	releasePooledBuf(&connReadBufPool, conn.readBuf, connBufPoolMaxCap)
	conn.readBuf = nil
}

func (worker *plainUringWorker) releaseIdleWriteBuf(conn *plainWorkerConn) {
	if conn.writeBorrowed {
		conn.writeBorrowed = false
		conn.writeBuf = nil
		return
	}
	releasePooledBuf(&connWriteBufPool, conn.writeBuf, connBufPoolMaxCap)
	conn.writeBuf = nil
}

func (worker *plainUringWorker) handleWriteNotification(conn *plainWorkerConn) error {
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

func (worker *plainUringWorker) fillAccepts(now int64) error {
	if atomic.LoadInt64(&worker.acceptBackfill) <= 0 || worker.server.doneClosed() || worker.listenerFD < 0 {
		return nil
	}
	if worker.acceptPausedUntil != 0 {
		if now < worker.acceptPausedUntil {
			return nil
		}
		worker.acceptPausedUntil = 0
	}
	for atomic.LoadInt64(&worker.acceptBackfill) > 0 {
		if err := worker.ring.prepAcceptUser(worker.listenerFD, plainEncodeUserData(plainUringOpAccept, 0, 0), uint32(sockCloexec|sockNonblock)); err != nil {
			return err
		}
		atomic.AddInt64(&worker.acceptBackfill, -1)
	}
	return nil
}

func (worker *plainUringWorker) drainHandoffs(now int64) error {
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

func (worker *plainUringWorker) attachAccepted(fd int, now int64) error {
	conn := worker.acquireConnection()
	if conn == nil {
		_ = syscall.Close(fd)
		return nil
	}
	conn.fd = fd
	if _, remote := socketAddrs(fd); remote != nil {
		conn.remoteAddr = remote.String()
	}
	conn.state = plainConnStateReading
	conn.readN = 0
	conn.writeN = 0
	conn.writeSent = 0
	conn.requestCount = 0
	conn.keepAlive = false
	conn.closeAfter = false
	conn.closeDone = false
	conn.writeBorrowed = false
	conn.writeZeroCopy = false
	conn.zcPending = 0
	conn.lastActive = now
	conn.protocol = plainConnProtoUnknown
	conn.readArmed = false
	conn.readPollFirst = false
	conn.h2.reset()
	if worker.recvBufs == nil && conn.readBuf == nil {
		conn.readBuf = acquirePooledBuf(&connReadBufPool)
	}
	if !worker.server.tryTrackConn() {
		_ = syscall.Close(fd)
		conn.fd = -1
		worker.recycleConnection(conn)
		return nil
	}
	conn.tracked = true
	worker.active.Add(1)
	Stats.ActiveConns.Add(1)
	Stats.TotalConns.Add(1)
	return worker.queueRead(conn)
}

func (worker *plainUringWorker) queueRead(conn *plainWorkerConn) error {
	if conn.fd < 0 || conn.state == plainConnStateClosing {
		return nil
	}
	conn.state = plainConnStateReading
	if worker.recvBufs != nil {
		if conn.readArmed {
			return nil
		}
		conn.readArmed = true
		if err := worker.ring.prepRecvMultishotUser(conn.fd, worker.recvBufs.bgid, plainEncodeUserData(plainUringOpRead, int(conn.index), conn.generation), conn.readPollFirst, false); err != nil {
			conn.readArmed = false
			return err
		}
		return nil
	}
	if !worker.ensureReadCapacity(conn, plainReadMinFree, resolveReadCap(worker.server.config.MaxReadSize)) {
		return worker.closeConnection(conn)
	}
	return worker.ring.prepRecvUser(conn.fd, conn.readBuf[conn.readN:cap(conn.readBuf)], plainEncodeUserData(plainUringOpRead, int(conn.index), conn.generation))
}

func (worker *plainUringWorker) ensureReadCapacity(conn *plainWorkerConn, minFree int, maxRead int) bool {
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

func (worker *plainUringWorker) closeConnection(conn *plainWorkerConn) error {
	if conn.fd < 0 || conn.state == plainConnStateClosing {
		return nil
	}
	if conn.state == plainConnStateForwarding {
		worker.forwardClientGone(conn)
	}
	conn.state = plainConnStateClosing
	conn.closeDone = false
	_ = worker.ring.cancelFD(conn.fd, 0)
	if err := worker.ring.prepCloseUser(conn.fd, plainEncodeUserData(plainUringOpClose, int(conn.index), conn.generation)); err != nil {
		_ = syscall.Close(conn.fd)
		worker.finishClose(conn)
	}
	return nil
}

func (worker *plainUringWorker) finishClose(conn *plainWorkerConn) {
	if conn.fd >= 0 {
		conn.fd = -1
	}
	conn.closeDone = true
	if conn.zcPending > 0 {
		return
	}
	worker.releaseConnection(conn)
}

func (worker *plainUringWorker) releaseConnection(conn *plainWorkerConn) {
	if conn.tracked {
		worker.active.Add(-1)
		worker.server.releaseTrackedConn()
		Stats.ActiveConns.Add(-1)
		conn.tracked = false
	}
	worker.recycleConnection(conn)
}

func (worker *plainUringWorker) recycleConnection(conn *plainWorkerConn) {
	conn.state = plainConnStateFree
	conn.readN = 0
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
	conn.protocol = plainConnProtoUnknown
	conn.readArmed = false
	conn.readPollFirst = false
	conn.closeDone = false
	conn.tracked = false
	conn.writeZeroCopy = false
	conn.zcPending = 0
	conn.h2.reset()
	conn.req.resetFastH1()
	conn.resp.resetFastH1()
	releasePooledBuf(&connReadBufPool, conn.readBuf, connBufPoolMaxCap)
	conn.readBuf = nil
	if conn.writeBorrowed {
		conn.writeBorrowed = false
	} else {
		releasePooledBuf(&connWriteBufPool, conn.writeBuf, connBufPoolMaxCap)
	}
	conn.writeBuf = nil
	releasePooledBuf(&connBodyBufPool, conn.resp.body, connBufPoolMaxCap)
	conn.resp.body = nil
	conn.req.Body = nil
	conn.bodyBuf = nil
	conn.bodySent = 0
	conn.writingBody = false
}

func (worker *plainUringWorker) shouldUseZeroCopySend(conn *plainWorkerConn) bool {
	return conn.closeAfter && conn.writeN >= ioUringSendZCThreshold && worker.ring.canUseSendZC()
}

func (worker *plainUringWorker) queueWrite(conn *plainWorkerConn, buf []byte) error {
	userData := plainEncodeUserData(plainUringOpWrite, int(conn.index), conn.generation)
	if conn.writeZeroCopy {
		return worker.ring.prepSendZCUser(conn.fd, buf, userData, false)
	}
	return worker.ring.prepSendUser(conn.fd, buf, userData)
}

func (worker *plainUringWorker) maybeInitHTTP2(conn *plainWorkerConn) bool {
	if conn.protocol != plainConnProtoUnknown || conn.readN == 0 {
		return false
	}
	prefixLen := conn.readN
	if prefixLen > H2PrefaceLen {
		prefixLen = H2PrefaceLen
	}
	for i := 0; i < prefixLen; i++ {
		if conn.readBuf[i] != H2ClientPreface[i] {
			return false
		}
	}
	if conn.readN < H2PrefaceLen {
		return true
	}
	conn.protocol = plainConnProtoH2
	conn.h2.init()
	conn.writeBuf = appendH2ServerSettingsFlight(conn.writeBuf[:0], worker.server)
	Stats.H2Conns.Add(1)
	if worker.server.IsDebug() {
		Dbg("[%s] plain worker entering native h2c", conn.remoteAddr)
	}
	return true
}

func (worker *plainUringWorker) acquireConnection() *plainWorkerConn {
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

func (worker *plainUringWorker) compactReadBuffer(conn *plainWorkerConn, consumed int) {
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

func (worker *plainUringWorker) sweepIdle(now int64) {
	idleTO := worker.server.config.IdleTimeout
	readTO := worker.server.config.ReadTimeout
	writeTO := worker.server.config.WriteTimeout
	readHeaderTO := worker.server.config.ReadHeaderTimeout
	for i := range worker.connections {
		conn := &worker.connections[i]
		if conn.fd < 0 || conn.state == plainConnStateClosing || conn.state == plainConnStateDispatching {
			continue
		}
		timeout := idleTO
		switch conn.state {
		case plainConnStateWriting:
			if writeTO > 0 {
				timeout = writeTO
			}
		case plainConnStateReading:
			if conn.readN > 0 {
				rt := readTO
				if readHeaderTO > 0 {
					rt = readHeaderTO
				}
				if rt > 0 {
					timeout = rt
				}
			}
		}
		if timeout > 0 && now-conn.lastActive > timeout.Nanoseconds() {
			_ = worker.closeConnection(conn)
		}
	}
}

func (worker *plainUringWorker) runIdleSweeper(stop <-chan struct{}) {
	interval := time.Duration(worker.sweepIntervalNs)
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			worker.signalWake()
		}
	}
}

func sweepIntervalNsFor(durs ...time.Duration) int64 {
	smallest := int64(0)
	for _, d := range durs {
		if d > 0 && (smallest == 0 || d.Nanoseconds() < smallest) {
			smallest = d.Nanoseconds()
		}
	}
	if smallest == 0 {
		return int64(time.Second)
	}
	interval := smallest / 4
	if interval > int64(time.Second) {
		interval = int64(time.Second)
	}
	if interval < int64(50*time.Millisecond) {
		interval = int64(50 * time.Millisecond)
	}
	return interval
}

func (backend *plainUringBackend) dispatchAccepted(source *plainUringWorker, fd int, now int64) {
	if backend.server.doneClosed() {
		_ = syscall.Close(fd)
		return
	}
	workerCount := len(backend.workers)
	if workerCount == 0 {
		_ = syscall.Close(fd)
		return
	}
	start := int(backend.dispatch.Add(1)-1) % workerCount
	for offset := 0; offset < workerCount; offset++ {
		target := backend.workers[(start+offset)%workerCount]
		if target.enqueueAccepted(plainAcceptedConn{fd: fd, acceptedAt: now}) {
			return
		}
	}
	_ = source.attachAccepted(fd, now)
}

func plainUringWorkerCount(cfg Config, maxShards int) int {
	workers := cfg.WorkerCount
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		workers = 1
	}
	if maxShards > 0 && workers > maxShards {
		workers = maxShards
	}
	return workers
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (worker *plainUringWorker) enqueueAccepted(conn plainAcceptedConn) bool {
	select {
	case worker.handoffs <- conn:
		worker.signalWake()
		return true
	default:
		return false
	}
}

func (worker *plainUringWorker) armWake() error {
	if worker.wakeArmed {
		return nil
	}
	if err := worker.queueWake(); err != nil {
		return err
	}
	worker.wakeArmed = true
	return nil
}

func (worker *plainUringWorker) queueWake() error {
	return worker.ring.prepReadUser(worker.wakeupReadFD, worker.wakeupBuf[:], plainEncodeUserData(plainUringOpWake, 0, 0))
}

func (worker *plainUringWorker) signalWake() {
	if worker.wakeupWriteFD < 0 {
		return
	}
	_, err := syscall.Write(worker.wakeupWriteFD, []byte{1})
	if err != nil && !errors.Is(err, syscall.EAGAIN) {
		return
	}
}

func (worker *plainUringWorker) parkUntilWork() error {
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
				if errors.Is(err, errPlainWorkerPark) {
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

func openWakePipeALOS() ([2]int, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return [2]int{}, err
	}
	if err := syscall.SetNonblock(fds[1], true); err != nil {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
		return [2]int{}, err
	}
	return [2]int{fds[0], fds[1]}, nil
}

func plainEncodeUserData(op uint8, connIndex int, generation uint16) uint64 {
	return uint64(op)<<56 | uint64(generation)<<32 | uint64(uint32(connIndex))
}

func plainDecodeOp(userData uint64) uint8 {
	return uint8(userData >> 56)
}

func plainDecodeGeneration(userData uint64) uint16 {
	return uint16((userData >> 32) & 0xffff)
}

func plainDecodeConn(userData uint64) int {
	return int(uint32(userData))
}

func (ring *ioUring) prepAcceptUser(fd int, userData uint64, flags uint32) error {
	sqe, err := ring.getSqeNoClear()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpAccept
	sqe.Flags = 0
	sqe.Ioprio = 0
	sqe.FD = int32(fd)
	sqe.Off = 0
	sqe.Addr = 0
	sqe.Len = 0
	sqe.OpFlags = flags
	sqe.UserData = userData
	sqe.BufIndex = 0
	sqe.Personality = 0
	sqe.SpliceFDIn = 0
	sqe.Addr3 = 0
	sqe.Pad2 = 0
	return nil
}

func (ring *ioUring) prepRecvUser(fd int, buf []byte, userData uint64) error {
	return ring.prepRecvUserWithFlags(fd, buf, userData, false)
}

func (ring *ioUring) prepRecvUserWithFlags(fd int, buf []byte, userData uint64, pollFirst bool) error {
	sqe, err := ring.getSqeNoClear()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpRecv
	sqe.Flags = 0
	if pollFirst {
		sqe.Ioprio = ioUringPollFirst
	} else {
		sqe.Ioprio = 0
	}
	sqe.FD = int32(fd)
	sqe.Off = 0
	sqe.Addr = uint64(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
	sqe.Len = uint32(len(buf))
	sqe.OpFlags = 0
	sqe.UserData = userData
	sqe.BufIndex = 0
	sqe.Personality = 0
	sqe.SpliceFDIn = 0
	sqe.Addr3 = 0
	sqe.Pad2 = 0
	return nil
}

func (ring *ioUring) prepSendUser(fd int, buf []byte, userData uint64) error {
	return ring.prepSendUserWithFlags(fd, buf, userData, false)
}

func (ring *ioUring) prepSendUserWithFlags(fd int, buf []byte, userData uint64, pollFirst bool) error {
	return ring.prepSendUserWithFlagsAndMode(fd, buf, userData, pollFirst, false)
}

func (ring *ioUring) prepSendZCUser(fd int, buf []byte, userData uint64, pollFirst bool) error {
	return ring.prepSendUserWithFlagsAndMode(fd, buf, userData, pollFirst, true)
}

func (ring *ioUring) prepSendUserWithFlagsAndMode(fd int, buf []byte, userData uint64, pollFirst bool, zeroCopy bool) error {
	sqe, err := ring.getSqeNoClear()
	if err != nil {
		return err
	}
	if zeroCopy {
		sqe.Opcode = ioUringOpSendZC
	} else {
		sqe.Opcode = ioUringOpSend
	}
	sqe.Flags = 0
	var ioprio uint16
	if pollFirst {
		ioprio = ioUringPollFirst
	}
	if zeroCopy {
		ioprio |= ioUringSendZCReportUsage
	}
	sqe.Ioprio = ioprio
	sqe.FD = int32(fd)
	sqe.Off = 0
	sqe.Addr = uint64(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
	sqe.Len = uint32(len(buf))
	sqe.OpFlags = 0
	sqe.UserData = userData
	sqe.BufIndex = 0
	sqe.Personality = 0
	sqe.SpliceFDIn = 0
	sqe.Addr3 = 0
	sqe.Pad2 = 0
	return nil
}

func (ring *ioUring) prepCloseUser(fd int, userData uint64) error {
	sqe, err := ring.getSqeNoClear()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpClose
	sqe.Flags = 0
	sqe.Ioprio = 0
	sqe.FD = int32(fd)
	sqe.Off = 0
	sqe.Addr = 0
	sqe.Len = 0
	sqe.OpFlags = 0
	sqe.UserData = userData
	sqe.BufIndex = 0
	sqe.Personality = 0
	sqe.SpliceFDIn = 0
	sqe.Addr3 = 0
	sqe.Pad2 = 0
	return nil
}

func (ring *ioUring) prepReadvUser(fd int, iovec *syscall.Iovec, userData uint64) error {
	sqe, err := ring.getSqeNoClear()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpReadv
	sqe.Flags = 0
	sqe.Ioprio = 0
	sqe.FD = int32(fd)
	sqe.Off = 0
	sqe.Addr = uint64(uintptr(unsafe.Pointer(iovec)))
	sqe.Len = 1
	sqe.OpFlags = 0
	sqe.UserData = userData
	sqe.BufIndex = 0
	sqe.Personality = 0
	sqe.SpliceFDIn = 0
	sqe.Addr3 = 0
	sqe.Pad2 = 0
	return nil
}
