//go:build linux && amd64

package core

import (
	"errors"
	"fmt"
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

	plainConnStateFree    = 0
	plainConnStateReading = 1
	plainConnStateWriting = 2
	plainConnStateClosing = 3

	plainAcceptDepth       = 4
	plainWorkerRingEntries = 4096
	plainReadMinFree       = 4096
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
	writeBorrowed bool
	keepAlive     bool
	readN         int
	writeN        int
	writeSent     int
	requestCount  uint32
	lastActive    int64
	remoteAddr    string
	readBuf       []byte
	writeBuf      []byte
	req           Request
	resp          Response
	consumed      int
	closeAfter    bool
}

type plainUringWorker struct {
	id              int
	listenerFD      int
	wakeupReadFD    int
	wakeupWriteFD   int
	handoffs        chan plainAcceptedConn
	ring            *ioUring
	server          *Server
	connections     []plainWorkerConn
	freeHead        int32
	completions     [64]ioUringCqe
	timeoutCursor   int
	acceptBackfill  int64
	nextAcceptRetry int64
	localReqs       uint64
	wakeupBuf       [8]byte
	wakeupIovec     syscall.Iovec
	wakeArmed       bool
	parking         bool
	active          atomic.Int64
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
		return false, nil
	}
	defer backend.closeResources()
	log.Printf("[INFO] io_uring plain worker mode active on Linux amd64: workers=%d accept-shards=%d conns-per-shard=%d", len(backend.workers), minInt(len(listeners), len(backend.workers)), ioUringConnsPerShard)
	backend.start()
	return true, backend.wait()
}

func newPlainUringBackend(s *Server, listeners []net.Listener) (*plainUringBackend, error) {
	if len(listeners) == 0 {
		return nil, errors.New("no listeners")
	}
	shards, _ := ioUringShardLayout()
	workerCount := plainUringWorkerCount(shards)
	acceptShards := minInt(len(listeners), workerCount)
	backend := &plainUringBackend{
		server:  s,
		workers: make([]*plainUringWorker, 0, workerCount),
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
		ring, err := newOwnedIOUring(plainWorkerRingEntries)
		if err != nil {
			return nil, err
		}
		wakeupPair, err := openWakePipeALOS()
		if err != nil {
			ring.close()
			return nil, err
		}
		worker := &plainUringWorker{
			id:            workerID,
			listenerFD:    -1,
			wakeupReadFD:  wakeupPair[0],
			wakeupWriteFD: wakeupPair[1],
			handoffs:      make(chan plainAcceptedConn, ioUringConnsPerShard),
			ring:          ring,
			server:        s,
			connections:   make([]plainWorkerConn, ioUringConnsPerShard),
			freeHead:      0,
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
			backend.errCh <- worker.run(backend)
		}()
	}
}

func (backend *plainUringBackend) wait() error {
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

func (backend *plainUringBackend) closeResources() {
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

func (worker *plainUringWorker) initConnections() {
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

func (worker *plainUringWorker) run(backend *plainUringBackend) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer worker.flushReqStats()
	if err := worker.ring.enable(); err != nil {
		return err
	}
	if err := worker.fillAccepts(MonotonicNanotime()); err != nil {
		return err
	}
	if worker.listenerFD >= 0 {
		if err := worker.armWake(); err != nil {
			return err
		}
		if _, err := worker.ring.submitAndWait(0); err != nil {
			return err
		}
	}
	lastSweep := MonotonicNanotime()
	for {
		if worker.server.doneClosed() {
			return nil
		}
		now := MonotonicNanotime()
		if err := worker.drainHandoffs(now); err != nil {
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
			if err := worker.handleCompletion(backend, worker.completions[i], nowTime); err != nil {
				if errors.Is(err, errPlainWorkerPark) {
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
		if err := worker.fillAccepts(nowTime); err != nil {
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

func (worker *plainUringWorker) handleCompletion(backend *plainUringBackend, cqe ioUringCqe, now int64) error {
	op := plainDecodeOp(cqe.UserData)
	connIndex := plainDecodeConn(cqe.UserData)
	generation := plainDecodeGeneration(cqe.UserData)
	switch op {
	case plainUringOpAccept:
		return worker.handleAccept(backend, cqe.Res, now)
	case plainUringOpWake:
		return worker.handleWake(now, cqe.Res)
	case plainUringOpRead, plainUringOpWrite, plainUringOpClose:
		if connIndex < 0 || connIndex >= len(worker.connections) {
			return nil
		}
		conn := &worker.connections[connIndex]
		if conn.fd < 0 || conn.generation != generation {
			return nil
		}
		if conn.state == plainConnStateClosing && op != plainUringOpClose {
			return nil
		}
		switch op {
		case plainUringOpRead:
			return worker.handleRead(conn, cqe.Res, now)
		case plainUringOpWrite:
			return worker.handleWrite(conn, cqe.Res, now)
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
			atomic.StoreInt64(&worker.nextAcceptRetry, now+int64(5*time.Millisecond))
			return nil
		}
		return fmt.Errorf("plain io_uring accept failed: %w", syscall.Errno(-result))
	}
	atomic.StoreInt64(&worker.nextAcceptRetry, 0)
	fd := int(result)
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	backend.dispatchAccepted(worker, fd, now)
	return nil
}

func (worker *plainUringWorker) handleRead(conn *plainWorkerConn, result int32, now int64) error {
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
	return worker.processRequests(conn)
}

func (worker *plainUringWorker) processRequests(conn *plainWorkerConn) error {
	maxRead := worker.server.config.MaxReadSize
	if maxRead <= 0 {
		maxRead = 2 << 20
	}
	for {
		if fastResp, consumed, closeConn, ok := worker.server.matchPlainRootFastRequest(conn.readBuf[:conn.readN]); ok {
			conn.requestCount++
			worker.bumpReqStats()
			return worker.queuePrebuiltResponse(conn, fastResp, !closeConn, consumed)
		}

		conn.req.resetFastH1()
		headerEnd, contentLength, hasContentLength, closeConn, badTransferEncoding, ok := ParseH1RequestHead(conn.readBuf[:conn.readN], &conn.req)
		if !ok {
			return worker.queueRead(conn)
		}
		consumed := headerEnd
		if badTransferEncoding {
			conn.resp.Reset()
			conn.resp.Status(400).String("Bad Request")
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
			if bodyEnd > conn.readN {
				if !worker.ensureReadCapacity(conn, bodyEnd-conn.readN, int(maxRead)) {
					return worker.closeConnection(conn)
				}
				return worker.queueRead(conn)
			}
			conn.req.Body = conn.readBuf[headerEnd:bodyEnd]
			consumed = bodyEnd
		}
		conn.requestCount++
		worker.bumpReqStats()
		conn.resp.resetFastH1()
		conn.req.StreamWriter = nil
		conn.req.conn = nil
		conn.req.server = worker.server
		conn.req.Host = conn.req.cachedHost
		conn.req.RemoteAddr = conn.remoteAddr
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
			conn.resp.Status(500).String("Streaming/Hijack unsupported in plain io_uring worker backend")
			closeConn = true
		}
		if worker.server.config.MaxWriteSize > 0 && int64(conn.resp.BodyLen()) > worker.server.config.MaxWriteSize {
			conn.resp.resetFastH1()
			conn.resp.Status(500).String("Response Too Large")
			closeConn = true
		}
		return worker.queueResponse(conn, !closeConn, consumed)
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

func (worker *plainUringWorker) queueResponse(conn *plainWorkerConn, keepAlive bool, consumed int) error {
	conn.keepAlive = keepAlive
	conn.closeAfter = !keepAlive
	conn.consumed = consumed
	base := conn.writeBuf[:0]
	if conn.writeBorrowed {
		base = nil
		conn.writeBorrowed = false
	}
	buf := appendPlainResponse(&conn.resp, base)
	conn.writeBuf = buf
	conn.writeN = len(buf)
	conn.writeSent = 0
	worker.compactReadBuffer(conn, consumed)
	if conn.writeN == 0 {
		return worker.closeConnection(conn)
	}
	conn.state = plainConnStateWriting
	if err := worker.ring.prepSendUser(conn.fd, conn.writeBuf[:conn.writeN], plainEncodeUserData(plainUringOpWrite, int(conn.index), conn.generation)); err != nil {
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
	worker.compactReadBuffer(conn, consumed)
	if conn.writeN == 0 {
		return worker.closeConnection(conn)
	}
	conn.state = plainConnStateWriting
	if err := worker.ring.prepSendUser(conn.fd, conn.writeBuf[:conn.writeN], plainEncodeUserData(plainUringOpWrite, int(conn.index), conn.generation)); err != nil {
		return worker.closeConnection(conn)
	}
	return nil
}

func (worker *plainUringWorker) handleWrite(conn *plainWorkerConn, result int32, now int64) error {
	if result < 0 {
		err := syscall.Errno(-result)
		if isIOUringTransient(err) {
			remaining := conn.writeBuf[conn.writeSent:conn.writeN]
			return worker.ring.prepSendUser(conn.fd, remaining, plainEncodeUserData(plainUringOpWrite, int(conn.index), conn.generation))
		}
		return worker.closeConnection(conn)
	}
	conn.lastActive = now
	conn.writeSent += int(result)
	if conn.writeSent < conn.writeN {
		remaining := conn.writeBuf[conn.writeSent:conn.writeN]
		return worker.ring.prepSendUser(conn.fd, remaining, plainEncodeUserData(plainUringOpWrite, int(conn.index), conn.generation))
	}
	if conn.closeAfter {
		return worker.closeConnection(conn)
	}
	if conn.readN > 0 {
		return worker.processRequests(conn)
	}
	return worker.queueRead(conn)
}

func (worker *plainUringWorker) fillAccepts(now int64) error {
	if atomic.LoadInt64(&worker.acceptBackfill) <= 0 || worker.server.doneClosed() || worker.listenerFD < 0 {
		return nil
	}
	retryAt := atomic.LoadInt64(&worker.nextAcceptRetry)
	if retryAt != 0 && now < retryAt {
		return nil
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
	conn.state = plainConnStateReading
	conn.readN = 0
	conn.writeN = 0
	conn.writeSent = 0
	conn.requestCount = 0
	conn.keepAlive = false
	conn.closeAfter = false
	conn.writeBorrowed = false
	conn.lastActive = now
	if conn.readBuf == nil {
		conn.readBuf = make([]byte, 0, 8192)
	}
	if conn.writeBuf == nil {
		conn.writeBuf = make([]byte, 0, 16384)
	}
	worker.active.Add(1)
	worker.server.activeConns.Add(1)
	Stats.ActiveConns.Add(1)
	Stats.TotalConns.Add(1)
	Stats.H1Conns.Add(1)
	return worker.queueRead(conn)
}

func (worker *plainUringWorker) queueRead(conn *plainWorkerConn) error {
	if conn.fd < 0 || conn.state == plainConnStateClosing {
		return nil
	}
	if !worker.ensureReadCapacity(conn, plainReadMinFree, int(defaultInt64(worker.server.config.MaxReadSize, 2<<20))) {
		return worker.closeConnection(conn)
	}
	conn.state = plainConnStateReading
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
	conn.state = plainConnStateClosing
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
	conn.state = plainConnStateFree
	conn.readN = 0
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
	conn.req.resetFastH1()
	conn.resp.resetFastH1()
	conn.readBuf = conn.readBuf[:0]
	if conn.writeBorrowed {
		conn.writeBorrowed = false
		conn.writeBuf = nil
	} else {
		conn.writeBuf = conn.writeBuf[:0]
	}
}

func (worker *plainUringWorker) acquireConnection() *plainWorkerConn {
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
	idleTimeout := worker.server.config.IdleTimeout
	if idleTimeout <= 0 || len(worker.connections) == 0 {
		return
	}
	deadline := idleTimeout.Nanoseconds()
	for budget := 64; budget > 0; budget-- {
		conn := &worker.connections[worker.timeoutCursor]
		if conn.fd >= 0 && conn.state != plainConnStateClosing && now-conn.lastActive > deadline {
			_ = worker.closeConnection(conn)
		}
		worker.timeoutCursor++
		if worker.timeoutCursor >= len(worker.connections) {
			worker.timeoutCursor = 0
		}
	}
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

func plainUringWorkerCount(maxShards int) int {
	workers := runtime.GOMAXPROCS(0) + runtime.GOMAXPROCS(0)/2
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
	return worker.ring.prepReadvUser(worker.wakeupReadFD, &worker.wakeupIovec, plainEncodeUserData(plainUringOpWake, 0, 0))
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
	fds := []int{0, 0}
	if err := syscall.Pipe2(fds, syscall.O_CLOEXEC); err != nil {
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

func defaultInt64(value int64, fallback int64) int64 {
	if value > 0 {
		return value
	}
	return fallback
}

func (ring *ioUring) prepAcceptUser(fd int, userData uint64, flags uint32) error {
	sqe, err := ring.getSqe()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpAccept
	sqe.FD = int32(fd)
	sqe.OpFlags = flags
	sqe.UserData = userData
	return nil
}

func (ring *ioUring) prepRecvUser(fd int, buf []byte, userData uint64) error {
	return ring.prepRecvUserWithFlags(fd, buf, userData, false)
}

func (ring *ioUring) prepRecvUserWithFlags(fd int, buf []byte, userData uint64, pollFirst bool) error {
	sqe, err := ring.getSqe()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpRecv
	if pollFirst {
		sqe.Ioprio = ioUringPollFirst
	}
	sqe.FD = int32(fd)
	sqe.Addr = uint64(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
	sqe.Len = uint32(len(buf))
	sqe.UserData = userData
	return nil
}

func (ring *ioUring) prepSendUser(fd int, buf []byte, userData uint64) error {
	return ring.prepSendUserWithFlags(fd, buf, userData, false)
}

func (ring *ioUring) prepSendUserWithFlags(fd int, buf []byte, userData uint64, pollFirst bool) error {
	sqe, err := ring.getSqe()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpSend
	if pollFirst {
		sqe.Ioprio = ioUringPollFirst
	}
	sqe.FD = int32(fd)
	sqe.Addr = uint64(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
	sqe.Len = uint32(len(buf))
	sqe.UserData = userData
	return nil
}

func (ring *ioUring) prepCloseUser(fd int, userData uint64) error {
	sqe, err := ring.getSqe()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpClose
	sqe.FD = int32(fd)
	sqe.UserData = userData
	return nil
}

func (ring *ioUring) prepReadvUser(fd int, iovec *syscall.Iovec, userData uint64) error {
	sqe, err := ring.getSqe()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpReadv
	sqe.FD = int32(fd)
	sqe.Addr = uint64(uintptr(unsafe.Pointer(iovec)))
	sqe.Len = 1
	sqe.UserData = userData
	return nil
}
