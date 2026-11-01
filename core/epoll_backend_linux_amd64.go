//go:build linux && amd64

package core

import (
	"crypto/x509"
	"fmt"
	"net"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const (
	epollConnSlabSize         = 128
	epollEventBatch           = 512
	epollListenBacklog        = 4096
	epollShrinkSlackSlabs     = 3
	epollBufShrinkThreshold   = 32 << 10
	epollNotSentLowat         = 8192
	epollWorkerBufStackMax    = 256
	epollWorkerWriteBufMaxCap = 16 << 10
)

const (
	epollActionNeedRead = iota
	epollActionCloseAfterFlush
	// epollActionProxyInFlight means an upstream exchange owns this connection
	// until it completes: nothing may flush, recycle or close it meanwhile.
	epollActionProxyInFlight
	// epollActionDetached means a handler took the socket over on the event
	// loop thread; the connection object goes back to the pool.
	epollActionDetached
)

type epollConn struct {
	fd            int
	generation    uint32
	protocol      uint8
	closeAfter    bool
	outArmed      bool
	outRegistered bool
	readScratch   bool
	tls           bool
	tlsVersion    uint16
	dispatching   bool
	readPending   bool
	peerHup       bool
	inputEOF      bool
	flushQueued   bool
	ipHeld        bool
	inFlight      int
	readN         int
	writeSent     int
	h1Off         int
	deadline      int64
	readBuf       []byte
	writeBuf      []byte
	bodyOut       []byte
	remoteAddr    string
	ipKey         string
	req           Request
	h1Cancel      cancelSlot
	resp          Response
	h2            tlsWorkerH2State
	slab          *epollSlab

	h2Streaming     map[uint32]*epollH2StreamWriter
	h2Draining      int
	h2EndedInFlight int
	h2PumpDue       bool
	inTLSFrameDrain bool
	h2BodyIn        map[uint32]*h2BodyIn

	h1DispatchGen   uint32
	h1ContinueSent  bool
	h1DispatchClose bool
	h1DispatchFast  bool
	h1InlineSeq     uint64
	h1Handler       HandlerFunc
	h1Route         *inlineRoute
	h1AsyncFn       func()
	h1DoneNext      *epollConn
	h1Body          []byte
	h1BodyOff       int
	h1Stream        *epollH1StreamWriter
	h1OutKeepAlive  bool
	h1OutComplete   bool
	h1ResumeDue     bool
	h1FirstSegSent  bool
	h1In            *h1BodyIn
	lingering       bool
	lingerLeft      int

	phase        uint8
	selectedALPN string
	hsReader     *TrafficAEAD
	appReader    *TrafficAEAD
	appWriter    *TrafficAEAD
	plainBuf     []byte
	appBuf       []byte
	appBufOff    int
	clientHello  *ParsedClientHello
	expectedFin  [64]byte
	expectedFinN int
	tls12        *tls12State
	tlsRetry     *tls13Retry
	ticket       *pendingTicket
	clientAuth   *tls13ClientAuth
	tlsAlertSent bool
	peerCerts    []*x509.Certificate
	tlsCertEntry *CertEntry

	tlsPeerClosed     bool
	tlsUselessRecords uint8
	cipherOff         int

	reqBodyCopy     []byte
	h1BodyAccounted int64
	h1BodyDeadline  int64
	chunkScanPos    int
	h2GoingAway     bool

	h1AttacherFn   func(*Request) net.Conn
	takeoverPinned bool
	takeoverParked bool
	unpinNext      *epollConn
	connLimiter    *ConnectionLimiter

	// proxyEx is the in-flight upstream exchange for this connection, and
	// pausedBackend the backend socket whose reads were disarmed because this
	// client fell behind while a response was being relayed.
	proxyEx       *proxyExchange
	pausedBackend *backendConn
	tunnelBE      *backendConn

	h2ProxyBuffered int64
	tunnelPaused    bool

	ws        *wsLoopConn
	wsPending *wsLoopConn

	worker *epollWorker
}

type epollSlab struct {
	conns []epollConn
	free  int
}

type epollConnPool struct {
	slabs      []*epollSlab
	free       []*epollConn
	floorSlabs int
	batchSize  int
	parked     int
	server     *Server
}

func (p *epollConnPool) slabSize() int {
	if p.batchSize > 0 {
		return p.batchSize
	}
	return epollConnSlabSize
}

func (p *epollConnPool) addSlab() {
	bs := p.slabSize()
	s := &epollSlab{conns: make([]epollConn, bs), free: bs}
	for i := range s.conns {
		c := &s.conns[i]
		c.slab = s
		p.free = append(p.free, c)
	}
	p.slabs = append(p.slabs, s)
}

func (p *epollConnPool) prewarm(minConns int) {
	bs := p.slabSize()
	need := (minConns + bs - 1) / bs
	if need < 1 {
		need = 1
	}
	p.floorSlabs = need
	for len(p.slabs) < need {
		p.addSlab()
	}
	for i := 0; i < minConns; i++ {
		releaseEpollReadBuf(make([]byte, epollReadBufCap))
	}
}

func (p *epollConnPool) get() *epollConn {
	if len(p.free) == 0 {
		p.addSlab()
	}
	c := p.free[len(p.free)-1]
	p.free = p.free[:len(p.free)-1]
	c.slab.free--
	return c
}

func (p *epollConnPool) slotsHeld() int {
	return len(p.slabs)*p.slabSize() - len(p.free) - p.parked
}

func shrinkEpollBuf(b []byte) []byte {
	if cap(b) > epollBufShrinkThreshold {
		return nil
	}
	return b[:0]
}

func (c *epollConn) releaseClientHello() {
	if c.clientHello != nil {
		c.clientHello.Reset()
		clientHelloPool.Put(c.clientHello)
		c.clientHello = nil
	}
}

func (p *epollConnPool) put(c *epollConn) {
	p.releaseConnSlot()
	p.recycle(c)
}

func (p *epollConnPool) releaseConnSlot() {
	if p.server != nil {
		p.server.releaseTrackedConn()
		Stats.ActiveConns.Add(-1)
	}
}

func (p *epollConnPool) recycle(c *epollConn) {
	if c.ipHeld {
		if p.server != nil {
			p.server.perIPConnLimiter.Load().release(c.ipKey)
		}
		c.ipHeld = false
		c.ipKey = ""
	}
	if !c.readScratch {
		releaseEpollReadBuf(c.readBuf)
	}
	c.readScratch = false
	c.readBuf = nil
	releaseIOBuf(c.writeBuf)
	c.writeBuf = nil
	releaseIOBuf(c.appBuf)
	c.appBuf = nil
	releaseIOBuf(c.plainBuf)
	c.plainBuf = nil
	c.reqBodyCopy = shrinkEpollBuf(c.reqBodyCopy)
	c.releaseH1BodyBudget()
	c.req.Body = nil
	c.resp.resetFastH1()
	if c.h2.decoder != nil {
		HpackDecoderPool.Put(c.h2.decoder)
		c.h2.decoder = nil
	}
	c.releaseClientHello()
	c.deadline = 0
	p.free = append(p.free, c)
	c.slab.free++
	if len(p.slabs) > p.floorSlabs && len(p.free) >= p.slabSize()*epollShrinkSlackSlabs {
		p.shrinkOne()
	}
}

func (c *epollConn) reserveH1BodyBudget(srv *Server, received int) bool {
	if int64(received) <= c.h1BodyAccounted {
		return true
	}
	if !srv.tryReserveBodyBytes(received - int(c.h1BodyAccounted)) {
		return false
	}
	c.h1BodyAccounted = int64(received)
	return true
}

func (c *epollConn) releaseH1BodyBudget() {
	if c.h1BodyAccounted <= 0 {
		return
	}
	if c.worker != nil && c.worker.server != nil {
		c.worker.server.releaseBodyBytes(c.h1BodyAccounted)
	}
	c.h1BodyAccounted = 0
}

func (p *epollConnPool) shrinkOne() {
	bs := p.slabSize()
	victim := -1
	for i := len(p.slabs) - 1; i >= 0; i-- {
		if p.slabs[i].free == bs {
			victim = i
			break
		}
	}
	if victim < 0 {
		return
	}
	vs := p.slabs[victim]
	filtered := p.free[:0]
	for _, c := range p.free {
		if c.slab != vs {
			filtered = append(filtered, c)
		}
	}
	for i := len(filtered); i < len(p.free); i++ {
		p.free[i] = nil
	}
	p.free = filtered
	p.slabs = append(p.slabs[:victim], p.slabs[victim+1:]...)
}

type epollWorker struct {
	server          *Server
	bytesIn         uint64
	bytesOut        uint64
	reqs            uint64
	acceptedConns   uint64
	epfd            int
	listenerFD      int
	wakeFd          int
	coreID          int
	spawned         int
	tlsMode         bool
	conns           []*epollConn
	pool            epollConnPool
	events          []unix.EpollEvent
	taskCh          chan func(*epollWorker)
	handlers        *handlerPool
	taskPending     atomic.Bool
	h1Done          atomic.Pointer[epollConn]
	h2Done          atomic.Pointer[H2Stream]
	takeoverUnpins  atomic.Pointer[epollConn]
	parked          atomic.Bool
	wakeBuf         [8]byte
	flushList       []*epollConn
	h2FinishScratch []byte
	h2Direct        h2DirectScratch
	readTO          int64
	headerTO        int64
	handshakeTO     int64
	writeTO         int64
	idleTO          int64
	maxHeaderSize   int
	maxBodySize     int64
	streamBodyAbove int64
	limitsGen       uint64
	discardBuf      []byte
	maxPendingWrite int
	lastSweep       int64
	acceptResumeAt  int64
	acceptBackoff   time.Duration
	draining        bool
	drainExpired    bool
	be              beLoop
	beCfg           fpConfig
	exFree          *Exchange
	pxFree          *proxyExchange
	beScratch       []byte
	hdrStrings      [][2]string
	sendIov         [2]unix.Iovec
	sendMsg         unix.Msghdr
	acceptAddr      unix.RawSockaddrAny
	acceptAddrLen   uint32
	sockoptInherit  uint8
	promote         promoteArena
	readBufs        epollBufStack
	writeBufs       epollBufStack
	readScratchBuf  []byte
	wsWake          atomic.Pointer[wsLoopConn]
	wsLive          int
	inlineRun       atomic.Uint64
	inlineSeq       uint64
	inlineRoute     uintptr
	inlineQ         []inlineTask
	inlineHead      int
	inlineDeadline  int64
	inlineSeen      uint64
	inlineAll       bool
	inlineRan       bool
	resumed         bool
	loopErr         chan<- error
}

// ListenAndServeEpollH2 listens on addr and serves plain HTTP/1.1 and
// HTTP/2-via-prior-knowledge connections using the epoll backend, blocking
// until an error occurs.
func (s *Server) ListenAndServeEpollH2(addr string) error {
	return s.serveEpoll(addr, false)
}

// ListenAndServeEpollTLS listens on addr and serves TLS-terminated HTTP/1.1
// and HTTP/2 connections using the epoll backend, blocking until an error
// occurs.
func (s *Server) ListenAndServeEpollTLS(addr string) error {
	return s.serveEpoll(addr, true)
}

func (s *Server) epollListenerCount() int {
	if s.config.Listeners > 0 {
		return s.config.Listeners
	}
	return autoWorkerCount()
}

func (s *Server) serveEpoll(addr string, tlsMode bool) error {
	listenerFDs, err := s.openEpollListeners(addr, epollListen)
	if err != nil {
		return err
	}
	errCh, err := s.startEpollWorkers(listenerFDs, tlsMode)
	if err != nil {
		return err
	}
	return <-errCh
}

func (s *Server) openEpollListeners(addr string, open func(string) (int, error)) ([]int, error) {
	count := s.epollListenerCount()
	listenerFDs := make([]int, 0, count)
	for i := 0; i < count; i++ {
		lfd, err := open(addr)
		if err != nil {
			closeEpollListeners(listenerFDs)
			return nil, fmt.Errorf("epoll listen %s: %w", addr, err)
		}
		listenerFDs = append(listenerFDs, lfd)
	}
	return listenerFDs, nil
}

func closeEpollListeners(listenerFDs []int) {
	for _, lfd := range listenerFDs {
		_ = unix.Close(lfd)
	}
}

func (s *Server) startEpollWorkers(listenerFDs []int, tlsMode bool) (<-chan error, error) {
	s.adoptAssignedEngines()
	s.Router.Build()
	s.computeFastDispatch()
	minPerWorker := 0
	if s.config.MinPrealloc > 0 {
		minPerWorker = (s.config.MinPrealloc + len(listenerFDs) - 1) / len(listenerFDs)
	}
	for _, lfd := range listenerFDs {
		if err := activateEpollListener(lfd); err != nil {
			closeEpollListeners(listenerFDs)
			return nil, fmt.Errorf("epoll listen: %w", err)
		}
	}
	workers := make([]*epollWorker, 0, len(listenerFDs))
	for i, lfd := range listenerFDs {
		w, err := newEpollWorkerOnListener(s, lfd, minPerWorker)
		if err != nil {
			for _, built := range workers {
				built.closeUnstarted()
			}
			closeEpollListeners(listenerFDs[i+1:])
			return nil, err
		}
		w.coreID = i % runtime.NumCPU()
		w.tlsMode = tlsMode
		workers = append(workers, w)
	}
	go s.epollScavenger()
	errCh := make(chan error, len(workers))
	for _, w := range workers {
		w.loopErr = errCh
		go func() {
			if w.inlineAll || s.Router.hasInlineRoutes() {
				s.inlineWatch.add(w)
			}
			if err := w.run(); err != errEpollLoopHandedOff {
				errCh <- err
			}
		}()
	}
	return errCh, nil
}

func (w *epollWorker) closeUnstarted() {
	w.server.removeShutdownWaker(w)
	w.handlers.close()
	_ = unix.Close(w.listenerFD)
	_ = unix.Close(w.wakeFd)
	_ = unix.Close(w.epfd)
}

func (s *Server) epollScavenger() {
	const (
		freeThrottleNs  = 10 * int64(time.Second)
		idleRatePerTick = 40
		connActive      = 32
		minReturnable   = 24 << 20
		maxReclaims     = 2
		tick            = 100 * time.Millisecond
		idleRunEvery    = 2 * time.Second
		ticksPerIdleRun = int(idleRunEvery / tick)
		largeQuietHeld  = 64 << 20
		nudgeSpacingNs  = int64(250 * time.Millisecond)
		nudgePhaseGapNs = 2 * int64(time.Second)
	)
	var lastFree, lastNudge int64
	var lastReqs, rate uint64
	var armed bool
	var reclaims int
	var ms runtime.MemStats
	var nudge largeBufNudge
	for ticks := 1; ; ticks++ {
		select {
		case <-s.done:
			return
		default:
		}
		turbo.Sleep(tick)
		now := turbo.UnixNano()
		quiet := nudge.observe(largeBufs.getBytes.Load())
		if !quiet && nudge.retrying() {
			nudge.settle()
		}
		if quiet && now-lastNudge >= nudgeSpacingNs && (nudge.retrying() || now-lastNudge >= nudgePhaseGapNs) {
			runtime.ReadMemStats(&ms)
			if ms.HeapSys-ms.HeapReleased <= largeQuietHeld {
				nudge.settle()
			} else {
				debug.FreeOSMemory()
				lastFree, lastNudge = now, now
				runtime.ReadMemStats(&ms)
				if ms.HeapInuse <= largeQuietHeld {
					nudge.settle()
				} else {
					nudge.retry()
				}
			}
		}
		if ticks%ticksPerIdleRun != 0 {
			continue
		}
		cur := s.activeConns.Load()
		reqs := Stats.TotalReqs.Load()
		if reqs >= lastReqs {
			rate = reqs - lastReqs
		} else {
			rate = 0
		}
		lastReqs = reqs

		if rate > idleRatePerTick || cur > connActive {
			armed = true
			reclaims = 0
			continue
		}
		if !armed || reclaims >= maxReclaims {
			continue
		}
		if now-lastFree < freeThrottleNs {
			continue
		}
		runtime.ReadMemStats(&ms)
		heldIdle := int64(ms.HeapIdle) - int64(ms.HeapReleased)
		if heldIdle <= minReturnable && ms.HeapInuse <= minReturnable {
			armed = false
			continue
		}
		debug.FreeOSMemory()
		lastFree = now
		reclaims++
		if reclaims >= maxReclaims {
			armed = false
		}
	}
}

func newEpollWorker(s *Server, addr string, minPrealloc int) (*epollWorker, error) {
	lfd, err := epollListen(addr)
	if err != nil {
		return nil, fmt.Errorf("epoll listen %s: %w", addr, err)
	}
	return newEpollWorkerOnListener(s, lfd, minPrealloc)
}

func newEpollWorkerOnListener(s *Server, lfd int, minPrealloc int) (*epollWorker, error) {
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		_ = unix.Close(lfd)
		return nil, fmt.Errorf("epoll create: %w", err)
	}
	ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(lfd)}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, lfd, &ev); err != nil {
		_ = unix.Close(lfd)
		_ = unix.Close(epfd)
		return nil, fmt.Errorf("epoll add listener: %w", err)
	}
	wfd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		_ = unix.Close(lfd)
		_ = unix.Close(epfd)
		return nil, fmt.Errorf("eventfd: %w", err)
	}
	wev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(wfd)}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, wfd, &wev); err != nil {
		_ = unix.Close(lfd)
		_ = unix.Close(epfd)
		_ = unix.Close(wfd)
		return nil, fmt.Errorf("epoll add wake: %w", err)
	}
	w := &epollWorker{
		server:     s,
		epfd:       epfd,
		listenerFD: lfd,
		wakeFd:     wfd,
		conns:      make([]*epollConn, 1024),
		events:     make([]unix.EpollEvent, epollEventBatch),
		taskCh:     make(chan func(*epollWorker), epollTaskQueueSize),
		handlers:   newHandlerPool(handlerPoolWorkersPerLoop),
		flushList:  make([]*epollConn, 0, 64),
		inlineAll:  s.inlineDispatchEnabled(),
	}
	w.pool.server = s
	w.pool.batchSize = s.preallocBatch()
	w.refreshLimits()
	w.maxPendingWrite = epollMaxPendingWriteDefault
	if s.config.MaxPendingWriteBytes > 0 {
		w.maxPendingWrite = int(s.config.MaxPendingWriteBytes)
	}
	w.pool.prewarm(minPrealloc)
	w.initBackendLoop()
	s.addShutdownWaker(w)
	return w, nil
}

func (w *epollWorker) wakeForShutdown() {
	var one uint64 = 1
	_, _ = unix.Write(w.wakeFd, (*[8]byte)(unsafe.Pointer(&one))[:])
}

func (c *epollConn) cancelH1(cause error) {
	if s := c.req.cancelSrc; s != nil {
		s.cancel(cause)
	}
}

func (c *epollConn) cancelInFlight(cause error) {
	c.cancelH1(cause)
	c.h2.cancelBusy(cause)
}

func (w *epollWorker) cancelInFlight(cause error) {
	w.postTask(func(w *epollWorker) {
		w.drainExpired = true
		for _, c := range w.conns {
			if c != nil && c.fd >= 0 {
				c.cancelInFlight(cause)
			}
		}
	})
}

func (s *Server) preallocBatch() int {
	if s.config.PreallocBatch > 0 {
		return s.config.PreallocBatch
	}
	return epollConnSlabSize
}

const epollTaskQueueSize = 8192

func (w *epollWorker) postTask(fn func(*epollWorker)) {
	w.taskCh <- fn
	w.taskPending.Store(true)
	if w.parked.Load() {
		var one uint64 = 1
		_, _ = unix.Write(w.wakeFd, (*[8]byte)(unsafe.Pointer(&one))[:])
	}
}

func (w *epollWorker) pushH1Done(c *epollConn) {
	for {
		head := w.h1Done.Load()
		c.h1DoneNext = head
		if w.h1Done.CompareAndSwap(head, c) {
			break
		}
	}
	w.taskPending.Store(true)
	if w.parked.Load() {
		var one uint64 = 1
		_, _ = unix.Write(w.wakeFd, (*[8]byte)(unsafe.Pointer(&one))[:])
	}
}

func (w *epollWorker) drainTasks() {
	w.taskPending.Store(false)
	done := w.h1Done.Swap(nil)
	h2Done := w.h2Done.Swap(nil)
	for {
		select {
		case fn := <-w.taskCh:
			w.runTask(fn)
		default:
			w.finishH1Done(done)
			w.finishH2Done(h2Done)
			if w.takeoverUnpins.Load() != nil {
				w.runTakeoverUnpins()
			}
			if w.wsWake.Load() != nil {
				w.runWSWakes()
			}
			return
		}
	}
}

func (w *epollWorker) finishH1Done(head *epollConn) {
	var ordered *epollConn
	for c := head; c != nil; {
		next := c.h1DoneNext
		c.h1DoneNext = ordered
		ordered = c
		c = next
	}
	for ordered != nil {
		c := ordered
		ordered = c.h1DoneNext
		c.h1DoneNext = nil
		w.runH1Finish(c)
	}
}

func (w *epollWorker) runH1Finish(c *epollConn) {
	defer func() {
		if r := recover(); r != nil {
			w.server.reportPanic(nil, r)
		}
	}()
	c.finishH1Dispatch(w, c.h1DispatchGen, c.h1DispatchClose)
}

func (w *epollWorker) runTask(fn func(*epollWorker)) {
	defer func() {
		if r := recover(); r != nil {
			w.server.reportPanic(nil, r)
		}
	}()
	fn(w)
}

func (w *epollWorker) serviceConn(c *epollConn, evs uint32) {
	defer func() {
		if r := recover(); r != nil {
			w.server.reportPanic(nil, r)
			w.closeConn(c)
		}
	}()
	if evs&(unix.EPOLLERR|unix.EPOLLHUP) != 0 && evs&unix.EPOLLIN == 0 {
		w.closeConn(c)
		return
	}
	if evs&unix.EPOLLOUT != 0 && c.outArmed {
		if !w.flush(c) {
			return
		}
	}
	if evs&(unix.EPOLLIN|unix.EPOLLRDHUP) != 0 {
		w.readable(c, evs&unix.EPOLLRDHUP != 0)
	}
}

func epollListen(addr string) (int, error) {
	fd, err := epollBind(addr, true)
	if err != nil {
		return -1, err
	}
	if err := unix.Listen(fd, epollListenBacklog); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func epollReserve(addr string) (int, error) {
	return epollBind(addr, false)
}

func epollBind(addr string, reuseAddr bool) (int, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", addr)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if reuseAddr {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	setConnSockopts(fd)
	sa := &unix.SockaddrInet4{Port: tcpAddr.Port}
	if ip4 := tcpAddr.IP.To4(); ip4 != nil {
		copy(sa.Addr[:], ip4)
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func activateEpollListener(fd int) error {
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	return unix.Listen(fd, epollListenBacklog)
}

func (w *epollWorker) run() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err := w.loop()
	if err != errEpollLoopHandedOff {
		w.closeLoop()
	}
	return err
}

func (w *epollWorker) closeLoop() {
	w.flushStatsCounters()
	w.handlers.close()
	w.server.inlineWatch.remove(w)
	w.server.removeShutdownWaker(w)
	_ = unix.Close(w.wakeFd)
	_ = unix.Close(w.epfd)
}

func (w *epollWorker) loop() error {
	resumed := w.resumed
	w.resumed = false
	for {
		if !w.draining {
			select {
			case <-w.server.done:
				_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_DEL, w.listenerFD, nil)
				_ = unix.Close(w.listenerFD)
				w.listenerFD = -1
				w.draining = true
			default:
			}
		}
		w.flushStatsCounters()
		if w.draining {
			w.drainForShutdown()
			if !w.hasClientConns() && w.pool.slotsHeld() == 0 {
				return nil
			}
		}
		w.be.seq++
		n := 0
		acceptPending := resumed && !w.draining
		if !resumed {
			var err error
			n, err = w.waitEvents()
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				return fmt.Errorf("epoll wait: %w", err)
			}
		}
		resumed = false
		w.refreshLimits()
		w.inlineDeadline = turbo.Now() + int64(inlineBatchBudget)
		tasksPending := false
		for i := 0; i < n; i++ {
			fd := int(w.events[i].Fd)
			if fd == w.listenerFD {
				acceptPending = true
				continue
			}
			if fd == w.wakeFd {
				tasksPending = true
				continue
			}
			if w.events[i].Pad == epollFDClassBackend {
				w.backendEvent(fd, w.events[i].Events)
				continue
			}
			if fd < 0 || fd >= len(w.conns) {
				continue
			}
			c := w.conns[fd]
			if c == nil {
				continue
			}
			w.serviceConn(c, w.events[i].Events)
		}
		if tasksPending {
			_, _ = unix.Read(w.wakeFd, w.wakeBuf[:])
		}
		for round := 0; round < epollDispatchRounds && (tasksPending || w.spawned > 0 || w.inlineRan || w.taskPending.Load() || w.inlinePending()); round++ {
			tasksPending = false
			if w.spawned > 0 || w.inlineRan {
				w.spawned = 0
				w.inlineRan = false
				w.yieldToHandlers()
			}
			if w.inlinePending() {
				if !w.runInlineQueue() {
					return errEpollLoopHandedOff
				}
				w.inlineRan = true
			}
			if w.taskPending.Load() {
				w.drainTasks()
			}
		}
		if len(w.flushList) > 0 {
			w.flushPending()
		}
		if w.acceptResumeAt != 0 && w.resumeAcceptIfDue(turbo.UnixNano()) {
			acceptPending = true
		}
		if acceptPending {
			w.acceptLoop()
		}
		w.sweepDeadlines()
	}
}

// waitEvents blocks for readiness. The parked flag lets postTask skip the
// eventfd wake whenever the worker is not actually inside epoll_wait.
func (w *epollWorker) waitEvents() (int, error) {
	waitMs := epollSweepIntervalMs
	if w.be.liveConns > 0 {
		waitMs = min(waitMs, w.be.nextTimeoutMs())
	}
	if w.acceptResumeAt != 0 {
		waitMs = min(waitMs, w.msUntilAcceptResume(turbo.UnixNano()))
	}
	if w.draining {
		waitMs = min(waitMs, epollDrainPollMs)
	}
	w.parked.Store(true)
	if w.taskPending.Load() || w.inlinePending() {
		waitMs = 0
	}
	n, err := unix.EpollWait(w.epfd, w.events, waitMs)
	w.parked.Store(false)
	return n, err
}

func (c *epollConn) speaksH2() bool {
	return c.protocol == plainConnProtoH2 || c.phase == tlsConnPhaseH2Native
}

func (c *epollConn) unparsedInput() bool {
	if c.tls {
		return c.readN != 0 || c.appBufOff < len(c.appBuf) || (c.speaksH2() && c.h2.appBufOff < len(c.appBuf))
	}
	if c.speaksH2() {
		return c.readN != c.h2.appBufOff
	}
	return c.readN != 0
}

func (c *epollConn) bufferedInput() int {
	switch {
	case c.tls:
		return c.readN
	case c.speaksH2():
		return c.readN - c.h2.appBufOff
	default:
		return c.readN - c.h1Off
	}
}

func (c *epollConn) idle() bool {
	return c.fd >= 0 && c.inFlight == 0 && !c.dispatching && c.proxyEx == nil && c.tunnelBE == nil &&
		!c.unparsedInput() && !c.outArmed && c.writeSent == len(c.writeBuf) && len(c.bodyOut) == 0 &&
		len(c.h2.streams) == 0 && len(c.h2.sending) == 0
}

func (w *epollWorker) drainForShutdown() {
	now := turbo.UnixNano()
	for _, c := range w.conns {
		if c == nil || c.fd < 0 {
			continue
		}
		switch {
		case c.lingering:
			c.deadline = min(c.deadline, now+int64(epollShutdownLingerTimeout))
			if w.drainExpired || now > c.deadline {
				w.closeConn(c)
			}
		case w.drainExpired && !c.runsHandler():
			w.closeConn(c)
		case c.ws != nil:
			w.wsGoingAway(c)
		case c.speaksH2():
			w.goAwayForShutdown(c)
		case c.idle():
			w.closeAfterResponse(c)
		}
	}
}

func (c *epollConn) runsHandler() bool {
	return c.inFlight > 0 || c.dispatching
}

func (w *epollWorker) goAwayForShutdown(c *epollConn) {
	idle := c.idle()
	if c.h2GoingAway && !idle {
		return
	}
	if !c.h2GoingAway {
		c.h2GoingAway = true
		var goAway [h2FrameHeaderSize + 8]byte
		w.clientAppend(c, appendH2GoAwayFrame(goAway[:0], c.h2.lastStreamID, H2ErrNoError))
	}
	if idle {
		c.closeAfter = true
	}
	w.flush(c)
}

func (c *epollConn) refuseH2StreamGoingAway(streamID uint32, headerBlock []byte) bool {
	st := &c.h2
	headers, _, _, err := st.decoder.DecodeRequest(st.headersBuf[:0], headerBlock)
	st.headersBuf = headers[:0]
	if err != nil && err != errH2MalformedRequest && err != errH2HeaderListTooLarge {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrCompression)
		return true
	}
	c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrRefusedStream)
	return false
}

func (w *epollWorker) hasClientConns() bool {
	for _, c := range w.conns {
		if c != nil && c.fd >= 0 {
			return true
		}
	}
	return false
}

const (
	epollSweepIntervalMs = 1000
	epollDispatchRounds  = 64
)

func (w *epollWorker) flushStatsCounters() {
	if w.reqs != 0 {
		Stats.TotalReqs.Add(w.reqs)
		Stats.RawReqs.Add(w.reqs)
		w.reqs = 0
	}
	if w.acceptedConns != 0 {
		Stats.TotalConns.Add(w.acceptedConns)
		w.acceptedConns = 0
	}
	if w.bytesIn != 0 {
		Stats.BytesIn.Add(w.bytesIn)
		w.bytesIn = 0
	}
	if w.bytesOut != 0 {
		Stats.BytesOut.Add(w.bytesOut)
		w.bytesOut = 0
	}
}

func (w *epollWorker) refreshLimits() {
	gen := w.server.limitsGen.Load()
	if gen == w.limitsGen && w.maxHeaderSize != 0 {
		return
	}
	l := w.server.limits.Load()
	w.readTO = int64(l.ReadTimeout)
	w.headerTO = int64(l.headerTimeout())
	w.handshakeTO = int64(l.handshakeTimeout())
	w.writeTO = int64(l.WriteTimeout)
	w.idleTO = int64(l.IdleTimeout)
	w.maxHeaderSize = l.MaxHeaderSize
	w.maxBodySize = l.MaxBodySize
	w.streamBodyAbove = l.StreamBodyAbove
	w.limitsGen = gen
}

func (w *epollWorker) bodyTooLarge(n int64) bool {
	return w.maxBodySize > 0 && n > w.maxBodySize
}

func (w *epollWorker) sweepDeadlines() {
	if w.readTO == 0 && w.writeTO == 0 && w.idleTO == 0 && w.be.liveConns == 0 && w.wsLive == 0 {
		return
	}
	now := turbo.UnixNano()
	w.be.maybeSweep(now)
	if w.readTO == 0 && w.writeTO == 0 && w.idleTO == 0 && w.wsLive == 0 {
		return
	}
	if now-w.lastSweep < int64(epollSweepIntervalMs)*1_000_000 {
		return
	}
	w.lastSweep = now
	for fd := 0; fd < len(w.conns); fd++ {
		c := w.conns[fd]
		if c == nil || c.fd < 0 {
			continue
		}
		if c.deadline != 0 && now > c.deadline {
			w.closeConn(c)
			continue
		}
		if c.holdsIdleBuffers() && now-(c.deadline-w.idleTO) >= int64(epollSweepIntervalMs)*1_000_000 {
			w.releaseIdleBuffers(c)
		}
	}
}

func deadlineFrom(to int64) int64 {
	if to <= 0 {
		return 0
	}
	return turbo.UnixNano() + to
}

func (w *epollWorker) nextReadTimeout(c *epollConn) int64 {
	if c.tls && c.phase != tlsConnPhaseApplication && c.phase != tlsConnPhaseH2Native {
		return w.handshakeTO
	}
	if c.h1BodyAccounted > 0 || c.protocol == plainConnProtoH2 || c.phase == tlsConnPhaseH2Native {
		return w.readTO
	}
	return w.headerTO
}

func (w *epollWorker) yieldToHandlers() {
	runtime.UnlockOSThread()
	runtime.Gosched()
	runtime.LockOSThread()
}

func (w *epollWorker) markFlush(c *epollConn) {
	if c.flushQueued {
		return
	}
	c.flushQueued = true
	w.flushList = append(w.flushList, c)
}

func (w *epollWorker) flushPending() {
	for i := 0; i < len(w.flushList); i++ {
		c := w.flushList[i]
		w.flushList[i] = nil
		c.flushQueued = false
		if c.fd < 0 {
			continue
		}
		if c.h2PumpDue {
			c.h2PumpDue = false
			c.h2PumpAll(w)
		}
		if !w.flush(c) {
			continue
		}
		if c.h1ResumeDue {
			c.h1ResumeDue = false
			w.resumeConn(c)
			continue
		}
		if c.deadline == 0 && !c.closeAfter {
			if c.idleDrained() {
				c.deadline = w.wsQuietDeadline(c)
			} else if c.speaksH2() && c.outputSettled() {
				c.deadline = deadlineFrom(w.readTO)
			}
		}
	}
	w.flushList = w.flushList[:0]
}

func (c *epollConn) idleDrained() bool {
	return c.readN == 0 && c.outputSettled()
}

func (c *epollConn) outputSettled() bool {
	return c.inFlight == 0 && !c.dispatching && !c.outArmed && c.writeSent == len(c.writeBuf) && len(c.bodyOut) == 0
}

func (c *epollConn) holdsIdleBuffers() bool {
	return (c.readBuf != nil || c.writeBuf != nil) && c.deadline != 0 && !c.closeAfter && !c.lingering && c.idleDrained() && !c.tlsAppPending() &&
		c.proxyEx == nil && c.pausedBackend == nil && c.h1Body == nil && c.h1Stream == nil && !c.takeoverPinned && !c.takeoverParked && c.ws == nil
}

func (w *epollWorker) acceptLoop() {
	for {
		if w.server.shuttingDown.Load() {
			return
		}
		nfd, err := socketAccept(w.listenerFD, &w.acceptAddr, &w.acceptAddrLen)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if acceptResourceExhausted(err) {
				w.pauseAccept(turbo.UnixNano())
			}
			return
		}
		w.acceptBackoff = 0
		limits := w.server.limits.Load()
		if !w.admitAccepted(nfd, limits) {
			continue
		}
		w.acceptedConns++
		w.configureAccepted(nfd)
		c := w.pool.get()
		c.req.resetConnIdentity()
		c.fd = nfd
		c.worker = w
		c.protocol = plainConnProtoUnknown
		c.closeAfter = false
		c.outArmed = false
		c.outRegistered = false
		c.dispatching = false
		c.readPending = false
		c.peerHup = false
		c.inputEOF = false
		c.flushQueued = false
		c.h1ContinueSent = false
		c.h1FirstSegSent = false
		c.readN = 0
		c.writeSent = 0
		c.h1Off = 0
		c.chunkScanPos = 0
		c.h1BodyDeadline = 0
		c.h2GoingAway = false
		if w.tlsMode {
			c.deadline = deadlineFrom(w.handshakeTO)
		} else {
			c.deadline = deadlineFrom(w.headerTO)
		}
		c.remoteAddr = epollRemoteAddr(&w.acceptAddr)
		c.connLimiter = w.server.newConnLimiter()
		c.ipHeld = false
		c.ipKey = ""
		if limiter := w.server.perIPConnLimiter.Load(); limiter != nil && limits.MaxConnsPerIP > 0 && !w.server.trustedProxies.active {
			key := extractIP(c.remoteAddr)
			if !limiter.acquire(key, limits.MaxConnsPerIP) {
				c.fd = -1
				_ = unix.Close(nfd)
				w.pool.put(c)
				continue
			}
			c.ipHeld = true
			c.ipKey = key
		}
		c.writeBuf = c.writeBuf[:0]
		c.h2.appBufOff = 0
		c.tls = w.tlsMode
		c.tlsVersion = 0
		c.appBufOff = 0
		if c.appBuf != nil {
			c.appBuf = c.appBuf[:0]
		}
		if c.tls {
			c.phase = tlsConnPhaseClientHello
			c.hsReader = nil
			c.appReader = nil
			c.appWriter = nil
			c.tls12 = nil
			c.tlsRetry = nil
			c.ticket = nil
			c.clientAuth = nil
			c.tlsAlertSent = false
			c.peerCerts = nil
			c.tlsCertEntry = nil
			c.tlsPeerClosed = false
			c.tlsUselessRecords = 0
			c.cipherOff = 0
			c.selectedALPN = ""
		}
		for nfd >= len(w.conns) {
			w.conns = append(w.conns, make([]*epollConn, len(w.conns))...)
		}
		w.conns[nfd] = c
		ev := unix.EpollEvent{Events: uint32(unix.EPOLLIN|unix.EPOLLRDHUP) | uint32(unix.EPOLLET&0xffffffff), Fd: int32(nfd)}
		if err := unix.EpollCtl(w.epfd, unix.EPOLL_CTL_ADD, nfd, &ev); err != nil {
			w.conns[nfd] = nil
			_ = unix.Close(nfd)
			w.pool.put(c)
		}
	}
}

const (
	sockoptInheritUnknown = iota
	sockoptInheritYes
	sockoptInheritNo
)

func setConnSockopts(fd int) {
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, epollNotSentLowat)
}

func connSockoptsApplied(fd int) bool {
	noDelay, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY)
	if err != nil || noDelay == 0 {
		return false
	}
	lowat, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
	return err == nil && lowat == epollNotSentLowat
}

func (w *epollWorker) configureAccepted(fd int) {
	switch w.sockoptInherit {
	case sockoptInheritYes:
		return
	case sockoptInheritUnknown:
		if connSockoptsApplied(fd) {
			w.sockoptInherit = sockoptInheritYes
			return
		}
		w.sockoptInherit = sockoptInheritNo
	}
	setConnSockopts(fd)
}

func (w *epollWorker) admitAccepted(nfd int, limits *Limits) bool {
	active := w.server.activeConns.Add(1)
	Stats.ActiveConns.Add(1)
	if w.server.shuttingDown.Load() || (limits.MaxConns > 0 && active > limits.MaxConns) {
		w.server.releaseTrackedConn()
		Stats.ActiveConns.Add(-1)
		_ = unix.Close(nfd)
		return false
	}
	return true
}

const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

func acceptResourceExhausted(err error) bool {
	return err == unix.EMFILE || err == unix.ENFILE || err == unix.ENOBUFS || err == unix.ENOMEM
}

func (w *epollWorker) pauseAccept(now int64) {
	w.acceptBackoff = min(max(2*w.acceptBackoff, acceptBackoffMin), acceptBackoffMax)
	w.acceptResumeAt = now + int64(w.acceptBackoff)
	ev := unix.EpollEvent{Fd: int32(w.listenerFD)}
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_MOD, w.listenerFD, &ev)
}

func (w *epollWorker) resumeAcceptIfDue(now int64) bool {
	if now < w.acceptResumeAt {
		return false
	}
	w.acceptResumeAt = 0
	if w.listenerFD < 0 {
		return false
	}
	ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(w.listenerFD)}
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_MOD, w.listenerFD, &ev)
	return true
}

func (w *epollWorker) msUntilAcceptResume(now int64) int {
	if now >= w.acceptResumeAt {
		return 0
	}
	return int((w.acceptResumeAt-now)/int64(time.Millisecond)) + 1
}

func epollRemoteAddr(rsa *unix.RawSockaddrAny) string {
	if rsa.Addr.Family != unix.AF_INET {
		return ""
	}
	sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(rsa))
	port := (*[2]byte)(unsafe.Pointer(&sa4.Port))
	var buf [len("255.255.255.255:65535")]byte
	b := buf[:0]
	for i, octet := range sa4.Addr {
		if i > 0 {
			b = append(b, '.')
		}
		b = strconv.AppendUint(b, uint64(octet), 10)
	}
	b = append(b, ':')
	b = strconv.AppendUint(b, uint64(port[0])<<8|uint64(port[1]), 10)
	return string(b)
}

func (w *epollWorker) readable(c *epollConn, peerClosed bool) {
	for w.readOnce(c, peerClosed) {
	}
}

func (w *epollWorker) readOnce(c *epollConn, peerClosed bool) (readAgain bool) {
	if c.lingering {
		w.discardLingering(c)
		return false
	}
	if peerClosed {
		c.peerHup = true
	}
	if c.tunnelPaused {
		if peerClosed {
			w.closeConn(c)
			return false
		}
		c.readPending = true
		return false
	}
	if c.dispatching && !c.h1BodyWantsInput() {
		c.readPending = true
		if peerClosed {
			c.cancelH1(ErrClientGone)
		}
		return false
	}
	c.readPending = false
	if c.readBuf == nil {
		if w.canBorrowReadScratch(c) {
			c.readBuf, c.readScratch = w.readScratch(), true
		} else {
			c.readBuf = w.acquireReadBuf()
		}
	}
	if c.writeBuf == nil {
		c.writeBuf = w.acquireWriteBuf()
	}
	maxRead := w.server.effectiveReadCap()
	prevReadN := c.readN
	closed := false
	bufferFull := false
	for {
		if cap(c.readBuf)-c.readN < plainReadMinFree {
			c.compactH2ReadBuffer(true)
			if cap(c.readBuf)-c.readN < plainReadMinFree {
				if c.ws != nil {
					if !c.wsGrowReadBuf(maxRead) {
						bufferFull = true
						break
					}
				} else {
					grown, ok := growPlainReadBuffer(c.readBuf[:c.readN], plainReadMinFree, maxRead)
					if !ok {
						bufferFull = true
						break
					}
					c.readBuf, c.readScratch = grown[:cap(grown)], false
				}
			}
		}
		reqLen := cap(c.readBuf) - c.readN
		n, err := socketRecv(c.fd, c.readBuf[c.readN:cap(c.readBuf)])
		if n > 0 {
			w.bytesIn += uint64(n)
			c.readN += n
			if n < reqLen && !c.h1BodyDrainsToEOF() {
				break
			}
			if c.h1In != nil && c.readN >= h1BodyReadAhead {
				c.readPending = true
				break
			}
			continue
		}
		if n == 0 && err == nil {
			if c.h1BodyStreaming() {
				c.inputEOF = true
				break
			}
			closed = true
			break
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN {
			break
		}
		w.closeConn(c)
		return false
	}
	if prevReadN == 0 && c.readN > 0 {
		keepDeadline := c.tls && c.deadline != 0 && (c.phase != tlsConnPhaseApplication && c.phase != tlsConnPhaseH2Native || len(c.appBuf) > 0)
		if !keepDeadline {
			c.deadline = deadlineFrom(w.nextReadTimeout(c))
		}
	}
	if c.readScratch && c.protocol == plainConnProtoUnknown && c.readN > 0 && couldBeH2Preface(c.readBuf[:c.readN]) {
		c.ownReadBuf(w)
	}
	fullAt := c.bufferedInput()
	w.serviceBuffered(c, closed, peerClosed)
	if c.readScratch {
		w.settleReadScratch(c)
	}
	if w.abortStarvedBody(c) {
		return false
	}
	if !bufferFull || closed || c.fd < 0 || c.lingering {
		return false
	}
	if c.dispatching || c.tunnelPaused {
		c.readPending = true
		return false
	}
	if c.bufferedInput() < fullAt {
		return true
	}
	w.closeConn(c)
	return false
}

// resumeConn continues a connection after an asynchronous dispatch. A read
// edge seen while the handler ran is honoured with a fresh read; otherwise
// only already-buffered input is processed, which spares a syscall per
// request on the common path.
func (w *epollWorker) resumeConn(c *epollConn) {
	if c.readPending {
		w.readable(c, false)
		return
	}
	if c.readBuf == nil && c.tls {
		c.readBuf = w.acquireReadBuf()
	}
	if c.writeBuf == nil {
		c.writeBuf = w.acquireWriteBuf()
	}
	w.serviceBuffered(c, false, false)
}

func (w *epollWorker) canBorrowReadScratch(c *epollConn) bool {
	return !c.tls && c.ws == nil && (c.protocol == plainConnProtoH1 || c.protocol == plainConnProtoUnknown) && c.h1In == nil && c.proxyEx == nil && c.tunnelBE == nil &&
		w.server.proxy.Load() == nil && w.server.httpRouter.Load() == nil
}

func (w *epollWorker) readScratch() []byte {
	if w.readScratchBuf == nil {
		w.readScratchBuf = make([]byte, epollReadBufCap)
	}
	return w.readScratchBuf
}

func (w *epollWorker) settleReadScratch(c *epollConn) {
	if c.fd < 0 {
		c.readBuf, c.readScratch = nil, false
		return
	}
	if c.readN == c.h1Off && c.h1In == nil {
		c.readBuf, c.readScratch = nil, false
		c.readN, c.h1Off, c.chunkScanPos = 0, 0, 0
		return
	}
	c.ownReadBuf(w)
}

func (c *epollConn) ownReadBuf(w *epollWorker) {
	own := w.acquireReadBuf()
	if cap(own) < c.readN {
		own = make([]byte, c.readN)
	}
	own = own[:cap(own)]
	copy(own, c.readBuf[:c.readN])
	c.readBuf, c.readScratch = own, false
}

func (w *epollWorker) dropReadBuf(c *epollConn) {
	if c.readScratch {
		c.readScratch = false
	} else {
		w.releaseReadBuf(c.readBuf)
	}
	c.readBuf = nil
}

func (w *epollWorker) serviceBuffered(c *epollConn, closed, peerClosed bool) {
	if c.readN > 0 || c.tlsAppPending() {
		var action int
		if c.tls {
			action = c.epollProcessTLS(w.server)
		} else {
			action = c.epollProcess(w.server)
		}
		if action == epollActionDetached {
			if c.inFlight == 0 {
				w.putTakenOver(c)
			}
			return
		}
		if action == epollActionProxyInFlight {
			// The upstream exchange owns this connection now. Only a client
			// that actually went away may tear it down here.
			if closed {
				w.closeConn(c)
				return
			}
			c.deadline = 0
			return
		}
		if action == epollActionCloseAfterFlush {
			c.closeAfter = true
		}
		if c.dispatching && !c.closeAfter {
			if len(c.writeBuf) > c.writeSent || len(c.bodyOut) > 0 {
				w.markFlush(c)
			}
		} else if !w.flush(c) {
			return
		}
	} else if !c.dispatching && (c.writeSent < len(c.writeBuf) || len(c.bodyOut) > 0) {
		if !w.flush(c) {
			return
		}
	}
	if closed {
		w.closeConn(c)
		return
	}
	if c.fd < 0 {
		return
	}
	if c.inFlight > 0 || c.dispatching {
		c.deadline = 0
		if c.h1BodyWantsInput() {
			c.deadline = deadlineFrom(w.readTO)
		}
		return
	}
	if peerClosed || c.inputEOF {
		if !c.outArmed && c.writeSent == len(c.writeBuf) {
			w.closeConn(c)
			return
		}
		c.closeAfter = true
	}
	if c.readN == 0 && !c.outArmed && c.writeSent == len(c.writeBuf) {
		w.releaseIdleBuffers(c)
		c.deadline = w.wsQuietDeadline(c)
	}
}

func (w *epollWorker) releaseIdleBuffers(c *epollConn) {
	w.dropReadBuf(c)
	w.releaseWriteBuf(c.writeBuf)
	c.writeBuf = nil
	if c.appBuf != nil && len(c.appBuf) == 0 {
		w.releaseWriteBuf(c.appBuf)
		c.appBuf = nil
	}
	if c.plainBuf != nil && len(c.plainBuf) == 0 {
		w.releaseWriteBuf(c.plainBuf)
		c.plainBuf = nil
	}
	c.reqBodyCopy = shrinkEpollBuf(c.reqBodyCopy)
	c.req.Body = nil
	c.resp.resetFastH1()
}

type epollBufStack struct {
	bufs [][]byte
}

func (s *epollBufStack) pop() []byte {
	n := len(s.bufs)
	if n == 0 {
		return nil
	}
	b := s.bufs[n-1]
	s.bufs[n-1] = nil
	s.bufs = s.bufs[:n-1]
	return b
}

func (s *epollBufStack) push(b []byte) bool {
	if len(s.bufs) >= epollWorkerBufStackMax {
		return false
	}
	s.bufs = append(s.bufs, b)
	return true
}

func (w *epollWorker) acquireReadBuf() []byte {
	if b := w.readBufs.pop(); b != nil {
		return b[:cap(b)]
	}
	return acquireEpollReadBuf()
}

func (w *epollWorker) releaseReadBuf(b []byte) {
	if cap(b) == epollReadBufCap && w.readBufs.push(b) {
		return
	}
	releaseEpollReadBuf(b)
}

func (w *epollWorker) acquireWriteBuf() []byte {
	if b := w.writeBufs.pop(); b != nil {
		return b[:0]
	}
	return acquireIOBuf()
}

func (w *epollWorker) releaseWriteBuf(b []byte) {
	if cap(b) >= epollIOBufCap && cap(b) <= epollWorkerWriteBufMaxCap && w.writeBufs.push(b) {
		return
	}
	releaseIOBuf(b)
}

func (c *epollConn) tlsAppPending() bool {
	return c.tls && (c.appBufOff < len(c.appBuf) || c.tlsPeerClosed)
}

func couldBeH2Preface(b []byte) bool {
	if len(b) > H2PrefaceLen {
		b = b[:H2PrefaceLen]
	}
	return string(b) == string(H2ClientPreface[:len(b)])
}

func (c *epollConn) epollProcess(srv *Server) int {
	if c.protocol == plainConnProtoUnknown {
		avail := c.readN
		if couldBeH2Preface(c.readBuf[:avail]) && srv.http2Enabled() {
			if avail < H2PrefaceLen {
				return epollActionNeedRead
			}
			c.protocol = plainConnProtoH2
			c.h2.init(srv.h2HeaderTableSize(), srv.h2HeaderListLimit())
			c.deadline = deadlineFrom(c.worker.readTO)
			c.writeBuf = appendH2ServerSettingsFlight(c.writeBuf, srv)
			Stats.H2Conns.Add(1)
		} else {
			c.protocol = plainConnProtoH1
			Stats.H1Conns.Add(1)
		}
	}
	if c.protocol == plainConnProtoTunnel {
		c.worker.tunnelToBackend(c)
		return epollActionNeedRead
	}
	if c.protocol == plainConnProtoH1 {
		return c.epollProcessH1(srv)
	}
	return c.epollProcessH2Frames(srv)
}

const epollMaxPendingWriteDefault = 8 << 20

func (w *epollWorker) flush(c *epollConn) bool {
	if c.lingering {
		return false
	}
	if c.closeAfter {
		c.coalesceCloseNotify()
	}
	progressed := false
drain:
	for c.writeSent < len(c.writeBuf) || len(c.bodyOut) > 0 {
		var n int
		var err error
		if len(c.bodyOut) == 0 {
			n, err = socketSend(c.fd, c.writeBuf[c.writeSent:])
		} else {
			n, err = w.sendWithBody(c)
		}
		if n > 0 {
			w.bytesOut += uint64(n)
			c.advanceSent(n)
			progressed = true
			continue
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN {
			if len(c.writeBuf)-c.writeSent > w.maxPendingWrite {
				w.closeConn(c)
				return false
			}
			w.resumeRelayIfDrained(c)
			if c.fd < 0 {
				return false
			}
			if progressed && c.outArmed {
				c.deadline = w.wsOutDeadline(c)
			}
			w.armOut(c)
			return true
		}
		w.closeConn(c)
		return false
	}
	c.writeBuf = c.writeBuf[:0]
	c.writeSent = 0
	if c.h2PumpAll(w) || c.h1PumpOut(w) {
		goto drain
	}
	if c.h1FileBlocked(w) {
		return true
	}
	if c.outArmed {
		w.disarmOut(c)
	}
	w.resumeRelayIfDrained(c)
	if c.fd < 0 {
		return false
	}
	if c.writeSent < len(c.writeBuf) {
		return true
	}
	if c.closeAfter {
		w.closeAfterResponse(c)
		return false
	}
	return true
}

func (w *epollWorker) sendWithBody(c *epollConn) (int, error) {
	head := c.writeBuf[c.writeSent:]
	if len(head) == 0 {
		return socketSend(c.fd, c.bodyOut)
	}
	w.sendIov[0].Base = &head[0]
	w.sendIov[0].SetLen(len(head))
	w.sendIov[1].Base = &c.bodyOut[0]
	w.sendIov[1].SetLen(len(c.bodyOut))
	w.sendMsg.Iov = &w.sendIov[0]
	w.sendMsg.SetIovlen(len(w.sendIov))
	n, err := socketSendmsg(c.fd, &w.sendMsg)
	w.sendIov[0].Base, w.sendIov[1].Base = nil, nil
	return n, err
}

func (c *epollConn) advanceSent(n int) {
	head := len(c.writeBuf) - c.writeSent
	if n <= head {
		c.writeSent += n
		return
	}
	c.writeSent = len(c.writeBuf)
	c.bodyOut = c.bodyOut[n-head:]
	if len(c.bodyOut) == 0 {
		c.bodyOut = nil
	}
}

func (w *epollWorker) armOut(c *epollConn) {
	if c.outArmed {
		return
	}
	c.outArmed = true
	c.deadline = w.wsOutDeadline(c)
	if c.outRegistered {
		return
	}
	c.outRegistered = true
	ev := unix.EpollEvent{Events: uint32(unix.EPOLLIN|unix.EPOLLOUT|unix.EPOLLRDHUP) | uint32(unix.EPOLLET&0xffffffff), Fd: int32(c.fd)}
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_MOD, c.fd, &ev)
}

func (w *epollWorker) disarmOut(c *epollConn) {
	c.outArmed = false
	if c.inFlight > 0 || c.dispatching {
		c.deadline = 0
	} else if c.ws != nil {
		c.deadline = c.ws.readDeadline
	} else if w.idleTO > 0 {
		c.deadline = deadlineFrom(w.idleTO)
	}
}

func (w *epollWorker) closeConn(c *epollConn) {
	if c.fd < 0 {
		return
	}
	if c.ws != nil {
		w.wsTeardown(c)
	}
	c.cancelInFlight(ErrClientGone)
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_DEL, c.fd, nil)
	_ = unix.Close(c.fd)
	if c.fd < len(w.conns) {
		w.conns[c.fd] = nil
	}
	c.fd = -1
	c.generation++
	c.releaseH1BodyBudget()
	w.abortProxyExchange(c)
	if c.tunnelBE != nil {
		w.closeTunnelFromClient(c)
	}
	c.flushQueued = false
	c.h2AbortAllStreaming()
	c.h1AbortOut()
	c.h1AbortIn()
	c.h2AbortAllBodyIn()
	c.lingering = false
	for id, stream := range c.h2.streams {
		if stream.asyncBusy {
			continue
		}
		stream.Reset()
		StreamPool.Put(stream)
		delete(c.h2.streams, id)
	}
	for id, stream := range c.h2.sending {
		stream.Reset()
		StreamPool.Put(stream)
		delete(c.h2.sending, id)
	}
	c.readN = 0
	c.writeSent = 0
	c.h1Off = 0
	c.chunkScanPos = 0
	c.writeBuf = c.writeBuf[:0]
	c.h2.appBufOff = 0
	c.protocol = plainConnProtoUnknown
	c.closeAfter = false
	c.outArmed = false
	c.outRegistered = false
	c.dispatching = false
	c.readPending = false
	c.peerHup = false
	c.inputEOF = false
	c.h1ContinueSent = false
	c.hsReader = nil
	c.appReader = nil
	c.appWriter = nil
	c.tls12 = nil
	c.tlsRetry = nil
	c.ticket = nil
	c.clientAuth = nil
	c.tlsAlertSent = false
	c.peerCerts = nil
	c.tlsCertEntry = nil
	c.tlsPeerClosed = false
	c.tlsUselessRecords = 0
	c.cipherOff = 0
	c.h2GoingAway = false
	c.appBufOff = 0
	if c.appBuf != nil {
		c.appBuf = c.appBuf[:0]
	}
	c.tls = false
	c.tlsVersion = 0
	w.dropReadBuf(c)
	if c.ipHeld {
		w.server.perIPConnLimiter.Load().release(c.ipKey)
		c.ipHeld = false
		c.ipKey = ""
	}
	if c.inFlight > 0 {
		return
	}
	w.pool.put(c)
}

func (c *epollConn) acquireIPConn(srv *Server, req *Request) bool {
	if srv.trustedProxies.active {
		applyTrustedRealIP(req, srv.trustedProxies)
	}
	return true
}

func (c *epollConn) compactH2ReadBuffer(force bool) {
	st := &c.h2
	if st.appBufOff == 0 {
		return
	}
	if !force && st.appBufOff <= cap(c.readBuf)/2 && st.appBufOff != c.readN {
		return
	}
	remaining := c.readN - st.appBufOff
	if remaining > 0 {
		copy(c.readBuf, c.readBuf[st.appBufOff:c.readN])
	}
	c.readN = remaining
	st.appBufOff = 0
}
