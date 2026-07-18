//go:build linux && amd64

package core

import (
	"fmt"
	"log"
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
	epollConnSlabSize       = 128
	epollEventBatch         = 512
	epollListenBacklog      = 4096
	epollShrinkSlackSlabs   = 3
	epollBufShrinkThreshold = 32 << 10
)

const (
	epollActionNeedRead = iota
	epollActionCloseAfterFlush
	epollActionProxyDetach
	epollActionDetached
)

type epollConn struct {
	fd          int
	generation  uint32
	protocol    uint8
	closeAfter  bool
	outArmed    bool
	tls         bool
	dispatching bool
	ipHeld      bool
	inFlight    int
	readN       int
	writeSent   int
	h1Off       int
	deadline    int64
	readBuf     []byte
	writeBuf    []byte
	remoteAddr  string
	ipKey       string
	req         Request
	resp        Response
	h2          tlsWorkerH2State
	slab        *epollSlab

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

	proxyRoute  *httpRouteEntry
	proxyRawReq []byte
	reqBodyCopy []byte

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
	if p.server != nil {
		p.server.activeConns.Add(-1)
		Stats.ActiveConns.Add(-1)
	}
	releaseEpollReadBuf(c.readBuf)
	c.readBuf = nil
	releaseIOBuf(c.writeBuf)
	c.writeBuf = nil
	releaseIOBuf(c.appBuf)
	c.appBuf = nil
	releaseIOBuf(c.plainBuf)
	c.plainBuf = nil
	c.reqBodyCopy = shrinkEpollBuf(c.reqBodyCopy)
	c.proxyRawReq = shrinkEpollBuf(c.proxyRawReq)
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
	epfd            int
	listenerFD      int
	wakeFd          int
	coreID          int
	tlsMode         bool
	conns           []*epollConn
	pool            epollConnPool
	events          []unix.EpollEvent
	taskCh          chan func(*epollWorker)
	taskPending     atomic.Bool
	wakeBuf         [8]byte
	flushSet        map[*epollConn]struct{}
	h2FinishScratch []byte
	readTO          int64
	writeTO         int64
	idleTO          int64
	lastSweep       int64
}

// ListenAndServeEpollH2 serves plain HTTP/1.1 and HTTP/2 prior-knowledge on
// addr using the epoll backend: Config.Listeners SO_REUSEPORT sockets (default:
// one per CPU thread), each with its own event-loop worker goroutine. It blocks
// until the server stops.
func (s *Server) ListenAndServeEpollH2(addr string) error {
	return s.serveEpoll(addr, false)
}

// ListenAndServeEpollTLS serves HTTPS (TLS 1.3/1.2, HTTP/1.1 + HTTP/2) on addr
// using the epoll backend with Config.Listeners SO_REUSEPORT sockets (default:
// one per CPU thread), each with its own event-loop worker goroutine. It blocks
// until the server stops.
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
	s.Router.Build()
	s.computeFastDispatch()
	workers := s.epollListenerCount()
	minPerWorker := 0
	if s.config.MinPrealloc > 0 {
		minPerWorker = (s.config.MinPrealloc + workers - 1) / workers
	}
	go s.epollScavenger()
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		coreID := i % runtime.NumCPU()
		go func() {
			w, err := newEpollWorker(s, addr, minPerWorker)
			if err != nil {
				errCh <- err
				return
			}
			w.coreID = coreID
			w.tlsMode = tlsMode
			errCh <- w.run()
		}()
	}
	return <-errCh
}

func (s *Server) epollScavenger() {
	const (
		freeThrottleNs  = 10 * int64(time.Second)
		idleRatePerTick = 40
		connActive      = 32
		minReturnable   = 24 << 20
		maxReclaims     = 2
	)
	var lastFree int64
	var lastReqs, rate uint64
	var armed bool
	var reclaims int
	var ms runtime.MemStats
	for {
		turbo.Sleep(2 * time.Second)
		now := turbo.UnixNano()
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
		flushSet:   make(map[*epollConn]struct{}, 64),
	}
	w.pool.server = s
	w.pool.batchSize = s.preallocBatch()
	w.readTO = int64(s.config.ReadTimeout)
	w.writeTO = int64(s.config.WriteTimeout)
	w.idleTO = int64(s.config.IdleTimeout)
	w.pool.prewarm(minPrealloc)
	return w, nil
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
	var one uint64 = 1
	_, _ = unix.Write(w.wakeFd, (*[8]byte)(unsafe.Pointer(&one))[:])
}

func (w *epollWorker) drainTasks() {
	w.taskPending.Store(false)
	for {
		select {
		case fn := <-w.taskCh:
			w.runTask(fn)
		default:
			return
		}
	}
}

func (w *epollWorker) runTask(fn func(*epollWorker)) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[EPOLL-PANIC] worker %d task recovered: %v", w.coreID, r)
		}
	}()
	fn(w)
}

func epollListen(addr string) (int, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", addr)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	sa := &unix.SockaddrInet4{Port: tcpAddr.Port}
	if ip4 := tcpAddr.IP.To4(); ip4 != nil {
		copy(sa.Addr[:], ip4)
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if err := unix.Listen(fd, epollListenBacklog); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (w *epollWorker) run() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for {
		n, err := unix.EpollWait(w.epfd, w.events, epollSweepIntervalMs)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("epoll wait: %w", err)
		}
		acceptPending := false
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
			if fd < 0 || fd >= len(w.conns) {
				continue
			}
			c := w.conns[fd]
			if c == nil {
				continue
			}
			evs := w.events[i].Events
			if evs&(unix.EPOLLERR|unix.EPOLLHUP) != 0 && evs&unix.EPOLLIN == 0 {
				w.closeConn(c)
				continue
			}
			if evs&unix.EPOLLOUT != 0 {
				if !w.flush(c) {
					continue
				}
			}
			if evs&(unix.EPOLLIN|unix.EPOLLRDHUP) != 0 {
				w.readable(c)
			}
		}
		if tasksPending {
			_, _ = unix.Read(w.wakeFd, w.wakeBuf[:])
			w.drainTasks()
			w.flushPending()
		}
		if acceptPending {
			w.acceptLoop()
		}
		w.sweepDeadlines()
	}
}

const epollSweepIntervalMs = 1000

func (w *epollWorker) sweepDeadlines() {
	if w.readTO == 0 && w.writeTO == 0 && w.idleTO == 0 {
		return
	}
	now := turbo.UnixNano()
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
		}
	}
}

func deadlineFrom(to int64) int64 {
	if to <= 0 {
		return 0
	}
	return turbo.UnixNano() + to
}

func (w *epollWorker) markFlush(c *epollConn) {
	w.flushSet[c] = struct{}{}
}

func (w *epollWorker) flushPending() {
	for c := range w.flushSet {
		delete(w.flushSet, c)
		if c.fd >= 0 {
			w.flush(c)
		}
	}
}

func (w *epollWorker) acceptLoop() {
	for {
		nfd, sa, err := unix.Accept4(w.listenerFD, unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		active := w.server.activeConns.Add(1)
		Stats.ActiveConns.Add(1)
		if lim := w.server.config.MaxConns; lim > 0 && active > lim {
			w.server.activeConns.Add(-1)
			Stats.ActiveConns.Add(-1)
			_ = unix.Close(nfd)
			continue
		}
		_ = unix.SetsockoptInt(nfd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
		_ = unix.SetsockoptInt(nfd, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, 8192)
		c := w.pool.get()
		c.fd = nfd
		c.worker = w
		c.protocol = plainConnProtoUnknown
		c.closeAfter = false
		c.outArmed = false
		c.dispatching = false
		c.readN = 0
		c.writeSent = 0
		c.h1Off = 0
		c.deadline = deadlineFrom(w.readTO)
		c.remoteAddr = epollRemoteAddr(sa)
		c.ipHeld = false
		c.ipKey = ""
		if w.server.perIPConnLimiter != nil && !w.server.trustedProxies.active {
			key := extractIP(c.remoteAddr)
			if !w.server.perIPConnLimiter.acquire(key, w.server.maxConnsPerIP) {
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
		c.appBufOff = 0
		if c.appBuf != nil {
			c.appBuf = c.appBuf[:0]
		}
		if c.tls {
			c.phase = tlsConnPhaseClientHello
			c.hsReader = nil
			c.appReader = nil
			c.appWriter = nil
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

func epollRemoteAddr(sa unix.Sockaddr) string {
	sa4, ok := sa.(*unix.SockaddrInet4)
	if !ok {
		return ""
	}
	return net.IP(sa4.Addr[:]).String() + ":" + strconv.Itoa(sa4.Port)
}

func (w *epollWorker) readable(c *epollConn) {
	if c.dispatching {
		return
	}
	if c.readBuf == nil {
		c.readBuf = acquireEpollReadBuf()
	}
	if c.writeBuf == nil {
		c.writeBuf = acquireIOBuf()
	}
	maxRead := resolveReadCap(w.server.config.MaxReadSize)
	prevReadN := c.readN
	closed := false
	for {
		if cap(c.readBuf)-c.readN < plainReadMinFree {
			c.compactH2ReadBuffer(true)
			if cap(c.readBuf)-c.readN < plainReadMinFree {
				grown, ok := growPlainReadBuffer(c.readBuf[:c.readN], plainReadMinFree, maxRead)
				if !ok {
					w.closeConn(c)
					return
				}
				c.readBuf = grown[:cap(grown)]
			}
		}
		reqLen := cap(c.readBuf) - c.readN
		n, err := unix.Read(c.fd, c.readBuf[c.readN:cap(c.readBuf)])
		if n > 0 {
			c.readN += n
			if n < reqLen {
				break
			}
			continue
		}
		if n == 0 && err == nil {
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
		return
	}
	if prevReadN == 0 && c.readN > 0 && w.readTO > 0 {
		c.deadline = deadlineFrom(w.readTO)
	}
	if c.readN > 0 {
		var action int
		if c.tls {
			action = c.epollProcessTLS(w.server)
		} else {
			action = c.epollProcess(w.server)
		}
		if action == epollActionProxyDetach {
			w.detachProxy(c)
			return
		}
		if action == epollActionDetached {
			w.recycleConn(c)
			return
		}
		if action == epollActionCloseAfterFlush {
			c.closeAfter = true
		}
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
		return
	}
	if c.readN == 0 && !c.outArmed && c.writeSent == len(c.writeBuf) {
		releaseEpollReadBuf(c.readBuf)
		c.readBuf = nil
		releaseIOBuf(c.writeBuf)
		c.writeBuf = nil
		if c.appBuf != nil && len(c.appBuf) == 0 {
			releaseIOBuf(c.appBuf)
			c.appBuf = nil
		}
		if c.plainBuf != nil && len(c.plainBuf) == 0 {
			releaseIOBuf(c.plainBuf)
			c.plainBuf = nil
		}
		c.resp.resetFastH1()
		c.deadline = deadlineFrom(w.idleTO)
	}
}

func (w *epollWorker) detachProxy(c *epollConn) {
	fd := c.fd
	route := c.proxyRoute
	rawReq := append([]byte(nil), c.proxyRawReq...)
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_DEL, fd, nil)
	if fd < len(w.conns) {
		w.conns[fd] = nil
	}
	c.fd = -1
	c.proxyRoute = nil
	w.recycleConn(c)
	go w.server.epollProxyForward(fd, rawReq, route)
}

func (w *epollWorker) recycleConn(c *epollConn) {
	for id, stream := range c.h2.streams {
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
	c.writeBuf = c.writeBuf[:0]
	c.h2.appBufOff = 0
	c.protocol = plainConnProtoUnknown
	c.closeAfter = false
	c.outArmed = false
	c.hsReader = nil
	c.appReader = nil
	c.appWriter = nil
	c.appBufOff = 0
	if c.appBuf != nil {
		c.appBuf = c.appBuf[:0]
	}
	c.tls = false
	w.pool.put(c)
}

func (c *epollConn) epollProcess(srv *Server) int {
	if c.protocol == plainConnProtoUnknown {
		avail := c.readN
		checkLen := avail
		if checkLen > H2PrefaceLen {
			checkLen = H2PrefaceLen
		}
		isPreface := true
		for i := 0; i < checkLen; i++ {
			if c.readBuf[i] != H2ClientPreface[i] {
				isPreface = false
				break
			}
		}
		if isPreface {
			if avail < H2PrefaceLen {
				return epollActionNeedRead
			}
			c.protocol = plainConnProtoH2
			c.h2.init()
			c.writeBuf = appendH2ServerSettingsFlight(c.writeBuf, srv)
			Stats.H2Conns.Add(1)
		} else {
			c.protocol = plainConnProtoH1
			Stats.H1Conns.Add(1)
		}
	}
	if c.protocol == plainConnProtoH1 {
		return c.epollProcessH1(srv)
	}
	return c.epollProcessH2Frames(srv)
}

func (w *epollWorker) flush(c *epollConn) bool {
	for c.writeSent < len(c.writeBuf) {
		n, err := unix.Write(c.fd, c.writeBuf[c.writeSent:])
		if n > 0 {
			c.writeSent += n
			continue
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN {
			w.armOut(c)
			return true
		}
		w.closeConn(c)
		return false
	}
	c.writeBuf = c.writeBuf[:0]
	c.writeSent = 0
	if c.outArmed {
		w.disarmOut(c)
	}
	if c.closeAfter {
		w.closeConn(c)
		return false
	}
	return true
}

func (w *epollWorker) armOut(c *epollConn) {
	if c.outArmed {
		return
	}
	c.outArmed = true
	if w.writeTO > 0 {
		c.deadline = deadlineFrom(w.writeTO)
	}
	ev := unix.EpollEvent{Events: uint32(unix.EPOLLIN|unix.EPOLLOUT|unix.EPOLLRDHUP) | uint32(unix.EPOLLET&0xffffffff), Fd: int32(c.fd)}
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_MOD, c.fd, &ev)
}

func (w *epollWorker) disarmOut(c *epollConn) {
	c.outArmed = false
	if w.idleTO > 0 {
		c.deadline = deadlineFrom(w.idleTO)
	}
	ev := unix.EpollEvent{Events: uint32(unix.EPOLLIN|unix.EPOLLRDHUP) | uint32(unix.EPOLLET&0xffffffff), Fd: int32(c.fd)}
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_MOD, c.fd, &ev)
}

func (w *epollWorker) closeConn(c *epollConn) {
	if c.fd < 0 {
		return
	}
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_DEL, c.fd, nil)
	_ = unix.Close(c.fd)
	if c.fd < len(w.conns) {
		w.conns[c.fd] = nil
	}
	c.fd = -1
	c.generation++
	delete(w.flushSet, c)
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
	c.writeBuf = c.writeBuf[:0]
	c.h2.appBufOff = 0
	c.protocol = plainConnProtoUnknown
	c.closeAfter = false
	c.outArmed = false
	c.dispatching = false
	c.hsReader = nil
	c.appReader = nil
	c.appWriter = nil
	c.appBufOff = 0
	if c.appBuf != nil {
		c.appBuf = c.appBuf[:0]
	}
	c.tls = false
	releaseEpollReadBuf(c.readBuf)
	c.readBuf = nil
	if c.ipHeld {
		w.server.perIPConnLimiter.release(c.ipKey)
		c.ipHeld = false
		c.ipKey = ""
	}
	if c.inFlight > 0 {
		return
	}
	w.pool.put(c)
}

func (c *epollConn) acquireIPConn(srv *Server, req *Request) bool {
	if srv.perIPConnLimiter == nil || c.ipHeld || !srv.trustedProxies.active {
		return true
	}
	applyTrustedRealIP(req, srv.trustedProxies)
	key := extractIP(req.RemoteAddr)
	if !srv.perIPConnLimiter.acquire(key, srv.maxConnsPerIP) {
		return false
	}
	c.ipHeld = true
	c.ipKey = key
	return true
}

func (c *epollConn) compactH2ReadBuffer(force bool) {
	st := &c.h2
	if st.appBufOff == 0 {
		return
	}
	if !force && st.appBufOff <= cap(c.readBuf)/2 {
		return
	}
	remaining := c.readN - st.appBufOff
	if remaining > 0 {
		copy(c.readBuf, c.readBuf[st.appBufOff:c.readN])
	}
	c.readN = remaining
	st.appBufOff = 0
}
