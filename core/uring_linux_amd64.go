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

	"golang.org/x/sys/unix"
)

const (
	ioUringOffSqRing                 = 0
	ioUringOffCqRing                 = 0x08000000
	ioUringOffSqes                   = 0x10000000
	ioUringEnterGetEvents            = 1
	ioUringEnterRegistered           = 1 << 4
	ioUringRegisterSyscall           = 427
	ioUringOpReadv                   = 1
	ioUringOpAccept                  = 13
	ioUringOpAsyncCancel             = 14
	ioUringOpClose                   = 19
	ioUringOpRecv                    = 27
	ioUringOpSend                    = 26
	ioUringOpSendZC                  = 47
	ioUringFeatSingleMmap            = 1
	ioUringFeatRegRegRing            = 1 << 13
	ioUringFeatRecvSendBundle        = 1 << 14
	ioUringSetupSyscall              = 425
	ioUringEnterSyscall              = 426
	ioUringSetupRDisabled            = 1 << 6
	ioUringSetupSubmitAll            = 1 << 7
	ioUringSetupCoopTaskrun          = 1 << 8
	ioUringSetupTaskrunFlag          = 1 << 9
	ioUringSetupSingleIssuer         = 1 << 12
	ioUringSetupDeferTaskrun         = 1 << 13
	ioUringEntries                   = 256
	ioUringConnEntries               = 32
	ioUringPollFirst                 = 1 << 0
	ioUringRecvMultishot             = 1 << 1
	ioUringAcceptMultishot           = 1 << 0
	ioUringSqeFixedFile              = 1 << 0
	ioUringSqeBufferSelect           = 1 << 5
	ioUringSqTaskrun                 = 1 << 2
	ioUringCqeBuffer                 = 1 << 0
	ioUringCqeMore                   = 1 << 1
	ioUringCqeSockNonEmpty           = 1 << 2
	ioUringCqeNotif                  = 1 << 3
	ioUringCqeBufferShift            = 16
	ioUringRegisterEnable            = 12
	ioUringRegisterUseRegisteredRing = 1 << 31
	ioUringRegisterRingFDs           = 20
	ioUringUnregisterRingFDs         = 21
	ioUringRegisterPbufRing          = 22
	ioUringRegisterSyncCancel        = 24
	ioUringAsyncCancelAll            = 1 << 0
	ioUringAsyncCancelFD             = 1 << 1
	ioUringAsyncCancelOp             = 1 << 5
	ioUringRecvSendBundle            = 1 << 4
	ioUringSendZCReportUsage         = 1 << 3
	sockCloexec                      = 0x80000
	sockNonblock                     = 0x800
	ioUringConnsPerShard             = 600
	ioUringAcceptDepth               = 16
	ioUringConnSlotsPerLN            = 2048
	ioUringSendZCThreshold           = 32 << 10
)

type ioUringSqringOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Flags       uint32
	Dropped     uint32
	Array       uint32
	Resv1       uint32
	UserAddr    uint64
}

type ioUringCqringOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Overflow    uint32
	Cqes        uint32
	Flags       uint32
	Resv1       uint32
	UserAddr    uint64
}

type ioUringParams struct {
	SqEntries    uint32
	CqEntries    uint32
	Flags        uint32
	SqThreadCPU  uint32
	SqThreadIdle uint32
	Features     uint32
	WqFd         uint32
	Resv         [3]uint32
	SqOff        ioUringSqringOffsets
	CqOff        ioUringCqringOffsets
}

type ioUringSqe struct {
	Opcode      uint8
	Flags       uint8
	Ioprio      uint16
	FD          int32
	Off         uint64
	Addr        uint64
	Len         uint32
	OpFlags     uint32
	UserData    uint64
	BufIndex    uint16
	Personality uint16
	SpliceFDIn  int32
	Addr3       uint64
	Pad2        uint64
}

type ioUringCqe struct {
	UserData uint64
	Res      int32
	Flags    uint32
}

type ioUringRsrcUpdate struct {
	Offset uint32
	Resv   uint32
	Data   uint64
}

type ioUringKernelTimespec struct {
	Sec  int64
	Nsec int64
}

type ioUringSyncCancelReg struct {
	Addr    uint64
	FD      int32
	Flags   uint32
	Timeout ioUringKernelTimespec
	Opcode  uint8
	Pad     [7]uint8
	Pad2    [3]uint64
}

type ioUring struct {
	fd      int
	enterFD int

	sqRing []byte
	cqRing []byte
	sqes   []ioUringSqe
	cqes   []ioUringCqe

	sqHead          *uint32
	sqTail          *uint32
	sqMask          *uint32
	sqEntries       *uint32
	sqFlags         *uint32
	sqArray         []uint32
	cqHead          *uint32
	cqTail          *uint32
	cqMask          *uint32
	localSqTail     uint32
	submitted       uint32
	flags           uint32
	features        uint32
	disabled        bool
	registeredRing  bool
	regRegRing      bool
	sendZCState     uint8
	syncCancelState uint8
}

type ioUringAcceptor struct {
	listener net.Listener
	fd       int
	ring     *ioUring
	slots    chan struct{}
	inflight int
}

type ioUringConn struct {
	fd         int
	readRing   *ioUring
	writeRing  *ioUring
	readMu     sync.Mutex
	writeMu    sync.Mutex
	closeOnce  sync.Once
	closed     atomic.Bool
	readDLN    atomic.Int64
	writeDLN   atomic.Int64
	localAddr  net.Addr
	remoteAddr net.Addr
	onClose    func()
}

type ioUringRawConn struct {
	conn *ioUringConn
}

type deadlineExceededError struct{}

func (deadlineExceededError) Error() string   { return "i/o timeout" }
func (deadlineExceededError) Timeout() bool   { return true }
func (deadlineExceededError) Temporary() bool { return true }

var errIOUringDeadlineExceeded error = deadlineExceededError{}

type syscallConnListener interface {
	SyscallConn() (syscall.RawConn, error)
}

func (s *Server) tryServeWithIOUringRedirect(listeners []net.Listener) error {
	slotPool := make(chan struct{}, ioUringTotalConnSlots(s.config.Listeners, len(listeners)))
	acceptors := make([]*ioUringAcceptor, 0, len(listeners))
	for _, listener := range listeners {
		acceptor, err := newIOUringAcceptor(listener, slotPool)
		if err != nil {
			for _, item := range acceptors {
				item.close()
			}
			return err
		}
		acceptors = append(acceptors, acceptor)
	}
	errCh := make(chan error, len(acceptors))
	for _, acceptor := range acceptors {
		acceptor := acceptor
		go s.ioUringRedirectAcceptLoop(acceptor, errCh)
	}
	go func() {
		select {
		case <-s.done:
			for _, ln := range listeners {
				_ = ln.Close()
			}
		case err := <-errCh:
			if err != nil {
				log.Printf("[HTTP] redirect io_uring listener failed: %v", err)
			}
			for _, ln := range listeners {
				_ = ln.Close()
			}
		}
	}()
	return nil
}

func ioUringListenerCount(configured int) int {
	if configured < 1 {
		return 1
	}
	return configured
}

func ioUringTotalConnSlots(configuredListeners, activeListeners int) int {
	listenerBudget := configuredListeners
	if listenerBudget < activeListeners {
		listenerBudget = activeListeners
	}
	if listenerBudget < 1 {
		listenerBudget = 1
	}
	total := listenerBudget * ioUringConnSlotsPerLN
	if total < ioUringConnSlotsPerLN {
		total = ioUringConnSlotsPerLN
	}
	if total > 65536 {
		total = 65536
	}
	return total
}

func ioUringShardLayout() (int, int) {
	shards := runtime.NumCPU() * 12
	if shards < 1 {
		shards = 1
	}
	acceptShards := 1
	if shards <= 96 {
		acceptShards = 1
	} else if shards <= 192 {
		acceptShards = 2
	} else if shards <= 384 {
		acceptShards = 3
	} else if shards <= 768 {
		acceptShards = 4
	} else if shards <= 1536 {
		acceptShards = 6
	} else {
		acceptShards = 8
	}
	return shards, acceptShards
}

func newIOUringAcceptor(listener net.Listener, slots chan struct{}) (*ioUringAcceptor, error) {
	rawListener, ok := listener.(syscallConnListener)
	if !ok {
		return nil, fmt.Errorf("listener %T does not expose SyscallConn", listener)
	}

	rawConn, err := rawListener.SyscallConn()
	if err != nil {
		return nil, err
	}

	var listenerFD int
	controlErr := rawConn.Control(func(fd uintptr) {
		listenerFD = int(fd)
	})
	if controlErr != nil {
		return nil, controlErr
	}
	if listenerFD < 0 {
		return nil, errors.New("listener fd unavailable")
	}

	ring, err := newOwnedIOUring(ioUringEntries)
	if err != nil {
		return nil, err
	}

	return &ioUringAcceptor{
		listener: listener,
		fd:       listenerFD,
		ring:     ring,
		slots:    slots,
	}, nil
}
func (s *Server) ioUringRedirectAcceptLoop(acceptor *ioUringAcceptor, errCh chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer acceptor.releaseInflight()
	defer acceptor.close()
	if err := acceptor.ring.enable(); err != nil {
		select {
		case errCh <- err:
		default:
		}
		return
	}
	var completions [64]ioUringCqe
	for {
		if acceptor.inflight == 0 {
			if !acceptor.acquireSlot(s.done) {
				return
			}
			if err := acceptor.ring.prepAccept(acceptor.fd, uint32(sockCloexec|sockNonblock)); err != nil {
				acceptor.releaseSlot()
				select {
				case errCh <- fmt.Errorf("io_uring redirect prepAccept listener_fd=%d: %w", acceptor.fd, err):
				default:
				}
				return
			}
			acceptor.inflight++
		}
		for acceptor.inflight < ioUringAcceptDepth && acceptor.tryAcquireSlot() {
			if err := acceptor.ring.prepAccept(acceptor.fd, uint32(sockCloexec|sockNonblock)); err != nil {
				acceptor.releaseSlot()
				select {
				case errCh <- fmt.Errorf("io_uring redirect refill listener_fd=%d: %w", acceptor.fd, err):
				default:
				}
				return
			}
			acceptor.inflight++
		}
		if _, err := acceptor.ring.submitAndWait(0); err != nil {
			if s.doneClosed() || isIOUringAcceptShutdownError(err) {
				return
			}
			select {
			case errCh <- fmt.Errorf("io_uring redirect submit listener_fd=%d: %w", acceptor.fd, err):
			default:
			}
			return
		}
		count := acceptor.ring.peekBatch(completions[:])
		if count == 0 {
			cqe, err := acceptor.ring.waitCqe()
			if err != nil {
				if s.doneClosed() || isIOUringAcceptShutdownError(err) {
					return
				}
				select {
				case errCh <- fmt.Errorf("io_uring redirect wait listener_fd=%d: %w", acceptor.fd, err):
				default:
				}
				return
			}
			completions[0] = cqe
			count = 1
		}
		for i := 0; i < count; i++ {
			if acceptor.inflight > 0 {
				acceptor.inflight--
			}
			cqe := completions[i]
			if cqe.Res < 0 {
				acceptor.releaseSlot()
				err := syscall.Errno(-cqe.Res)
				if s.doneClosed() || isIOUringAcceptShutdownError(err) {
					return
				}
				if isIOUringTransient(err) {
					continue
				}
				select {
				case errCh <- fmt.Errorf("io_uring redirect cqe listener_fd=%d: %w", acceptor.fd, err):
				default:
				}
				return
			}
			fd := int(cqe.Res)
			conn, err := newIOUringConn(fd)
			if err != nil {
				acceptor.releaseSlot()
				log.Printf("[HTTP] redirect accepted fd conversion failed: %v", err)
				continue
			}
			if uringConn, ok := conn.(*ioUringConn); ok {
				uringConn.onClose = acceptor.releaseSlot
			} else {
				acceptor.releaseSlot()
			}
			go s.serveHTTPRedirectConn(conn)
		}
	}
}

func (acceptor *ioUringAcceptor) acquireSlot(done <-chan struct{}) bool {
	select {
	case acceptor.slots <- struct{}{}:
		return true
	case <-done:
		return false
	}
}

func (acceptor *ioUringAcceptor) tryAcquireSlot() bool {
	if acceptor == nil || acceptor.slots == nil {
		return false
	}
	select {
	case acceptor.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (acceptor *ioUringAcceptor) releaseSlot() {
	if acceptor == nil || acceptor.slots == nil {
		return
	}
	select {
	case <-acceptor.slots:
	default:
	}
}

func (acceptor *ioUringAcceptor) releaseInflight() {
	for acceptor != nil && acceptor.inflight > 0 {
		acceptor.releaseSlot()
		acceptor.inflight--
	}
}

func (s *Server) doneClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (acceptor *ioUringAcceptor) close() {
	if acceptor == nil || acceptor.ring == nil {
		return
	}
	acceptor.ring.close()
	acceptor.ring = nil
}

func isIOUringAcceptShutdownError(err error) bool {
	return errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ECANCELED)
}

func isIOUringTransient(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.ECONNABORTED)
}

func newIOUringConn(fd int) (net.Conn, error) {
	prepareAcceptedFD(fd)
	localAddr, remoteAddr := socketAddrs(fd)
	readRing, err := newIOUring(ioUringConnEntries)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	writeRing, err := newIOUring(ioUringConnEntries)
	if err != nil {
		readRing.close()
		_ = syscall.Close(fd)
		return nil, err
	}
	return &ioUringConn{
		fd:         fd,
		readRing:   readRing,
		writeRing:  writeRing,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}, nil
}

func wrapConnectedConnWithIOUring(conn net.Conn) (net.Conn, error) {
	if _, ok := conn.(*ioUringConn); ok {
		return conn, nil
	}
	rawConnProvider, ok := conn.(syscallConnListener)
	if !ok {
		return conn, nil
	}
	rawConn, err := rawConnProvider.SyscallConn()
	if err != nil {
		return conn, nil
	}
	dupFD := -1
	var dupErr error
	controlErr := rawConn.Control(func(fd uintptr) {
		dupFD, dupErr = syscall.Dup(int(fd))
	})
	if controlErr != nil || dupErr != nil || dupFD < 0 {
		if dupFD >= 0 {
			_ = syscall.Close(dupFD)
		}
		return conn, nil
	}
	wrapped, err := newIOUringConn(dupFD)
	if err != nil {
		_ = syscall.Close(dupFD)
		return conn, nil
	}
	if err := conn.Close(); err != nil {
		_ = wrapped.Close()
		return nil, err
	}
	return wrapped, nil
}

func (c *ioUringConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.readRing.recv(c.fd, p, c.readDeadline())
	if errors.Is(err, errIOUringDeadlineExceeded) {
		_ = c.Close()
	}
	return n, err
}

func (c *ioUringConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.writeRing.sendAll(c.fd, p, c.writeDeadline())
	if errors.Is(err, errIOUringDeadlineExceeded) {
		_ = c.Close()
	}
	return n, err
}

func (c *ioUringConn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		if c.fd >= 0 {
			closeErr = syscall.Close(c.fd)
			c.fd = -1
		}
		if c.readRing != nil {
			c.readRing.close()
			c.readRing = nil
		}
		if c.writeRing != nil {
			c.writeRing.close()
			c.writeRing = nil
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
	return closeErr
}

func (c *ioUringConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *ioUringConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *ioUringConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}

func (c *ioUringConn) SetReadDeadline(t time.Time) error {
	c.readDLN.Store(deadlineUnixNano(t))
	return nil
}

func (c *ioUringConn) SetWriteDeadline(t time.Time) error {
	c.writeDLN.Store(deadlineUnixNano(t))
	return nil
}

func (c *ioUringConn) SyscallConn() (syscall.RawConn, error) {
	if c.closed.Load() {
		return nil, net.ErrClosed
	}
	return ioUringRawConn{conn: c}, nil
}

func (rc ioUringRawConn) Control(fn func(fd uintptr)) error {
	if rc.conn == nil || rc.conn.fd < 0 {
		return net.ErrClosed
	}
	fn(uintptr(rc.conn.fd))
	return nil
}

func (rc ioUringRawConn) Read(fn func(fd uintptr) bool) error {
	if rc.conn == nil || rc.conn.fd < 0 {
		return net.ErrClosed
	}
	fn(uintptr(rc.conn.fd))
	return nil
}

func (rc ioUringRawConn) Write(fn func(fd uintptr) bool) error {
	if rc.conn == nil || rc.conn.fd < 0 {
		return net.ErrClosed
	}
	fn(uintptr(rc.conn.fd))
	return nil
}

func (c *ioUringConn) readDeadline() time.Time {
	return deadlineFromUnixNano(c.readDLN.Load())
}

func (c *ioUringConn) writeDeadline() time.Time {
	return deadlineFromUnixNano(c.writeDLN.Load())
}

func deadlineUnixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func deadlineFromUnixNano(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value)
}

func socketAddrs(fd int) (net.Addr, net.Addr) {
	local := sockAddrToTCPAddr(mustSockaddr(syscall.Getsockname(fd)))
	remote := sockAddrToTCPAddr(mustSockaddr(syscall.Getpeername(fd)))
	return local, remote
}

func mustSockaddr(addr syscall.Sockaddr, err error) syscall.Sockaddr {
	if err != nil {
		return nil
	}
	return addr
}

func sockAddrToTCPAddr(addr syscall.Sockaddr) net.Addr {
	switch value := addr.(type) {
	case *syscall.SockaddrInet4:
		ip := make(net.IP, net.IPv4len)
		copy(ip, value.Addr[:])
		return &net.TCPAddr{IP: ip, Port: value.Port}
	case *syscall.SockaddrInet6:
		ip := make(net.IP, net.IPv6len)
		copy(ip, value.Addr[:])
		return &net.TCPAddr{IP: ip, Port: value.Port, Zone: zoneName(value.ZoneId)}
	default:
		return &net.TCPAddr{}
	}
}

func zoneName(zone uint32) string {
	if zone == 0 {
		return ""
	}
	iface, err := net.InterfaceByIndex(int(zone))
	if err != nil {
		return ""
	}
	return iface.Name
}

func newIOUring(entries uint32) (*ioUring, error) {
	return newIOUringWithFlagFallback(entries,
		ioUringSetupCoopTaskrun|ioUringSetupTaskrunFlag|ioUringSetupSubmitAll,
		ioUringSetupCoopTaskrun|ioUringSetupSubmitAll,
	)
}

func newOwnedIOUring(entries uint32) (*ioUring, error) {
	ring, err := newIOUringWithFlagFallback(entries,
		ioUringSetupSingleIssuer|ioUringSetupDeferTaskrun|ioUringSetupCoopTaskrun|ioUringSetupTaskrunFlag|ioUringSetupSubmitAll,
		ioUringSetupSingleIssuer|ioUringSetupCoopTaskrun|ioUringSetupTaskrunFlag|ioUringSetupSubmitAll,
		ioUringSetupCoopTaskrun|ioUringSetupTaskrunFlag|ioUringSetupSubmitAll,
		ioUringSetupCoopTaskrun|ioUringSetupSubmitAll,
	)
	if err != nil {
		return nil, err
	}
	if err := ring.registerRingFD(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOSYS) && !errors.Is(err, syscall.EOPNOTSUPP) && !errors.Is(err, syscall.EEXIST) {
		ring.close()
		return nil, err
	}
	return ring, nil
}

func newIOUringWithFlagFallback(entries uint32, flagCandidates ...uint32) (*ioUring, error) {
	candidates := make([]uint32, 0, len(flagCandidates)+1)
	candidates = append(candidates, flagCandidates...)
	candidates = append(candidates, 0)
	lastErr := error(nil)
	for idx, flags := range candidates {
		if idx > 0 && flags == candidates[idx-1] {
			continue
		}
		ring, err := newIOUringConfigured(entries, flags)
		if err == nil {
			return ring, nil
		}
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSYS) {
			lastErr = err
			continue
		}
		return nil, err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, syscall.EINVAL
}

func newIOUringConfigured(entries uint32, flags uint32) (*ioUring, error) {
	params := ioUringParams{}
	params.Flags = flags
	fd, _, errno := syscall.Syscall(ioUringSetupSyscall, uintptr(entries), uintptr(unsafe.Pointer(&params)), 0)
	if errno != 0 {
		return nil, errno
	}

	sqRingSize := params.SqOff.Array + params.SqEntries*uint32(unsafe.Sizeof(uint32(0)))
	cqRingSize := params.CqOff.Cqes + params.CqEntries*uint32(unsafe.Sizeof(ioUringCqe{}))
	sqesSize := params.SqEntries * uint32(unsafe.Sizeof(ioUringSqe{}))

	var sqRing []byte
	var cqRing []byte
	if params.Features&ioUringFeatSingleMmap != 0 {
		ringSize := sqRingSize
		if cqRingSize > ringSize {
			ringSize = cqRingSize
		}
		mapped, err := syscall.Mmap(int(fd), ioUringOffSqRing, int(ringSize), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_POPULATE)
		if err != nil {
			_ = syscall.Close(int(fd))
			return nil, err
		}
		sqRing = mapped
		cqRing = mapped
	} else {
		mappedSq, err := syscall.Mmap(int(fd), ioUringOffSqRing, int(sqRingSize), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_POPULATE)
		if err != nil {
			_ = syscall.Close(int(fd))
			return nil, err
		}
		mappedCq, err := syscall.Mmap(int(fd), ioUringOffCqRing, int(cqRingSize), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_POPULATE)
		if err != nil {
			_ = syscall.Munmap(mappedSq)
			_ = syscall.Close(int(fd))
			return nil, err
		}
		sqRing = mappedSq
		cqRing = mappedCq
	}

	sqesBytes, err := syscall.Mmap(int(fd), ioUringOffSqes, int(sqesSize), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_POPULATE)
	if err != nil {
		if len(sqRing) > 0 {
			_ = syscall.Munmap(sqRing)
		}
		if len(cqRing) > 0 && unsafe.Pointer(unsafe.SliceData(cqRing)) != unsafe.Pointer(unsafe.SliceData(sqRing)) {
			_ = syscall.Munmap(cqRing)
		}
		_ = syscall.Close(int(fd))
		return nil, err
	}

	ring := &ioUring{fd: int(fd), enterFD: int(fd), sqRing: sqRing, cqRing: cqRing}
	ring.sqHead = byteOffsetPtr[uint32](sqRing, params.SqOff.Head)
	ring.sqTail = byteOffsetPtr[uint32](sqRing, params.SqOff.Tail)
	ring.sqMask = byteOffsetPtr[uint32](sqRing, params.SqOff.RingMask)
	ring.sqEntries = byteOffsetPtr[uint32](sqRing, params.SqOff.RingEntries)
	ring.sqFlags = byteOffsetPtr[uint32](sqRing, params.SqOff.Flags)
	ring.sqArray = byteOffsetSlice[uint32](sqRing, params.SqOff.Array, int(params.SqEntries))
	ring.cqHead = byteOffsetPtr[uint32](cqRing, params.CqOff.Head)
	ring.cqTail = byteOffsetPtr[uint32](cqRing, params.CqOff.Tail)
	ring.cqMask = byteOffsetPtr[uint32](cqRing, params.CqOff.RingMask)
	ring.cqes = byteOffsetSlice[ioUringCqe](cqRing, params.CqOff.Cqes, int(params.CqEntries))
	ring.sqes = unsafe.Slice((*ioUringSqe)(unsafe.Pointer(unsafe.SliceData(sqesBytes))), int(params.SqEntries))
	ring.localSqTail = atomic.LoadUint32(ring.sqTail)
	ring.submitted = ring.localSqTail
	ring.flags = params.Flags
	ring.features = params.Features
	ring.disabled = params.Flags&ioUringSetupRDisabled != 0
	ring.regRegRing = params.Features&ioUringFeatRegRegRing != 0
	return ring, nil
}

func (ring *ioUring) close() {
	if ring == nil {
		return
	}
	if ring.registeredRing {
		_ = ring.unregisterRingFD()
	}
	if len(ring.sqes) > 0 {
		sqeBytes := unsafe.Slice((*byte)(unsafe.Pointer(unsafe.SliceData(ring.sqes))), len(ring.sqes)*int(unsafe.Sizeof(ioUringSqe{})))
		_ = syscall.Munmap(sqeBytes)
	}
	if len(ring.sqRing) > 0 {
		_ = syscall.Munmap(ring.sqRing)
	}
	if len(ring.cqRing) > 0 && unsafe.Pointer(unsafe.SliceData(ring.cqRing)) != unsafe.Pointer(unsafe.SliceData(ring.sqRing)) {
		_ = syscall.Munmap(ring.cqRing)
	}
	if ring.fd >= 0 {
		_ = syscall.Close(ring.fd)
		ring.fd = -1
	}
}

func (ring *ioUring) accept(fd int, flags uint32) (int, error) {
	if err := ring.prepAccept(fd, flags); err != nil {
		return -1, err
	}
	if _, err := ring.submitAndWait(1); err != nil {
		return -1, err
	}
	cqe, err := ring.waitCqe()
	if err != nil {
		return -1, err
	}
	if cqe.Res < 0 {
		return -1, syscall.Errno(-cqe.Res)
	}
	return int(cqe.Res), nil
}

func (ring *ioUring) recv(fd int, buf []byte, deadline time.Time) (int, error) {
	for {
		if err := ring.prepRecv(fd, buf); err != nil {
			return 0, err
		}
		cqe, err := ring.submitAndAwait(deadline)
		if err != nil {
			return 0, err
		}
		if cqe.Res < 0 {
			err = syscall.Errno(-cqe.Res)
			if isIOUringTransient(err) {
				continue
			}
			return 0, err
		}
		return int(cqe.Res), nil
	}
}

func (ring *ioUring) sendAll(fd int, buf []byte, deadline time.Time) (int, error) {
	total := 0
	for len(buf) > 0 {
		if err := ring.prepSend(fd, buf); err != nil {
			return total, err
		}
		cqe, err := ring.submitAndAwait(deadline)
		if err != nil {
			return total, err
		}
		if cqe.Res < 0 {
			err = syscall.Errno(-cqe.Res)
			if isIOUringTransient(err) {
				continue
			}
			return total, err
		}
		n := int(cqe.Res)
		total += n
		buf = buf[n:]
	}
	return total, nil
}

func (ring *ioUring) prepAccept(fd int, flags uint32) error {
	sqe, err := ring.getSqe()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpAccept
	sqe.FD = int32(fd)
	sqe.OpFlags = flags
	return nil
}

func (ring *ioUring) prepRecv(fd int, buf []byte) error {
	return ring.prepRecvWithFlags(fd, buf, false)
}

func (ring *ioUring) prepRecvWithFlags(fd int, buf []byte, pollFirst bool) error {
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
	return nil
}

func (ring *ioUring) prepSend(fd int, buf []byte) error {
	return ring.prepSendWithFlags(fd, buf, false)
}

func (ring *ioUring) prepSendWithFlags(fd int, buf []byte, pollFirst bool) error {
	return ring.prepSendWithFlagsAndMode(fd, buf, pollFirst, false)
}

func (ring *ioUring) prepSendZCWithFlags(fd int, buf []byte, pollFirst bool) error {
	return ring.prepSendWithFlagsAndMode(fd, buf, pollFirst, true)
}

func (ring *ioUring) prepSendWithFlagsAndMode(fd int, buf []byte, pollFirst bool, zeroCopy bool) error {
	sqe, err := ring.getSqe()
	if err != nil {
		return err
	}
	if zeroCopy {
		sqe.Opcode = ioUringOpSendZC
	} else {
		sqe.Opcode = ioUringOpSend
	}
	if pollFirst {
		sqe.Ioprio = ioUringPollFirst
	}
	if zeroCopy {
		sqe.Ioprio |= ioUringSendZCReportUsage
	}
	sqe.FD = int32(fd)
	sqe.Addr = uint64(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
	sqe.Len = uint32(len(buf))
	return nil
}

func (ring *ioUring) register(op uint32, arg uintptr, nrArgs uint32) error {
	_, err := ring.registerResult(op, arg, nrArgs)
	return err
}

func (ring *ioUring) registerResult(op uint32, arg uintptr, nrArgs uint32) (int, error) {
	if ring == nil || ring.fd < 0 {
		return 0, syscall.EBADF
	}
	fd := ring.fd
	if ring.registeredRing && ring.regRegRing && ring.enterFD >= 0 {
		op |= ioUringRegisterUseRegisteredRing
		fd = ring.enterFD
	}
	ret, _, errno := syscall.Syscall6(ioUringRegisterSyscall, uintptr(fd), uintptr(op), arg, uintptr(nrArgs), 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(ret), nil
}

func (ring *ioUring) enable() error {
	if ring == nil || !ring.disabled {
		return nil
	}
	if err := ring.register(ioUringRegisterEnable, 0, 0); err != nil {
		return err
	}
	ring.disabled = false
	return nil
}

func (ring *ioUring) getSqe() (*ioUringSqe, error) {
	if ring == nil || ring.sqHead == nil || ring.sqEntries == nil || ring.sqMask == nil {
		return nil, syscall.EBADF
	}
	for {
		head := atomic.LoadUint32(ring.sqHead)
		if ring.localSqTail-head < atomic.LoadUint32(ring.sqEntries) {
			index := ring.localSqTail & atomic.LoadUint32(ring.sqMask)
			ring.sqArray[index] = index
			sqe := &ring.sqes[index]
			*sqe = ioUringSqe{}
			ring.localSqTail++
			return sqe, nil
		}
		if _, err := ring.submitAndWait(0); err != nil {
			return nil, err
		}
		head = atomic.LoadUint32(ring.sqHead)
		if ring.localSqTail-head < atomic.LoadUint32(ring.sqEntries) {
			continue
		}
		if _, err := ring.submitAndWait(1); err != nil {
			return nil, err
		}
	}
}

func (ring *ioUring) submitAndWait(minComplete uint32) (uint32, error) {
	for {
		toSubmit := ring.localSqTail - ring.submitted
		if toSubmit != 0 {
			atomic.StoreUint32(ring.sqTail, ring.localSqTail)
		}
		flags := uintptr(0)
		fd := ring.fd
		if ring.registeredRing && ring.enterFD >= 0 {
			fd = ring.enterFD
			flags |= ioUringEnterRegistered
		}
		if minComplete != 0 {
			flags = ioUringEnterGetEvents
			if ring.registeredRing && ring.enterFD >= 0 {
				flags |= ioUringEnterRegistered
			}
		}
		submitted, _, errno := syscall.Syscall6(ioUringEnterSyscall, uintptr(fd), uintptr(toSubmit), uintptr(minComplete), flags, 0, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return 0, errno
		}
		ring.submitted += uint32(submitted)
		return uint32(submitted), nil
	}
}

func (ring *ioUring) registerRingFD() error {
	if ring == nil || ring.fd < 0 || ring.registeredRing {
		return nil
	}
	update := ioUringRsrcUpdate{
		Offset: ^uint32(0),
		Data:   uint64(ring.fd),
	}
	ret, err := ring.registerResult(ioUringRegisterRingFDs, uintptr(unsafe.Pointer(&update)), 1)
	if err != nil {
		return err
	}
	if ret == 1 {
		ring.enterFD = int(update.Offset)
		ring.registeredRing = true
	}
	return nil
}

func (ring *ioUring) unregisterRingFD() error {
	if ring == nil || !ring.registeredRing {
		return nil
	}
	update := ioUringRsrcUpdate{Offset: uint32(ring.enterFD)}
	ret, err := ring.registerResult(ioUringUnregisterRingFDs, uintptr(unsafe.Pointer(&update)), 1)
	if err != nil {
		return err
	}
	if ret == 1 {
		ring.registeredRing = false
		ring.enterFD = ring.fd
	}
	return nil
}

func (ring *ioUring) supportsRecvSendBundle() bool {
	return ring != nil && ring.features&ioUringFeatRecvSendBundle != 0
}

func (ring *ioUring) canUseSendZC() bool {
	if ring == nil {
		return false
	}
	if ring.sendZCState == 0 {
		probe := getIOUringStartupProbe()
		if probe.sendZCOK {
			ring.sendZCState = 1
		} else {
			ring.sendZCState = 2
		}
	}
	return ring.sendZCState == 1
}

func (ring *ioUring) markSendZCSupported() {
	if ring != nil {
		ring.sendZCState = 1
	}
}

func (ring *ioUring) markSendZCUnsupported() {
	if ring != nil {
		ring.sendZCState = 2
	}
}

func (ring *ioUring) cancelFD(fd int, opcode uint8) error {
	if ring == nil || ring.fd < 0 || fd < 0 {
		return nil
	}
	if ring.syncCancelState == 2 {
		return nil
	}
	reg := ioUringSyncCancelReg{
		FD:    int32(fd),
		Flags: ioUringAsyncCancelFD | ioUringAsyncCancelAll,
	}
	if opcode != 0 {
		reg.Flags |= ioUringAsyncCancelOp
		reg.Opcode = opcode
	}
	_, err := ring.registerResult(ioUringRegisterSyncCancel, uintptr(unsafe.Pointer(&reg)), 1)
	if err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP) {
			ring.syncCancelState = 2
			return nil
		}
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ETIME) || errors.Is(err, syscall.EALREADY) {
			ring.syncCancelState = 1
			return nil
		}
		return err
	}
	if ring.syncCancelState == 0 {
		ring.syncCancelState = 1
	}
	return nil
}

func (ring *ioUring) waitCqe() (ioUringCqe, error) {
	for {
		head := atomic.LoadUint32(ring.cqHead)
		tail := atomic.LoadUint32(ring.cqTail)
		if head != tail {
			index := head & atomic.LoadUint32(ring.cqMask)
			item := ring.cqes[index]
			atomic.StoreUint32(ring.cqHead, head+1)
			return item, nil
		}
		if _, err := ring.submitAndWait(1); err != nil {
			return ioUringCqe{}, err
		}
	}
}

func (ring *ioUring) peekBatch(dst []ioUringCqe) int {
	head := atomic.LoadUint32(ring.cqHead)
	tail := atomic.LoadUint32(ring.cqTail)
	available := int(tail - head)
	if available == 0 {
		return 0
	}
	if available > len(dst) {
		available = len(dst)
	}
	mask := atomic.LoadUint32(ring.cqMask)
	for i := 0; i < available; i++ {
		dst[i] = ring.cqes[(head+uint32(i))&mask]
	}
	atomic.StoreUint32(ring.cqHead, head+uint32(available))
	return available
}

func (ring *ioUring) tryCqe() (ioUringCqe, bool) {
	head := atomic.LoadUint32(ring.cqHead)
	tail := atomic.LoadUint32(ring.cqTail)
	if head == tail {
		return ioUringCqe{}, false
	}
	index := head & atomic.LoadUint32(ring.cqMask)
	item := ring.cqes[index]
	atomic.StoreUint32(ring.cqHead, head+1)
	return item, true
}

func (ring *ioUring) submitAndAwait(deadline time.Time) (ioUringCqe, error) {
	if _, err := ring.submitAndWait(0); err != nil {
		return ioUringCqe{}, err
	}
	if deadline.IsZero() {
		return ring.waitCqe()
	}
	for {
		if cqe, ok := ring.tryCqe(); ok {
			return cqe, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ioUringCqe{}, errIOUringDeadlineExceeded
		}
		timeoutMS := int(remaining / time.Millisecond)
		if timeoutMS < 1 {
			timeoutMS = 1
		}
		fds := []unix.PollFd{{Fd: int32(ring.fd), Events: unix.POLLIN}}
		ready, err := unix.Poll(fds, timeoutMS)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return ioUringCqe{}, err
		}
		if ready == 0 {
			return ioUringCqe{}, errIOUringDeadlineExceeded
		}
	}
}

func byteOffsetPtr[T any](base []byte, offset uint32) *T {
	return (*T)(unsafe.Pointer(unsafe.SliceData(base[offset:])))
}

func byteOffsetSlice[T any](base []byte, offset uint32, length int) []T {
	if length == 0 {
		return nil
	}
	return unsafe.Slice((*T)(unsafe.Pointer(unsafe.SliceData(base[offset:]))), length)
}
