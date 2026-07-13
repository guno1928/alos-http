//go:build linux && amd64

package core

import (
	"context"
	"crypto/tls"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// enableProxyFuse turns on the single-syscall send+recv fuse for a pooled
// backend connection (works below TLS). Only pooled forward connections call
// this; websocket connections (dialed directly) stay unfused so their
// bidirectional streaming is not deferred.
func enableProxyFuse(conn net.Conn) {
	switch c := conn.(type) {
	case *proxyUringConn:
		c.fuseEnabled = true
	case *tls.Conn:
		if raw, ok := c.NetConn().(*proxyUringConn); ok {
			raw.fuseEnabled = true
		}
	}
}

const (
	proxyRingEntries = 64
	proxyConnEntries = 16
	proxyFuseMaxSend = 60000
)

type proxyRingPool struct {
	readRings    []*ioUring
	writeRings   []*ioUring
	connectRings []*ioUring
	readMu       []sync.Mutex
	writeMu      []sync.Mutex
	connectMu    []sync.Mutex
	count        int
	nextRead     atomic.Uint64
	nextWrite    atomic.Uint64
	nextConnect  atomic.Uint64
	closed       atomic.Bool
}

var (
	globalProxyRingPool     *proxyRingPool
	globalProxyRingPoolOnce sync.Once
	globalProxyRingPoolErr  error
)

func getProxyRingPool() (*proxyRingPool, error) {
	globalProxyRingPoolOnce.Do(func() {
		globalProxyRingPool, globalProxyRingPoolErr = newProxyRingPool()
	})
	return globalProxyRingPool, globalProxyRingPoolErr
}

func proxyRingPoolSize() int {
	n := runtime.NumCPU() * 4
	if n < 4 {
		n = 4
	}
	if n > 128 {
		n = 128
	}
	return n
}

func newProxyRingPool() (*proxyRingPool, error) {
	n := proxyRingPoolSize()
	pool := &proxyRingPool{
		readRings:    make([]*ioUring, n),
		writeRings:   make([]*ioUring, n),
		connectRings: make([]*ioUring, n),
		readMu:       make([]sync.Mutex, n),
		writeMu:      make([]sync.Mutex, n),
		connectMu:    make([]sync.Mutex, n),
		count:        n,
	}

	for i := 0; i < n; i++ {
		var err error
		pool.readRings[i], err = newIOUring(proxyRingEntries)
		if err != nil {
			pool.close()
			return nil, err
		}
		pool.writeRings[i], err = newIOUring(proxyRingEntries)
		if err != nil {
			pool.close()
			return nil, err
		}
		pool.connectRings[i], err = newIOUring(proxyConnEntries)
		if err != nil {
			pool.close()
			return nil, err
		}
	}

	return pool, nil
}

func (p *proxyRingPool) close() {
	if p == nil || !p.closed.CompareAndSwap(false, true) {
		return
	}
	for i := 0; i < p.count; i++ {
		if p.readRings[i] != nil {
			p.readRings[i].close()
		}
		if p.writeRings[i] != nil {
			p.writeRings[i].close()
		}
		if p.connectRings[i] != nil {
			p.connectRings[i].close()
		}
	}
}

func (p *proxyRingPool) acquireReadRing() (*ioUring, int) {
	idx := int(p.nextRead.Add(1) % uint64(p.count))
	p.readMu[idx].Lock()
	return p.readRings[idx], idx
}

func (p *proxyRingPool) releaseReadRing(idx int) {
	p.readMu[idx].Unlock()
}

func (p *proxyRingPool) acquireWriteRing() (*ioUring, int) {
	idx := int(p.nextWrite.Add(1) % uint64(p.count))
	p.writeMu[idx].Lock()
	return p.writeRings[idx], idx
}

func (p *proxyRingPool) releaseWriteRing(idx int) {
	p.writeMu[idx].Unlock()
}

func (p *proxyRingPool) doConnect(fd int, sa *unix.RawSockaddrInet4, deadline time.Time) error {
	idx := int(p.nextConnect.Add(1) % uint64(p.count))
	p.connectMu[idx].Lock()
	ring := p.connectRings[idx]
	err := ring.connect(fd, unsafe.Pointer(sa), uint64(unsafe.Sizeof(*sa)), deadline)
	p.connectMu[idx].Unlock()
	runtime.KeepAlive(sa)
	return err
}

type proxyUringConn struct {
	fd          int
	pool        *proxyRingPool
	readRing    *ioUring
	writeRing   *ioUring
	pendingSend []byte
	fuseEnabled bool
	readMu      sync.Mutex
	writeMu     sync.Mutex
	closeOnce  sync.Once
	closed     atomic.Bool
	readDLN    atomic.Int64
	writeDLN   atomic.Int64
	localAddr  net.Addr
	remoteAddr net.Addr
	onClose    func()
}

func newProxyUringConn(fd int, pool *proxyRingPool) (*proxyUringConn, error) {
	prepareAcceptedFD(fd)
	rr, err := newIOUring(proxyRingEntries)
	if err != nil {
		return nil, err
	}
	wr, err := newIOUring(proxyRingEntries)
	if err != nil {
		rr.close()
		return nil, err
	}
	localAddr, remoteAddr := socketAddrs(fd)
	return &proxyUringConn{
		fd:         fd,
		pool:       pool,
		readRing:   rr,
		writeRing:  wr,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}, nil
}

func (c *proxyUringConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.readMu.Lock()
	if c.closed.Load() {
		c.readMu.Unlock()
		return 0, net.ErrClosed
	}

	if c.fuseEnabled {
		c.writeMu.Lock()
		pend := c.pendingSend
		c.pendingSend = c.pendingSend[:0]
		c.writeMu.Unlock()
		if len(pend) > 0 {
			if len(pend) <= proxyFuseMaxSend {
				n, err := c.readRing.sendRecvLinked(c.fd, pend, p, c.readDeadline())
				err = c.normalizeError(err)
				c.readMu.Unlock()
				if err != nil {
					_ = c.Close()
				}
				return n, err
			}
			if _, err := c.writeRing.sendAll(c.fd, pend, c.writeDeadline()); err != nil {
				err = c.normalizeError(err)
				c.readMu.Unlock()
				_ = c.Close()
				return 0, err
			}
		}
	}

	n, err := c.readRing.recv(c.fd, p, c.readDeadline())

	err = c.normalizeError(err)
	c.readMu.Unlock()
	if err == errIOUringDeadlineExceeded {
		_ = c.Close()
	}
	return n, err
}

func (c *proxyUringConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.writeMu.Lock()
	if c.closed.Load() {
		c.writeMu.Unlock()
		return 0, net.ErrClosed
	}

	if c.fuseEnabled {
		c.pendingSend = append(c.pendingSend, p...)
		c.writeMu.Unlock()
		return len(p), nil
	}

	n, err := c.writeRing.sendAll(c.fd, p, c.writeDeadline())

	err = c.normalizeError(err)
	c.writeMu.Unlock()
	if err == errIOUringDeadlineExceeded {
		_ = c.Close()
	}
	return n, err
}

func (c *proxyUringConn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		if c.fd >= 0 {
			_ = syscall.Shutdown(c.fd, syscall.SHUT_RDWR)
		}
		c.readMu.Lock()
		c.writeMu.Lock()
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
		c.writeMu.Unlock()
		c.readMu.Unlock()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return closeErr
}

func (c *proxyUringConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *proxyUringConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *proxyUringConn) SetDeadline(t time.Time) error {
	c.readDLN.Store(deadlineUnixNano(t))
	c.writeDLN.Store(deadlineUnixNano(t))
	return nil
}

func (c *proxyUringConn) SetReadDeadline(t time.Time) error {
	c.readDLN.Store(deadlineUnixNano(t))
	return nil
}

func (c *proxyUringConn) SetWriteDeadline(t time.Time) error {
	c.writeDLN.Store(deadlineUnixNano(t))
	return nil
}

func (c *proxyUringConn) readDeadline() time.Time {
	return deadlineFromUnixNano(c.readDLN.Load())
}

func (c *proxyUringConn) writeDeadline() time.Time {
	return deadlineFromUnixNano(c.writeDLN.Load())
}

func (c *proxyUringConn) normalizeError(err error) error {
	if err == nil || err == errIOUringDeadlineExceeded {
		return err
	}
	if c.closed.Load() && isIOUringConnCloseError(err) {
		return net.ErrClosed
	}
	return err
}

func (c *proxyUringConn) SyscallConn() (syscall.RawConn, error) {
	if c.closed.Load() {
		return nil, net.ErrClosed
	}
	return proxyUringRawConn{conn: c}, nil
}

type proxyUringRawConn struct {
	conn *proxyUringConn
}

func (rc proxyUringRawConn) Control(fn func(fd uintptr)) error {
	if rc.conn == nil || rc.conn.fd < 0 {
		return net.ErrClosed
	}
	fn(uintptr(rc.conn.fd))
	return nil
}

func (rc proxyUringRawConn) Read(fn func(fd uintptr) bool) error {
	if rc.conn == nil || rc.conn.fd < 0 {
		return net.ErrClosed
	}
	fn(uintptr(rc.conn.fd))
	return nil
}

func (rc proxyUringRawConn) Write(fn func(fd uintptr) bool) error {
	if rc.conn == nil || rc.conn.fd < 0 {
		return net.ErrClosed
	}
	fn(uintptr(rc.conn.fd))
	return nil
}

func dialProxyConn(addr string, timeout time.Duration) (net.Conn, error) {
	pool, err := getProxyRingPool()
	if err != nil {
		return DialTCP4(addr, timeout)
	}

	host, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return nil, splitErr
	}

	resolved := addr
	if net.ParseIP(host) == nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		ip, err := resolveIPv4(ctx, host)
		if err != nil {
			return nil, err
		}
		resolved = net.JoinHostPort(ip.String(), port)
	}

	rHost, portText, err := net.SplitHostPort(resolved)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(rHost).To4()
	if ip == nil {
		return nil, &net.AddrError{Err: "non-IPv4 address", Addr: resolved}
	}
	portNum, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	if portNum < 0 || portNum > 65535 {
		return nil, &net.AddrError{Err: "invalid port", Addr: resolved}
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|sockCloexec|sockNonblock, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}

	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	sa := &unix.RawSockaddrInet4{Family: unix.AF_INET, Port: htons(uint16(portNum))}
	copy(sa.Addr[:], ip)

	if connectErr := pool.doConnect(fd, sa, deadline); connectErr != nil {
		_ = syscall.Close(fd)
		return nil, connectErr
	}

	return newProxyUringConn(fd, pool)
}
