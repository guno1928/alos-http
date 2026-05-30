//go:build linux && amd64

package core

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var udpDeadlineZero time.Time

const (
	ioUringOpRecvmsg   = 5
	ioUringOpSendmsg   = 9
	soReusePort        = 15
)

type iovec struct {
	Base *byte
	Len  uint64
}

type msghdr struct {
	Name       *byte
	Namelen    uint32
	Pad_cgo_0  [4]byte
	Iov        *iovec
	Iovlen     uint64
	Control    *byte
	Controllen uint64
	Flags      int32
	Pad_cgo_1  [4]byte
}

type ioUringUDPConn struct {
	fd       int
	recvRing *ioUring
	sendRing *ioUring
	writeMu  sync.Mutex
	recvMu   sync.Mutex
	closed   atomic.Bool
	done     chan struct{}
}

func newIOUringUDPConn(fd int) (*ioUringUDPConn, error) {
	recvRing, err := newIOUring(ioUringConnEntries)
	if err != nil {
		return nil, err
	}
	sendRing, err := newIOUring(ioUringConnEntries)
	if err != nil {
		recvRing.close()
		return nil, err
	}
	return &ioUringUDPConn{
		fd:       fd,
		recvRing: recvRing,
		sendRing: sendRing,
		done:     make(chan struct{}),
	}, nil
}

func (c *ioUringUDPConn) recvFrom(buf []byte) (int, *net.UDPAddr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}

	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}

	for {
		n, err := c.recvRing.recv(c.fd, buf, udpDeadlineZero)
		if err != nil {
			if isIOUringTransient(err) {
				continue
			}
			return 0, nil, err
		}

		rsa, _ := syscall.Getpeername(c.fd)
		var addr *net.UDPAddr
		if sa4, ok := rsa.(*syscall.SockaddrInet4); ok {
			ip := make(net.IP, net.IPv4len)
			copy(ip, sa4.Addr[:])
			addr = &net.UDPAddr{IP: ip, Port: sa4.Port}
		} else {
			addr = &net.UDPAddr{}
		}

		return n, addr, nil
	}
}

func (c *ioUringUDPConn) recvFromSyscall(buf []byte) (int, *net.UDPAddr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}

	c.recvMu.Lock()
	fd := c.fd
	c.recvMu.Unlock()
	if fd < 0 {
		return 0, nil, net.ErrClosed
	}

	for {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			if c.closed.Load() {
				return 0, nil, net.ErrClosed
			}
			return 0, nil, err
		}

		var addr *net.UDPAddr
		if sa4, ok := from.(*syscall.SockaddrInet4); ok {
			ip := make(net.IP, net.IPv4len)
			copy(ip, sa4.Addr[:])
			addr = &net.UDPAddr{IP: ip, Port: sa4.Port}
		} else if sa6, ok := from.(*syscall.SockaddrInet6); ok {
			ip := make(net.IP, net.IPv6len)
			copy(ip, sa6.Addr[:])
			addr = &net.UDPAddr{IP: ip, Port: sa6.Port, Zone: zoneName(sa6.ZoneId)}
		} else {
			addr = &net.UDPAddr{}
		}

		return n, addr, nil
	}
}

func (c *ioUringUDPConn) sendTo(buf []byte, addr *net.UDPAddr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	ip4 := addr.IP.To4()
	if ip4 == nil {
		return 0, &net.AddrError{Err: "non-IPv4 address", Addr: addr.String()}
	}
	sa := &syscall.SockaddrInet4{Port: addr.Port}
	copy(sa.Addr[:], ip4)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	err := syscall.Sendto(c.fd, buf, syscall.MSG_DONTWAIT, sa)
	if err != nil {
		if debugFlag.Load() {
			log.Printf("[H3-DBG] sendTo: FAILED %d bytes to %s: %v", len(buf), addr, err)
		}
		return 0, err
	}
	if debugFlag.Load() {
		log.Printf("[H3-DBG] sendTo: sent %d bytes to %s fd=%d", len(buf), addr, c.fd)
	}
	return len(buf), nil
}

func (c *ioUringUDPConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(c.done)
	fd := c.fd
	if fd >= 0 {
		syscall.Shutdown(fd, syscall.SHUT_RDWR)
	}
	c.recvMu.Lock()
	c.writeMu.Lock()
	var closeErr error
	if c.fd >= 0 {
		closeErr = syscall.Close(c.fd)
		c.fd = -1
	}
	if c.recvRing != nil {
		c.recvRing.close()
		c.recvRing = nil
	}
	if c.sendRing != nil {
		c.sendRing.close()
		c.sendRing = nil
	}
	c.writeMu.Unlock()
	c.recvMu.Unlock()
	return closeErr
}

func (ring *ioUring) prepRecvmsg(fd int, msg *msghdr) error {
	sqe, err := ring.getSqe()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpRecvmsg
	sqe.FD = int32(fd)
	sqe.Addr = uint64(uintptr(unsafe.Pointer(msg)))
	sqe.Len = 1
	return nil
}

func (ring *ioUring) prepSendmsg(fd int, msg *msghdr) error {
	sqe, err := ring.getSqe()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpSendmsg
	sqe.FD = int32(fd)
	sqe.Addr = uint64(uintptr(unsafe.Pointer(msg)))
	sqe.Len = 1
	return nil
}

func createQUICListenersIOUring(addr string, count int) ([]*ioUringUDPConn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4zero
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("non-IPv4 address: %s", host)
	}

	conns := make([]*ioUringUDPConn, 0, count)
	for i := 0; i < count; i++ {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|sockCloexec, syscall.IPPROTO_UDP)
		if err != nil {
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, fmt.Errorf("socket: %w", err)
		}

		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			_ = syscall.Close(fd)
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, fmt.Errorf("SO_REUSEADDR: %w", err)
		}

		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soReusePort, 1); err != nil {
			_ = syscall.Close(fd)
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, fmt.Errorf("SO_REUSEPORT: %w", err)
		}

		const bufSize = 4 << 20
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, bufSize)
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, bufSize)

		sa := &syscall.SockaddrInet4{Port: port}
		copy(sa.Addr[:], ip4)
		if err := syscall.Bind(fd, sa); err != nil {
			_ = syscall.Close(fd)
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, fmt.Errorf("bind: %w", err)
		}

		conn, err := newIOUringUDPConn(fd)
		if err != nil {
			_ = syscall.Close(fd)
			for _, c := range conns {
				_ = c.Close()
			}
			return nil, err
		}
		conns = append(conns, conn)
	}

	return conns, nil
}

func sockaddrToUDPAddr(sa *syscall.RawSockaddrInet4) *net.UDPAddr {
	ip := make(net.IP, net.IPv4len)
	copy(ip, sa.Addr[:])
	port := int(htons(sa.Port))
	return &net.UDPAddr{IP: ip, Port: port}
}

func udpAddrToSockaddr4(addr *net.UDPAddr) syscall.RawSockaddrInet4 {
	sa := syscall.RawSockaddrInet4{Family: syscall.AF_INET}
	sa.Port = htons(uint16(addr.Port))
	ip4 := addr.IP.To4()
	if ip4 != nil {
		copy(sa.Addr[:], ip4)
	}
	return sa
}
