//go:build linux && amd64

package core

import (
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var udpDeadlineZero time.Time

const (
	ioUringOpSendmsg = 9
	ioUringOpRecvmsg = 10
	soReusePort      = 15
	quicRingEntries  = 1024
	quicSendMaxBatch = 256

	solUDP          = 17
	udpSegment      = 103
	gsoMaxSegments  = 16
	gsoCmsgHdrLen   = 16
	gsoCmsgLen      = 18
	gsoCmsgSpace    = 24
)

type cmsghdr struct {
	Len   uint64
	Level int32
	Type  int32
}

func buildGSOCmsg(buf []byte, segSize uint16) {
	h := (*cmsghdr)(unsafe.Pointer(&buf[0]))
	h.Len = gsoCmsgLen
	h.Level = solUDP
	h.Type = udpSegment
	*(*uint16)(unsafe.Pointer(&buf[gsoCmsgHdrLen])) = segSize
}

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
	fd        int
	recvRing  *ioUring
	sendRing  *ioUring
	writeMu   sync.Mutex
	recvMu    sync.Mutex
	closed    atomic.Bool
	done      chan struct{}
	sendCh    chan quicSendReq
	sendStart sync.Once
}

type quicSendReq struct {
	data []byte
	addr *net.UDPAddr
	pbuf *[]byte
}

func newIOUringUDPConn(fd int) (*ioUringUDPConn, error) {
	recvRing, err := newIOUring(quicRingEntries)
	if err != nil {
		return nil, err
	}
	sendRing, err := newIOUring(quicRingEntries)
	if err != nil {
		recvRing.close()
		return nil, err
	}
	return &ioUringUDPConn{
		fd:       fd,
		recvRing: recvRing,
		sendRing: sendRing,
		done:     make(chan struct{}),
		sendCh:   make(chan quicSendReq, 16384),
	}, nil
}

func (c *ioUringUDPConn) sendTo(buf []byte, addr *net.UDPAddr) (int, error) {
	return c.sendToPooled(buf, addr, nil)
}

func (c *ioUringUDPConn) sendToPooled(buf []byte, addr *net.UDPAddr, pbuf *[]byte) (int, error) {
	if c.closed.Load() {
		if pbuf != nil {
			quicPktBufPool.Put(pbuf)
		}
		return 0, net.ErrClosed
	}
	select {
	case c.sendCh <- quicSendReq{data: buf, addr: addr, pbuf: pbuf}:
		return len(buf), nil
	default:
		if pbuf != nil {
			quicPktBufPool.Put(pbuf)
		}
		return 0, nil
	}
}

func (c *ioUringUDPConn) startSendLoop() {
	c.sendStart.Do(func() { go c.sendLoop() })
}

func (c *ioUringUDPConn) sendLoop() {
	batch := make([]quicSendReq, 0, quicSendMaxBatch)
	msgs := make([]msghdr, quicSendMaxBatch)
	iovs := make([]iovec, quicSendMaxBatch)
	sas := make([]syscall.RawSockaddrInet4, quicSendMaxBatch)
	ctrls := make([][gsoCmsgSpace]byte, quicSendMaxBatch)
	for {
		select {
		case req := <-c.sendCh:
			batch = append(batch[:0], req)
		case <-c.done:
			return
		}
	drain:
		for len(batch) < quicSendMaxBatch {
			select {
			case r := <-c.sendCh:
				batch = append(batch, r)
			default:
				break drain
			}
		}
		if c.closed.Load() || c.sendRing == nil {
			return
		}
		n := len(batch)
		if n > 1 {
			slices.SortFunc(batch, func(a, b quicSendReq) int {
				ai := uintptr(unsafe.Pointer(a.addr))
				bi := uintptr(unsafe.Pointer(b.addr))
				if ai != bi {
					if ai < bi {
						return -1
					}
					return 1
				}
				return len(b.data) - len(a.data)
			})
		}
		submitted := uint32(0)
		iovIdx := 0
		i := 0
		for i < n {
			r := batch[i]
			if len(r.data) == 0 || r.addr == nil {
				i++
				continue
			}
			j := i + 1
			for j < n && j-i < gsoMaxSegments && batch[j].addr == r.addr && len(batch[j].data) == len(r.data) {
				j++
			}
			if j < n && j-i < gsoMaxSegments && batch[j].addr == r.addr && len(batch[j].data) < len(r.data) {
				j++
			}
			cnt := j - i
			grp := int(submitted)
			iovStart := iovIdx
			for k := i; k < j; k++ {
				iovs[iovIdx] = iovec{Base: &batch[k].data[0], Len: uint64(len(batch[k].data))}
				iovIdx++
			}
			sas[grp] = udpAddrToSockaddr4(r.addr)
			msgs[grp] = msghdr{
				Name:    (*byte)(unsafe.Pointer(&sas[grp])),
				Namelen: uint32(unsafe.Sizeof(sas[grp])),
				Iov:     &iovs[iovStart],
				Iovlen:  uint64(cnt),
			}
			if cnt > 1 {
				buildGSOCmsg(ctrls[grp][:], uint16(len(r.data)))
				msgs[grp].Control = &ctrls[grp][0]
				msgs[grp].Controllen = gsoCmsgLen
			}
			if err := c.sendRing.prepSendmsg(c.fd, &msgs[grp]); err != nil {
				break
			}
			submitted++
			i = j
		}
		if submitted > 0 {
			if _, err := c.sendRing.submitAndWait(submitted); err != nil && c.closed.Load() {
				return
			}
			for {
				if _, ok := c.sendRing.tryCqe(); !ok {
					break
				}
			}
		}
		for bi := range batch {
			if batch[bi].pbuf != nil {
				quicPktBufPool.Put(batch[bi].pbuf)
				batch[bi].pbuf = nil
			}
		}
	}
}

func (c *ioUringUDPConn) recvmsgURing(buf []byte) (int, *net.UDPAddr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if len(buf) == 0 {
		return 0, nil, syscall.EINVAL
	}
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	if c.closed.Load() || c.fd < 0 || c.recvRing == nil {
		return 0, nil, net.ErrClosed
	}
	var rsa syscall.RawSockaddrInet4
	iov := iovec{Base: &buf[0], Len: uint64(len(buf))}
	msg := msghdr{Iov: &iov, Iovlen: 1}
	for {
		rsa = syscall.RawSockaddrInet4{}
		msg.Name = (*byte)(unsafe.Pointer(&rsa))
		msg.Namelen = uint32(unsafe.Sizeof(rsa))
		if err := c.recvRing.prepRecvmsg(c.fd, &msg); err != nil {
			return 0, nil, err
		}
		cqe, err := c.recvRing.submitAndAwait(udpDeadlineZero)
		if err != nil {
			return 0, nil, err
		}
		if cqe.Res < 0 {
			e := syscall.Errno(-cqe.Res)
			if isIOUringTransient(e) {
				continue
			}
			if c.closed.Load() {
				return 0, nil, net.ErrClosed
			}
			return 0, nil, e
		}
		return int(cqe.Res), sockaddrToUDPAddr(&rsa), nil
	}
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

func (ring *ioUring) prepRecvmsgMultishotUser(fd int, bgid uint16, msg *msghdr, userData uint64, pollFirst bool) error {
	sqe, err := ring.getSqeNoClear()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpRecvmsg
	sqe.Ioprio = ioUringRecvMultishot
	if pollFirst {
		sqe.Ioprio |= ioUringPollFirst
	}
	sqe.Flags = ioUringSqeBufferSelect
	sqe.FD = int32(fd)
	sqe.Off = 0
	sqe.Addr = uint64(uintptr(unsafe.Pointer(msg)))
	sqe.Len = 1
	sqe.OpFlags = 0
	sqe.UserData = userData
	sqe.BufIndex = bgid
	sqe.Personality = 0
	sqe.SpliceFDIn = 0
	sqe.Addr3 = 0
	sqe.Pad2 = 0
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

		const bufSize = 64 << 20
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
