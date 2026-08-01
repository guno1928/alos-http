//go:build linux && amd64

package core

import (
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func sortSendBatchByAddr(batch []quicSendReq) {
	slices.SortStableFunc(batch, func(a, b quicSendReq) int {
		ai := uintptr(unsafe.Pointer(a.addr))
		bi := uintptr(unsafe.Pointer(b.addr))
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
		return 0
	})
}

const (
	epollQUICRecvBatch = 64
	epollQUICDgramSize = 2048
	epollQUICSendQueue = 1024
)

type mmsghdr struct {
	Hdr msghdr
	Len uint32
	_   [4]byte
}

type epollUDPConn struct {
	fd        int
	closed    atomic.Bool
	done      chan struct{}
	sendCh    chan quicSendReq
	sendStart sync.Once
}

func (uc *epollUDPConn) sendTo(buf []byte, addr *net.UDPAddr) (int, error) {
	return uc.sendToPooled(buf, addr, nil)
}

func (uc *epollUDPConn) sendToPooled(buf []byte, addr *net.UDPAddr, pbuf *[]byte) (int, error) {
	if uc.closed.Load() || addr == nil {
		if pbuf != nil {
			quicPktBufPool.Put(pbuf)
		}
		return 0, unix.EBADF
	}
	select {
	case uc.sendCh <- quicSendReq{data: buf, addr: addr, pbuf: pbuf}:
		return len(buf), nil
	default:
		if pbuf != nil {
			quicPktBufPool.Put(pbuf)
		}
		return 0, nil
	}
}

func (uc *epollUDPConn) startSendLoop() {
	uc.sendStart.Do(func() { go uc.sendLoop() })
}

func (uc *epollUDPConn) sendLoop() {
	batch := make([]quicSendReq, 0, quicSendMaxBatch)
	msgs := make([]msghdr, quicSendMaxBatch)
	iovs := make([]iovec, quicSendMaxBatch)
	sas := make([]syscall.RawSockaddrInet4, quicSendMaxBatch)
	ctrls := make([][gsoCmsgSpace]byte, quicSendMaxBatch)
	mmsgs := make([]mmsghdr, quicSendMaxBatch)
	for {
		select {
		case req := <-uc.sendCh:
			batch = append(batch[:0], req)
		case <-uc.done:
			return
		}
	drain:
		for len(batch) < quicSendMaxBatch {
			select {
			case r := <-uc.sendCh:
				batch = append(batch, r)
			default:
				break drain
			}
		}
		if uc.closed.Load() {
			return
		}
		n := len(batch)
		if n > 1 {
			sortSendBatchByAddr(batch)
		}
		groups := 0
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
			iovStart := iovIdx
			for k := i; k < j; k++ {
				iovs[iovIdx] = iovec{Base: &batch[k].data[0], Len: uint64(len(batch[k].data))}
				iovIdx++
			}
			sas[groups] = udpAddrToSockaddr4(r.addr)
			msgs[groups] = msghdr{
				Name:    (*byte)(unsafe.Pointer(&sas[groups])),
				Namelen: uint32(unsafe.Sizeof(sas[groups])),
				Iov:     &iovs[iovStart],
				Iovlen:  uint64(cnt),
			}
			if cnt > 1 {
				buildGSOCmsg(ctrls[groups][:], uint16(len(r.data)))
				msgs[groups].Control = &ctrls[groups][0]
				msgs[groups].Controllen = gsoCmsgLen
			}
			mmsgs[groups].Hdr = msgs[groups]
			groups++
			i = j
		}
		sent := 0
		for sent < groups {
			r1, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(uc.fd), uintptr(unsafe.Pointer(&mmsgs[sent])), uintptr(groups-sent), 0, 0, 0)
			if errno != 0 {
				if errno == unix.EINTR {
					continue
				}
				break
			}
			if r1 == 0 {
				break
			}
			sent += int(r1)
		}
		for bi := range batch {
			if batch[bi].pbuf != nil {
				quicPktBufPool.Put(batch[bi].pbuf)
				batch[bi].pbuf = nil
			}
		}
	}
}

func (uc *epollUDPConn) close() {
	if uc.closed.CompareAndSwap(false, true) {
		close(uc.done)
		_ = unix.Close(uc.fd)
	}
}

func createEpollQUICListeners(addr string, count int) ([]*epollUDPConn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return nil, err
	}
	var ip4 [4]byte
	if host != "" && host != "0.0.0.0" && host != "::" {
		ipAddr := net.ParseIP(host)
		if ipAddr == nil {
			return nil, fmt.Errorf("bad host %q", host)
		}
		if v4 := ipAddr.To4(); v4 != nil {
			copy(ip4[:], v4)
		} else {
			return nil, fmt.Errorf("non-IPv4 address: %s", host)
		}
	}
	if count < 1 {
		count = 1
	}
	conns := make([]*epollUDPConn, 0, count)
	for i := 0; i < count; i++ {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
		if err != nil {
			return nil, fmt.Errorf("socket: %w", err)
		}
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		sa := &unix.SockaddrInet4{Port: port, Addr: ip4}
		if err := unix.Bind(fd, sa); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("bind: %w", err)
		}
		conns = append(conns, &epollUDPConn{fd: fd, done: make(chan struct{}), sendCh: make(chan quicSendReq, epollQUICSendQueue)})
	}
	return conns, nil
}

func (s *Server) serveEpollQUIC(uc *epollUDPConn, connMap *quicConnMap) {
	startReqStreamWorkers()
	uc.startSendLoop()
	bufs := make([]byte, epollQUICRecvBatch*epollQUICDgramSize)
	sas := make([]syscall.RawSockaddrInet4, epollQUICRecvBatch)
	iovs := make([]iovec, epollQUICRecvBatch)
	mmsgs := make([]mmsghdr, epollQUICRecvBatch)
	for i := 0; i < epollQUICRecvBatch; i++ {
		iovs[i] = iovec{Base: &bufs[i*epollQUICDgramSize], Len: epollQUICDgramSize}
		mmsgs[i].Hdr = msghdr{
			Name:    (*byte)(unsafe.Pointer(&sas[i])),
			Namelen: uint32(unsafe.Sizeof(sas[i])),
			Iov:     &iovs[i],
			Iovlen:  1,
		}
	}
	for {
		if uc.closed.Load() || s.shuttingDown.Load() {
			return
		}
		for i := range mmsgs {
			mmsgs[i].Hdr.Namelen = uint32(unsafe.Sizeof(sas[i]))
			iovs[i].Len = epollQUICDgramSize
			mmsgs[i].Len = 0
		}
		r1, _, errno := unix.Syscall6(unix.SYS_RECVMMSG, uintptr(uc.fd), uintptr(unsafe.Pointer(&mmsgs[0])), uintptr(len(mmsgs)), uintptr(unix.MSG_WAITFORONE), 0, 0)
		if errno != 0 {
			if uc.closed.Load() || s.shuttingDown.Load() {
				return
			}
			if errno == unix.EINTR || errno == unix.EAGAIN {
				continue
			}
			return
		}
		count := int(r1)
		for i := 0; i < count; i++ {
			n := int(mmsgs[i].Len)
			if n < 5 {
				continue
			}
			data := bufs[i*epollQUICDgramSize : i*epollQUICDgramSize+n]
			var remoteAddr *net.UDPAddr
			if quicIsLongHeader(data) {
				remoteAddr = sockaddrToUDPAddr(&sas[i])
			}
			pbuf := quicRecvBufPool.Get().(*[]byte)
			*pbuf = append((*pbuf)[:0], data...)
			s.handleQUICPacketIOUring(uc, remoteAddr, *pbuf, pbuf, connMap)
		}
	}
}

func (s *Server) listenAndServeQUICEpoll(addr string, connMap *quicConnMap) error {
	numListeners := s.epollListenerCount()
	listeners, err := createEpollQUICListeners(addr, numListeners)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	for _, ln := range listeners {
		wg.Add(1)
		go func(uc *epollUDPConn) {
			defer wg.Done()
			s.serveEpollQUIC(uc, connMap)
		}(ln)
	}
	go func() {
		<-s.done
		for _, ln := range listeners {
			ln.close()
		}
	}()
	wg.Wait()
	return nil
}
