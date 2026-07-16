//go:build linux && amd64

package core

import (
	"net"
	"syscall"
	"unsafe"
)

const (
	quicSendMaxBatch = 256
	gsoMaxSegments   = 16
	gsoCmsgHdrLen    = 16
	gsoCmsgLen       = 18
	gsoCmsgSpace     = 24

	solUDP     = 17
	udpSegment = 103
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

type quicSendReq struct {
	data []byte
	addr *net.UDPAddr
	pbuf *[]byte
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

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}
