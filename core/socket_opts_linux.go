//go:build linux

package core

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func prepareAcceptedFD(fd int) {
	if fd < 0 {
		return
	}
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 1)
	_ = syscall.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ZEROCOPY, 1)
}

func prepareAcceptedConn(conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		prepareAcceptedFD(int(fd))
	})
}
