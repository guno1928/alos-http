//go:build !linux

package core

import "net"

func prepareAcceptedFD(fd int) {
	_ = fd
}

func prepareAcceptedConn(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
}
