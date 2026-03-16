//go:build linux

package core

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func createListeners(addr string, count int) ([]net.Listener, error) {
	listeners := make([]net.Listener, 0, count)
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				if opErr != nil {
					return
				}
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_DEFER_ACCEPT, 1)
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 256)
			})
			if err != nil {
				return err
			}
			return opErr
		},
		KeepAlive: -1,
	}
	for i := 0; i < count; i++ {
		ln, err := lc.Listen(context.Background(), "tcp4", addr)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return nil, err
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
}
