//go:build linux

package core

import (
	"golang.org/x/sys/unix"
)

func dialNonBlocking(ip [4]byte, port uint16) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return -1, err
	}
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
	sa := &unix.SockaddrInet4{Port: int(port)}
	sa.Addr = ip
	err = unix.Connect(fd, sa)
	if err != nil && err != unix.EINPROGRESS {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func ipv4String(a [4]byte) string {
	var buf [15]byte
	n := 0
	for i := 0; i < 4; i++ {
		if i > 0 {
			buf[n] = '.'
			n++
		}
		v := a[i]
		if v >= 100 {
			buf[n] = '0' + v/100
			n++
			v %= 100
			buf[n] = '0' + v/10
			n++
			buf[n] = '0' + v%10
			n++
		} else if v >= 10 {
			buf[n] = '0' + v/10
			n++
			buf[n] = '0' + v%10
			n++
		} else {
			buf[n] = '0' + v
			n++
		}
	}
	return string(buf[:n])
}

func socketError(fd int) error {
	v, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		return err
	}
	if v != 0 {
		return unix.Errno(v)
	}
	return nil
}
