//go:build !linux || !amd64

package core

import (
	"net"
	"time"
)

func dialProxyConn(addr string, timeout time.Duration) (net.Conn, error) {
	return DialTCP4(addr, timeout)
}
