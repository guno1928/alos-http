//go:build linux && amd64

package core

import "net"

func createQUICListeners(_ string, _ int) ([]net.PacketConn, error) {
	return nil, ErrIOUringRequired
}
