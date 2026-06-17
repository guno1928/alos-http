//go:build !(linux && amd64)

package core

import "net"

func createQUICListeners(addr string, count int) ([]net.PacketConn, error) {
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return nil, err
	}
	return []net.PacketConn{conn}, nil
}
