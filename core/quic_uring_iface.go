package core

import "net"

type uringUDPSender interface {
	sendTo(buf []byte, addr *net.UDPAddr) (int, error)
}
