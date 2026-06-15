//go:build !linux

package core

import (
	"log"
	"net"
)

func createListeners(addr string, count int) ([]net.Listener, error) {
	if count > 1 {
		log.Printf("[WARN] SO_REUSEPORT not supported on this platform, using 1 listener")
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, err
	}
	return []net.Listener{ln}, nil
}
