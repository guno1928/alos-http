//go:build !linux || !amd64

package core

import (
	"errors"
	"net"
)

const ioUringInitialConnsPerShard = 0

type tlsUringBackend struct {
	workers []struct{}
}

func newTLSUringBackend(s *Server, listeners []net.Listener) (*tlsUringBackend, error) {
	return nil, ErrIOUringRequired
}

func (backend *tlsUringBackend) closeResources() {}

func (backend *tlsUringBackend) start() {}

func (backend *tlsUringBackend) wait() error {
	return ErrIOUringRequired
}

func (s *Server) doneClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func isIOUringAcceptShutdownError(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
