//go:build !linux || !amd64

package core

import "net"

func (s *Server) tryServeWithIOUringPlainWorkers(listeners []net.Listener) (bool, error) {
	return false, nil
}

func (s *Server) tryServeWithIOUringRedirect(listeners []net.Listener) error {
	return ErrIOUringRequired
}

func ioUringListenerCount(configured int) int {
	return configured
}

func wrapConnectedConnWithIOUring(conn net.Conn) (net.Conn, error) {
	return conn, nil
}
