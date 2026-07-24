//go:build !linux

package core

func (s *Server) serveEpollProxy(addr string) (bool, error) {
	return false, nil
}
