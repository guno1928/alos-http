//go:build !(linux && amd64)

package core

// ListenAndServeEpollH2 returns ErrEpollUnsupported on platforms without the
// linux/amd64 epoll backend.
func (s *Server) ListenAndServeEpollH2(addr string) error {
	return ErrEpollUnsupported
}

// ListenAndServeEpollTLS returns ErrEpollUnsupported on platforms without the
// linux/amd64 epoll backend.
func (s *Server) ListenAndServeEpollTLS(addr string) error {
	return ErrEpollUnsupported
}
