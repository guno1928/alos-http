//go:build !(linux && amd64)

package core

func (s *Server) ListenAndServeEpollH2(addr string) error {
	return ErrEpollUnsupported
}

func (s *Server) ListenAndServeEpollTLS(addr string) error {
	return ErrEpollUnsupported
}
