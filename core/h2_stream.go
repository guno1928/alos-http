package core

import "sync/atomic"

const (
	StreamIdle       uint32 = 0
	StreamOpen       uint32 = 1
	StreamHalfClosed uint32 = 2
	StreamClosed     uint32 = 3
)

type H2Stream struct {
	ID      uint32
	State   atomic.Uint32
	Window  atomic.Int64
	Method  string
	Path    string
	RawPath string
	Query   string
	Scheme  string
	Auth    string
	Headers [][2]string
	Body    []byte

	// refs is the single-owner recycle guard for the userspace HTTP/2 path
	// (h2_conn.go), where the read-loop goroutine and a concurrent dispatch
	// goroutine can both reference the same stream. Each owner holds one
	// reference; the owner that drops the count to zero is the sole owner that
	// returns the stream to StreamPool. This prevents a use-after-free /
	// double-Put when a RST_STREAM (or normal completion) races an in-flight
	// handler. The io_uring paths are single-goroutine and do not use refs.
	refs atomic.Int32

	headerBuf []byte
	endStream bool
}

func (s *H2Stream) Reset() {
	s.ID = 0
	s.State.Store(StreamIdle)
	s.Window.Store(0)
	s.refs.Store(0)
	s.Method = ""
	s.Path = ""
	s.RawPath = ""
	s.Query = ""
	s.Scheme = ""
	s.Auth = ""
	s.Headers = s.Headers[:0]
	s.Body = s.Body[:0]
	s.headerBuf = s.headerBuf[:0]
	s.endStream = false
}
