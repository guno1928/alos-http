package core

import "sync/atomic"

const (
	// StreamIdle marks a stream that has not yet received headers.
	StreamIdle       uint32 = 0
	// StreamOpen marks a stream with an active request/response in progress.
	StreamOpen       uint32 = 1
	// StreamHalfClosed marks a stream whose request side has ended.
	StreamHalfClosed uint32 = 2
	// StreamClosed marks a stream that has fully completed.
	StreamClosed     uint32 = 3
)

// H2Stream holds the per-stream state of an HTTP/2 request being processed
// on the epoll backend.
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

	headerBuf []byte
	endStream bool

	req             Request
	resp            Response
	asyncBusy       bool
	respOff         int
	respHeadersSent bool
	stallBytes      int
}

// Reset clears an H2Stream so it can be reused from a pool.
func (s *H2Stream) Reset() {
	s.ID = 0
	s.State.Store(StreamIdle)
	s.Window.Store(0)
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
	s.respOff = 0
	s.respHeadersSent = false
	s.stallBytes = 0
}
