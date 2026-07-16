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

	headerBuf []byte
	endStream bool

	req             Request
	resp            Response
	asyncBusy       bool
	respOff         int
	respHeadersSent bool
}

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
}
