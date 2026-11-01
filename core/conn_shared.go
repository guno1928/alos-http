//go:build linux && amd64

package core

const (
	plainConnProtoUnknown = 0
	plainConnProtoH1      = 1
	plainConnProtoH2      = 2
	// plainConnProtoTunnel means the connection has been upgraded and its
	// bytes are relayed verbatim to a backend rather than parsed.
	plainConnProtoTunnel = 3

	plainReadMinFree = 4096
)

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func indexByteFrom(b []byte, c byte, from int) int {
	for i := from; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func asyncChunkedComplete(buf []byte, pos int) (bodyEnd int, status int, resume int) {
	var d chunkedDecoder
	chunkStart := pos
	for {
		n, _, err := d.next(buf[pos:])
		if err != nil {
			return 0, -1, chunkStart
		}
		if n == 0 {
			return 0, 0, chunkStart
		}
		pos += n
		if d.done() {
			return pos, 1, pos
		}
		if d.state == chunkedAwaitSize {
			chunkStart = pos
		}
	}
}

type deadlineExceededError struct{}

func (deadlineExceededError) Error() string   { return "i/o timeout" }
func (deadlineExceededError) Timeout() bool   { return true }
func (deadlineExceededError) Temporary() bool { return true }

var errNetDeadlineExceeded error = deadlineExceededError{}

func (s *Server) doneClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}
