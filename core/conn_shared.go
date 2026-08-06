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
	for {
		chunkStart := pos
		nl := indexByteFrom(buf, '\n', pos)
		if nl < 0 {
			return 0, 0, chunkStart
		}
		line := buf[pos:nl]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if semi := indexByteFrom(line, ';', 0); semi >= 0 {
			line = line[:semi]
		}
		line = trimASCIISpaceBytes(line)
		size, ok := parseHex64Bytes(line)
		if !ok {
			return 0, -1, chunkStart
		}
		pos = nl + 1
		if size == 0 {
			for {
				nl2 := indexByteFrom(buf, '\n', pos)
				if nl2 < 0 {
					return 0, 0, chunkStart
				}
				tline := buf[pos:nl2]
				pos = nl2 + 1
				if len(tline) == 0 || (len(tline) == 1 && tline[0] == '\r') {
					return pos, 1, pos
				}
			}
		}
		if size > int64(len(buf)-pos-2) {
			return 0, 0, chunkStart
		}
		pos += int(size) + 2
	}
}

type deadlineExceededError struct{}

func (deadlineExceededError) Error() string   { return "i/o timeout" }
func (deadlineExceededError) Timeout() bool   { return true }
func (deadlineExceededError) Temporary() bool { return true }

var errNetDeadlineExceeded error = deadlineExceededError{}

func clampListenerCount(configured int) int {
	if configured < 1 {
		return 1
	}
	return configured
}

func (s *Server) doneClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}
