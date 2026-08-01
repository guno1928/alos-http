//go:build linux

package core

import (
	"bytes"
	"strconv"
)

const (
	h1PhaseHeaders = iota
	h1PhaseBodyCL
	h1PhaseChunkSize
	h1PhaseChunkData
	h1PhaseChunkCRLF
	h1PhaseTrailers
	h1PhaseBodyEOF
)

var fpCrlfcrlf = []byte("\r\n\r\n")

type h1Parser struct {
	phase     int8
	status    int
	keepAlive bool
	noBody    bool
	stream    bool
	remaining int64
	// hdrBuf is a private copy of the response header block. Refs cannot point
	// into the connection's read buffer: that buffer is consumed and refilled
	// while the body arrives, so by the time a buffered response is written to
	// the client the header bytes there are long gone.
	hdrBuf []byte
	// hdr holds name/value slices of hdrBuf, names lowercased in place. They are
	// valid until the next response head is parsed on this connection, which is
	// after the current exchange has been completed.
	hdr [][2][]byte
	// strs is the materialised form, built only for consumers that need strings.
	strs [][2]string
	body []byte
}

func (p *h1Parser) reset() {
	p.phase = h1PhaseHeaders
	p.status = 0
	p.keepAlive = false
	p.noBody = false
	p.stream = false
	p.remaining = 0
	p.hdr = p.hdr[:0]
	p.strs = p.strs[:0]
	// The body buffer is kept and refilled. completeH1 hands ownership away
	// only for callers that read it after the exchange finishes.
	p.body = p.body[:0]
}

func (p *h1Parser) emit(c *backendConn, data []byte) bool {
	if p.stream {
		c.be.sink.streamResponseChunk(c, data)
		return true
	}
	return false
}

type h1Proto struct{}

func (h *h1Proto) connReady(c *backendConn) error {
	if c.cur != nil {
		return h.attach(c)
	}
	return nil
}

func (h *h1Proto) attach(c *backendConn) error {
	l := c.be
	c.gotBytes = false
	c.h1.reset()
	out := c.cur.rawRequest
	if out == nil {
		l.serBuf = appendH1Request(l.serBuf[:0], c.cur.req)
		out = l.serBuf
	}
	if err := c.transport.wrapOut(c, out); err != nil {
		return err
	}
	l.flushWrites(c)
	if ex := c.cur; ex != nil && ex.readTimeoutNano > 0 {
		ex.deadline = l.nowNano() + ex.readTimeoutNano
	}
	return nil
}

func (h *h1Proto) onData(c *backendConn, data []byte) error {
	c.rbuf.write(data)
	if c.cur == nil {
		return fpErrBadResponse
	}
	done, err := c.h1.advance(c)
	if err != nil {
		return err
	}
	if done {
		c.be.completeH1(c)
	}
	return nil
}

func (h *h1Proto) onPeerClose(c *backendConn) {
	if c.h1.phase == h1PhaseBodyEOF {
		c.be.completeH1(c)
	}
}

func (h *h1Proto) canIdle(c *backendConn) bool {
	return c.h1.keepAlive && c.rbuf.length() == 0
}

func appendH1Request(dst []byte, req *fpRequest) []byte {
	dst = append(dst, req.Method...)
	dst = append(dst, ' ')
	if req.Path == "" {
		dst = append(dst, '/')
	} else {
		dst = append(dst, req.Path...)
	}
	dst = append(dst, " HTTP/1.1\r\nhost: "...)
	if req.HostHeader != "" {
		dst = append(dst, req.HostHeader...)
	} else {
		dst = append(dst, req.Authority...)
	}
	dst = append(dst, '\r', '\n')
	for _, hd := range req.Headers {
		dst = append(dst, hd[0]...)
		dst = append(dst, ':', ' ')
		dst = append(dst, hd[1]...)
		dst = append(dst, '\r', '\n')
	}
	if req.Upgrade != "" {
		dst = append(dst, "connection: Upgrade\r\nupgrade: "...)
		dst = append(dst, req.Upgrade...)
		dst = append(dst, '\r', '\n')
	}
	if len(req.Body) > 0 || req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH" {
		dst = append(dst, "content-length: "...)
		dst = strconv.AppendInt(dst, int64(len(req.Body)), 10)
		dst = append(dst, '\r', '\n')
	}
	dst = append(dst, '\r', '\n')
	dst = append(dst, req.Body...)
	return dst
}

func (p *h1Parser) advance(c *backendConn) (bool, error) {
	cfg := c.be.cfg
	for {
		switch p.phase {
		case h1PhaseHeaders:
			data := c.rbuf.unread()
			idx := bytes.Index(data, fpCrlfcrlf)
			if idx < 0 {
				if len(data) > cfg.MaxHeaderBytes {
					return false, fpErrHeaderTooLarge
				}
				return false, nil
			}
			chunked, contentLen, err := p.parseHeaderBlock(data[:idx], c.cur.req.Method)
			if err != nil {
				return false, err
			}
			c.rbuf.consume(idx + 4)
			if p.status == 101 {
				if c.be.sink.beginTunnel(c, p) {
					return false, nil
				}
				return false, fpErrBadResponse
			}
			if p.status >= 100 && p.status < 200 {
				p.hdr = p.hdr[:0]
				continue
			}
			if p.noBody {
				return true, nil
			}
			p.stream = c.be.sink.shouldStreamResponse(c, contentLen)
			if p.stream {
				c.be.sink.beginStreamResponse(c, p, contentLen)
			}
			if chunked {
				p.phase = h1PhaseChunkSize
				continue
			}
			if contentLen >= 0 {
				if contentLen == 0 {
					return true, nil
				}
				if !p.stream && contentLen > int64(cfg.MaxResponseBody) {
					return false, fpErrBodyTooLarge
				}
				p.remaining = contentLen
				p.phase = h1PhaseBodyCL
				continue
			}
			p.keepAlive = false
			p.phase = h1PhaseBodyEOF
			continue
		case h1PhaseBodyCL:
			data := c.rbuf.unread()
			if len(data) == 0 {
				return false, nil
			}
			take := p.remaining
			if int64(len(data)) < take {
				take = int64(len(data))
			}
			if !p.emit(c, data[:take]) {
				p.body = append(p.body, data[:take]...)
			}
			c.rbuf.consume(int(take))
			p.remaining -= take
			if p.remaining == 0 {
				return true, nil
			}
			return false, nil
		case h1PhaseChunkSize:
			data := c.rbuf.unread()
			idx := bytes.IndexByte(data, '\n')
			if idx < 0 {
				if len(data) > 4096 {
					return false, fpErrBadResponse
				}
				return false, nil
			}
			line := data[:idx]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			if semi := bytes.IndexByte(line, ';'); semi >= 0 {
				line = line[:semi]
			}
			size, err := strconv.ParseInt(string(bytes.TrimSpace(line)), 16, 64)
			if err != nil || size < 0 {
				return false, fpErrBadResponse
			}
			c.rbuf.consume(idx + 1)
			if size == 0 {
				p.phase = h1PhaseTrailers
				continue
			}
			if !p.stream && int64(len(p.body))+size > int64(cfg.MaxResponseBody) {
				return false, fpErrBodyTooLarge
			}
			p.remaining = size
			p.phase = h1PhaseChunkData
			continue
		case h1PhaseChunkData:
			data := c.rbuf.unread()
			if len(data) == 0 {
				return false, nil
			}
			take := p.remaining
			if int64(len(data)) < take {
				take = int64(len(data))
			}
			if !p.emit(c, data[:take]) {
				p.body = append(p.body, data[:take]...)
			}
			c.rbuf.consume(int(take))
			p.remaining -= take
			if p.remaining == 0 {
				p.phase = h1PhaseChunkCRLF
			}
			continue
		case h1PhaseChunkCRLF:
			data := c.rbuf.unread()
			if len(data) < 2 {
				return false, nil
			}
			if data[0] != '\r' || data[1] != '\n' {
				return false, fpErrBadResponse
			}
			c.rbuf.consume(2)
			p.phase = h1PhaseChunkSize
			continue
		case h1PhaseTrailers:
			data := c.rbuf.unread()
			idx := bytes.IndexByte(data, '\n')
			if idx < 0 {
				if len(data) > cfg.MaxHeaderBytes {
					return false, fpErrHeaderTooLarge
				}
				return false, nil
			}
			line := data[:idx]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			c.rbuf.consume(idx + 1)
			if len(line) == 0 {
				return true, nil
			}
			continue
		case h1PhaseBodyEOF:
			data := c.rbuf.unread()
			if len(data) > 0 {
				if !p.stream && len(p.body)+len(data) > cfg.MaxResponseBody {
					return false, fpErrBodyTooLarge
				}
				if !p.emit(c, data) {
					p.body = append(p.body, data...)
				}
				c.rbuf.consume(len(data))
			}
			return false, nil
		}
	}
}

func (p *h1Parser) parseHeaderBlock(block []byte, method string) (bool, int64, error) {
	// One copy of the whole block, then names and values are slices of it. The
	// buffer is reused across responses, so this costs no allocation and it is
	// what makes the header refs outlive the connection's read buffer.
	p.hdrBuf = append(p.hdrBuf[:0], block...)
	block = p.hdrBuf

	lineEnd := bytes.IndexByte(block, '\n')
	var statusLine []byte
	if lineEnd < 0 {
		statusLine = block
		block = nil
	} else {
		statusLine = block[:lineEnd]
		block = block[lineEnd+1:]
	}
	if len(statusLine) > 0 && statusLine[len(statusLine)-1] == '\r' {
		statusLine = statusLine[:len(statusLine)-1]
	}
	if len(statusLine) < 12 || !bytes.HasPrefix(statusLine, []byte("HTTP/1.")) {
		return false, -1, fpErrBadResponse
	}
	minor := statusLine[7]
	if statusLine[8] != ' ' {
		return false, -1, fpErrBadResponse
	}
	d0, d1, d2 := statusLine[9], statusLine[10], statusLine[11]
	if d0 < '0' || d0 > '9' || d1 < '0' || d1 > '9' || d2 < '0' || d2 > '9' {
		return false, -1, fpErrBadResponse
	}
	p.status = int(d0-'0')*100 + int(d1-'0')*10 + int(d2-'0')
	p.keepAlive = minor == '1'
	p.noBody = method == "HEAD" || p.status == 204 || p.status == 304

	chunked := false
	contentLen := int64(-1)
	for len(block) > 0 {
		lineEnd = bytes.IndexByte(block, '\n')
		var line []byte
		if lineEnd < 0 {
			line = block
			block = nil
		} else {
			line = block[:lineEnd]
			block = block[lineEnd+1:]
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return false, -1, fpErrBadResponse
		}
		name := line[:colon]
		value := line[colon+1:]
		for len(value) > 0 && (value[0] == ' ' || value[0] == '\t') {
			value = value[1:]
		}
		for len(value) > 0 && (value[len(value)-1] == ' ' || value[len(value)-1] == '\t') {
			value = value[:len(value)-1]
		}
		for i, ch := range name {
			if ch >= 'A' && ch <= 'Z' {
				name[i] = ch + 'a' - 'A'
			}
		}
		p.hdr = append(p.hdr, [2][]byte{name, value})
		switch {
		case asciiEqualFold(name, "content-length"):
			v, err := strconv.ParseInt(string(value), 10, 64)
			if err != nil || v < 0 {
				return false, -1, fpErrBadResponse
			}
			contentLen = v
		case asciiEqualFold(name, "transfer-encoding"):
			if fpContainsTokenFold(value, "chunked") {
				chunked = true
			}
		case asciiEqualFold(name, "connection"):
			if fpContainsTokenFold(value, "close") {
				p.keepAlive = false
			} else if fpContainsTokenFold(value, "keep-alive") {
				p.keepAlive = true
			}
		}
	}
	if chunked {
		contentLen = -1
	}
	return chunked, contentLen, nil
}

// stringHeaders materialises the parsed headers for consumers that need strings:
// user hooks, the cache, HTTP/2 framing and the blocking client bridge. The
// returned slice is reused on the next response, so a caller that retains it
// copies the slice; the strings themselves are independent of the parser.
func (p *h1Parser) stringHeaders() [][2]string {
	p.strs = p.strs[:0]
	for _, h := range p.hdr {
		p.strs = append(p.strs, [2]string{lowerHeaderName(h[0]), string(h[1])})
	}
	return p.strs
}

// commonResponseHeaders lets the parser return a shared string for the handful
// of header names that make up nearly all real responses, instead of
// allocating one per header per response.
var commonResponseHeaders = map[string]string{
	"content-length":            "content-length",
	"content-type":              "content-type",
	"content-encoding":          "content-encoding",
	"transfer-encoding":         "transfer-encoding",
	"connection":                "connection",
	"date":                      "date",
	"server":                    "server",
	"location":                  "location",
	"cache-control":             "cache-control",
	"etag":                      "etag",
	"expires":                   "expires",
	"last-modified":             "last-modified",
	"vary":                      "vary",
	"set-cookie":                "set-cookie",
	"accept-ranges":             "accept-ranges",
	"age":                       "age",
	"pragma":                    "pragma",
	"upgrade":                   "upgrade",
	"retry-after":               "retry-after",
	"content-disposition":       "content-disposition",
	"content-range":             "content-range",
	"content-language":          "content-language",
	"strict-transport-security": "strict-transport-security",
	"x-powered-by":              "x-powered-by",
	"x-request-id":              "x-request-id",
}

const maxInternedHeaderName = 40

func lowerHeaderName(name []byte) string {
	if len(name) <= maxInternedHeaderName {
		var buf [maxInternedHeaderName]byte
		lower := buf[:len(name)]
		for i, ch := range name {
			if ch >= 'A' && ch <= 'Z' {
				ch += 'a' - 'A'
			}
			lower[i] = ch
		}
		// Indexing a map with string(bytes) does not allocate.
		if s, ok := commonResponseHeaders[string(lower)]; ok {
			return s
		}
		return string(lower)
	}
	out := make([]byte, len(name))
	for i, ch := range name {
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		out[i] = ch
	}
	return string(out)
}

func asciiEqualFold(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := 0; i < len(b); i++ {
		cb := b[i]
		cs := s[i]
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if cb != cs {
			return false
		}
	}
	return true
}

func fpContainsTokenFold(value []byte, token string) bool {
	start := 0
	for start <= len(value) {
		end := start
		for end < len(value) && value[end] != ',' {
			end++
		}
		part := value[start:end]
		for len(part) > 0 && (part[0] == ' ' || part[0] == '\t') {
			part = part[1:]
		}
		for len(part) > 0 && (part[len(part)-1] == ' ' || part[len(part)-1] == '\t') {
			part = part[:len(part)-1]
		}
		if asciiEqualFold(part, token) {
			return true
		}
		if end >= len(value) {
			break
		}
		start = end + 1
	}
	return false
}
