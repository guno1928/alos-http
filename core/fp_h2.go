//go:build linux

package core

import "strconv"

const (
	h2FrameData         = 0x0
	h2FrameHeaders      = 0x1
	h2FramePriority     = 0x2
	h2FrameRSTStream    = 0x3
	h2FrameSettings     = 0x4
	h2FramePushPromise  = 0x5
	h2FramePing         = 0x6
	h2FrameGoAway       = 0x7
	h2FrameWindowUpdate = 0x8
	h2FrameContinuation = 0x9

	h2FlagEndStream  = 0x1
	h2FlagEndHeaders = 0x4
	h2FlagAck        = 0x1
	h2FlagPadded     = 0x8
	h2FlagPriority   = 0x20

	h2SettingsHeaderTableSize   = 0x1
	h2SettingsMaxConcurrent     = 0x3
	h2SettingsInitialWindowSize = 0x4
	h2SettingsMaxFrameSize      = 0x5

	h2DefaultWindow    = 65535
	h2MaxFrameSize     = 16384
	h2ConnWindowBump   = 1 << 30
	h2DefaultConcurrent = 100
)

var h2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

type h2Stream struct {
	id         uint32
	ex         *Exchange
	sendWindow int32
	gotHeaders bool
	status     int
	headers    [][2]string
	body       []byte
	bodyRem    []byte
	ended      bool
}

type h2Conn struct {
	enc            hpackEncoder
	dec            hpackDecoder
	streams        map[uint32]*h2Stream
	pending        []*Exchange
	nextID         uint32
	maxConcurrent  uint32
	peerInitWindow int32
	connSendWindow int32
	connRecvWindow int32
	maxFrameSize   int
	goAway         bool
	headerAssembly []byte
	continuation   uint32
	continuationEnd bool
	prefaceSent    bool
}

type h2Proto struct{}

func (c *backendConn) h2init() {
	c.h2 = &h2Conn{
		streams:        make(map[uint32]*h2Stream),
		nextID:         1,
		maxConcurrent:  h2DefaultConcurrent,
		peerInitWindow: h2DefaultWindow,
		connSendWindow: h2DefaultWindow,
		connRecvWindow: h2ConnWindowBump,
		maxFrameSize:   h2MaxFrameSize,
	}
	c.h2.dec.init(4096)
}

func (h *h2Proto) connReady(c *backendConn) error {
	if c.h2 == nil {
		c.h2init()
	}
	hc := c.h2
	c.send(h2Preface)
	c.send(h2BuildSettings())
	c.send(h2WindowUpdateFrame(0, h2ConnWindowBump-h2DefaultWindow))
	hc.prefaceSent = true
	h.flushPending(c)
	c.loop.flushWrites(c)
	return nil
}

func (h *h2Proto) attach(c *backendConn) error {
	return nil
}

func (h *h2Proto) flushPending(c *backendConn) {
	hc := c.h2
	for len(hc.pending) > 0 {
		if uint32(len(hc.streams)) >= hc.maxConcurrent || hc.goAway {
			return
		}
		ex := hc.pending[0]
		hc.pending = hc.pending[1:]
		h.openStream(c, ex)
	}
}

func (h *h2Proto) openStream(c *backendConn, ex *Exchange) {
	hc := c.h2
	id := hc.nextID
	hc.nextID += 2
	st := &h2Stream{id: id, ex: ex, sendWindow: hc.peerInitWindow}
	hc.streams[id] = st

	hc.enc.reset(c.loop.serBuf[:0])
	req := ex.req
	scheme := req.Scheme
	if scheme == "" {
		scheme = "https"
	}
	authority := req.HostHeader
	if authority == "" {
		authority = req.Authority
	}
	path := req.Path
	if path == "" {
		path = "/"
	}
	hc.enc.field(":method", req.Method)
	hc.enc.field(":scheme", scheme)
	hc.enc.field(":authority", authority)
	hc.enc.field(":path", path)
	for _, hd := range req.Headers {
		hc.enc.field(hd[0], hd[1])
	}
	block := hc.enc.buf
	c.loop.serBuf = block

	endStream := len(req.Body) == 0
	h2WriteHeaders(c, id, block, endStream)
	st.bodyRem = req.Body
	h.pumpBody(c, st)
	c.loop.flushWrites(c)
}

func (h *h2Proto) pumpBody(c *backendConn, st *h2Stream) {
	hc := c.h2
	for len(st.bodyRem) > 0 {
		max := int(st.sendWindow)
		if int(hc.connSendWindow) < max {
			max = int(hc.connSendWindow)
		}
		if max > hc.maxFrameSize {
			max = hc.maxFrameSize
		}
		if max <= 0 {
			return
		}
		chunk := st.bodyRem
		if len(chunk) > max {
			chunk = chunk[:max]
		}
		st.bodyRem = st.bodyRem[len(chunk):]
		st.sendWindow -= int32(len(chunk))
		hc.connSendWindow -= int32(len(chunk))
		h2WriteData(c, st.id, chunk, len(st.bodyRem) == 0)
	}
}

func (h *h2Proto) onData(c *backendConn, data []byte) error {
	c.rbuf.write(data)
	hc := c.h2
	for {
		buf := c.rbuf.unread()
		if len(buf) < 9 {
			return nil
		}
		length := int(buf[0])<<16 | int(buf[1])<<8 | int(buf[2])
		if length > 1<<20 {
			return fpErrBadResponse
		}
		if len(buf) < 9+length {
			return nil
		}
		ftype := buf[3]
		flags := buf[4]
		streamID := uint32(buf[5]&0x7f)<<24 | uint32(buf[6])<<16 | uint32(buf[7])<<8 | uint32(buf[8])
		payload := buf[9 : 9+length]
		if err := h.handleFrame(c, ftype, flags, streamID, payload); err != nil {
			return err
		}
		c.rbuf.consume(9 + length)
		_ = hc
	}
}

func (h *h2Proto) handleFrame(c *backendConn, ftype, flags byte, streamID uint32, payload []byte) error {
	hc := c.h2
	if hc.continuation != 0 && ftype != h2FrameContinuation {
		return fpErrBadResponse
	}
	switch ftype {
	case h2FrameSettings:
		if flags&h2FlagAck != 0 {
			return nil
		}
		if err := h.applySettings(c, payload); err != nil {
			return err
		}
		c.send(h2SettingsAck())
		c.loop.flushWrites(c)
	case h2FrameWindowUpdate:
		if len(payload) != 4 {
			return fpErrBadResponse
		}
		inc := int32(uint32(payload[0])<<24|uint32(payload[1])<<16|uint32(payload[2])<<8|uint32(payload[3])) & 0x7fffffff
		if streamID == 0 {
			hc.connSendWindow += inc
			h.resumeBodies(c)
		} else if st := hc.streams[streamID]; st != nil {
			st.sendWindow += inc
		}
	case h2FrameHeaders:
		return h.onHeaders(c, flags, streamID, payload)
	case h2FrameContinuation:
		return h.onContinuation(c, flags, streamID, payload)
	case h2FrameData:
		return h.onDataFrame(c, flags, streamID, payload)
	case h2FrameRSTStream:
		h.closeStream(c, streamID, fpErrConnClosed)
	case h2FramePing:
		if flags&h2FlagAck == 0 {
			c.send(h2PingAck(payload))
			c.loop.flushWrites(c)
		}
	case h2FrameGoAway:
		hc.goAway = true
	case h2FramePushPromise:
		return fpErrBadResponse
	}
	return nil
}

func (h *h2Proto) applySettings(c *backendConn, payload []byte) error {
	hc := c.h2
	if len(payload)%6 != 0 {
		return fpErrBadResponse
	}
	oldInit := hc.peerInitWindow
	for i := 0; i+6 <= len(payload); i += 6 {
		id := uint16(payload[i])<<8 | uint16(payload[i+1])
		val := uint32(payload[i+2])<<24 | uint32(payload[i+3])<<16 | uint32(payload[i+4])<<8 | uint32(payload[i+5])
		switch id {
		case h2SettingsMaxConcurrent:
			hc.maxConcurrent = val
		case h2SettingsInitialWindowSize:
			hc.peerInitWindow = int32(val)
		case h2SettingsMaxFrameSize:
			if val >= 16384 && val <= 1<<24-1 {
				hc.maxFrameSize = int(val)
			}
		case h2SettingsHeaderTableSize:
			hc.enc.reset(hc.enc.buf)
		}
	}
	if hc.peerInitWindow != oldInit {
		delta := hc.peerInitWindow - oldInit
		for _, st := range hc.streams {
			st.sendWindow += delta
		}
	}
	c.loop.h2proto.flushPending(c)
	h.resumeBodies(c)
	return nil
}

func (h *h2Proto) resumeBodies(c *backendConn) {
	hc := c.h2
	wrote := false
	for _, st := range hc.streams {
		if !st.ended && len(st.bodyRem) > 0 {
			before := len(st.bodyRem)
			h.pumpBody(c, st)
			if len(st.bodyRem) != before {
				wrote = true
			}
		}
	}
	if wrote {
		c.loop.flushWrites(c)
	}
}

func (h *h2Proto) onHeaders(c *backendConn, flags byte, streamID uint32, payload []byte) error {
	hc := c.h2
	if flags&h2FlagPadded != 0 {
		if len(payload) < 1 {
			return fpErrBadResponse
		}
		pad := int(payload[0])
		payload = payload[1:]
		if pad > len(payload) {
			return fpErrBadResponse
		}
		payload = payload[:len(payload)-pad]
	}
	if flags&h2FlagPriority != 0 {
		if len(payload) < 5 {
			return fpErrBadResponse
		}
		payload = payload[5:]
	}
	hc.headerAssembly = append(hc.headerAssembly[:0], payload...)
	if flags&h2FlagEndHeaders == 0 {
		hc.continuation = streamID
		hc.continuationEnd = flags&h2FlagEndStream != 0
		return nil
	}
	return h.completeHeaders(c, streamID, flags&h2FlagEndStream != 0)
}

func (h *h2Proto) onContinuation(c *backendConn, flags byte, streamID uint32, payload []byte) error {
	hc := c.h2
	if hc.continuation != streamID {
		return fpErrBadResponse
	}
	hc.headerAssembly = append(hc.headerAssembly, payload...)
	if flags&h2FlagEndHeaders == 0 {
		return nil
	}
	hc.continuation = 0
	return h.completeHeaders(c, streamID, hc.continuationEnd)
}

func (h *h2Proto) completeHeaders(c *backendConn, streamID uint32, endStream bool) error {
	hc := c.h2
	st := hc.streams[streamID]
	fields, err := hc.dec.decode(hc.headerAssembly, nil)
	if err != nil {
		return err
	}
	if st == nil {
		return nil
	}
	for _, f := range fields {
		if f[0] == ":status" {
			st.status, _ = strconv.Atoi(f[1])
		} else if len(f[0]) > 0 && f[0][0] != ':' {
			st.headers = append(st.headers, f)
		}
	}
	st.gotHeaders = true
	if endStream {
		h.finishStream(c, st)
	}
	return nil
}

func (h *h2Proto) onDataFrame(c *backendConn, flags byte, streamID uint32, payload []byte) error {
	hc := c.h2
	if flags&h2FlagPadded != 0 {
		if len(payload) < 1 {
			return fpErrBadResponse
		}
		pad := int(payload[0])
		payload = payload[1:]
		if pad > len(payload) {
			return fpErrBadResponse
		}
		payload = payload[:len(payload)-pad]
	}
	st := hc.streams[streamID]
	if len(payload) > 0 {
		if st != nil {
			if len(st.body)+len(payload) > c.loop.cfg.MaxResponseBody {
				return fpErrBodyTooLarge
			}
			st.body = append(st.body, payload...)
		}
		c.send(h2WindowUpdateFrame(0, int32(len(payload))))
		if st != nil {
			c.send(h2WindowUpdateFrame(streamID, int32(len(payload))))
		}
		c.loop.flushWrites(c)
	}
	if flags&h2FlagEndStream != 0 && st != nil {
		h.finishStream(c, st)
	}
	return nil
}

func (h *h2Proto) finishStream(c *backendConn, st *h2Stream) {
	hc := c.h2
	if st.ended {
		return
	}
	st.ended = true
	delete(hc.streams, st.id)
	ex := st.ex
	ex.resp.Status = st.status
	ex.resp.Headers = st.headers
	ex.resp.Body = st.body
	c.loop.finish(ex, nil)
	h.flushPending(c)
	if len(hc.streams) == 0 && len(hc.pending) == 0 && !hc.goAway {
		if c.loop.h2conns[c.key] != c {
			c.loop.closeConn(c, nil)
		}
	}
}

func (h *h2Proto) closeStream(c *backendConn, streamID uint32, err error) {
	hc := c.h2
	st := hc.streams[streamID]
	if st == nil {
		return
	}
	delete(hc.streams, streamID)
	if !st.ended {
		st.ended = true
		c.loop.failOrRetry(st.ex, err, c)
	}
}

func (h *h2Proto) onPeerClose(c *backendConn) {
}

func (h *h2Proto) canIdle(c *backendConn) bool {
	return false
}

func (hc *h2Conn) failAll(l *eventLoop, c *backendConn, err error) {
	for _, st := range hc.streams {
		if !st.ended {
			st.ended = true
			l.failOrRetry(st.ex, err, c)
		}
	}
	hc.streams = map[uint32]*h2Stream{}
	for _, ex := range hc.pending {
		l.failOrRetry(ex, err, c)
	}
	hc.pending = nil
}

func h2BuildSettings() []byte {
	settings := []struct {
		id  uint16
		val uint32
	}{
		{h2SettingsInitialWindowSize, h2ConnWindowBump},
		{h2SettingsMaxFrameSize, h2MaxFrameSize},
		{h2SettingsHeaderTableSize, 4096},
	}
	payload := make([]byte, 0, len(settings)*6)
	for _, s := range settings {
		payload = append(payload, byte(s.id>>8), byte(s.id))
		payload = append(payload, byte(s.val>>24), byte(s.val>>16), byte(s.val>>8), byte(s.val))
	}
	return h2Frame(h2FrameSettings, 0, 0, payload)
}

func h2SettingsAck() []byte {
	return h2Frame(h2FrameSettings, h2FlagAck, 0, nil)
}

func h2PingAck(payload []byte) []byte {
	return h2Frame(h2FramePing, h2FlagAck, 0, payload)
}

func h2WindowUpdateFrame(streamID uint32, inc int32) []byte {
	payload := []byte{byte(inc >> 24), byte(inc >> 16), byte(inc >> 8), byte(inc)}
	return h2Frame(h2FrameWindowUpdate, 0, streamID, payload)
}

func h2WriteHeaders(c *backendConn, streamID uint32, block []byte, endStream bool) {
	flags := byte(h2FlagEndHeaders)
	if endStream {
		flags |= h2FlagEndStream
	}
	max := c.h2.maxFrameSize
	if len(block) <= max {
		c.send(h2Frame(h2FrameHeaders, flags, streamID, block))
		return
	}
	first := block[:max]
	rest := block[max:]
	c.send(h2Frame(h2FrameHeaders, flags&h2FlagEndStream, streamID, first))
	for len(rest) > max {
		c.send(h2Frame(h2FrameContinuation, 0, streamID, rest[:max]))
		rest = rest[max:]
	}
	c.send(h2Frame(h2FrameContinuation, h2FlagEndHeaders, streamID, rest))
}

func h2WriteData(c *backendConn, streamID uint32, chunk []byte, endStream bool) {
	flags := byte(0)
	if endStream {
		flags = h2FlagEndStream
	}
	c.send(h2Frame(h2FrameData, flags, streamID, chunk))
}

func h2Frame(ftype, flags byte, streamID uint32, payload []byte) []byte {
	out := make([]byte, 9+len(payload))
	n := len(payload)
	out[0] = byte(n >> 16)
	out[1] = byte(n >> 8)
	out[2] = byte(n)
	out[3] = ftype
	out[4] = flags
	out[5] = byte(streamID >> 24)
	out[6] = byte(streamID >> 16)
	out[7] = byte(streamID >> 8)
	out[8] = byte(streamID)
	copy(out[9:], payload)
	return out
}
