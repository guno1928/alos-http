//go:build linux && amd64

package core

import (
	"strconv"
	"sync/atomic"

	"github.com/guno1928/turbo"
)

// Backend sockets can share an epoll set with client sockets, so registrations
// carry a class in EpollEvent.Pad. The kernel echoes that field back untouched
// (see TestEpollEventPadRoundTrips), and zero means "client", which is what
// every pre-existing registration already reports.
const (
	epollFDClassClient  = 0
	epollFDClassBackend = 1
)

// beLoop drives outbound (backend) connections against an epoll set it does
// not own. Keeping it independent of the surrounding loop lets the same
// connection pool, H1/H2 protocol handling and TLS client run either inside
// the standalone eventLoop or directly inside an epollWorker, so a proxied
// request can be served by a single thread holding both sockets.
type beLoop struct {
	ep        int
	cfg       *fpConfig
	sink      beSink
	conns     []*backendConn
	idle      map[poolKey]*fpIdleList
	h2conns   map[poolKey]*backendConn
	scratch   []byte
	serBuf    []byte
	h1proto   h1Proto
	h2proto   h2Proto
	liveConns int
	lastSweep int64

	sweepEveryNano int64
	liveMaxIdle    *atomic.Int64
	panicReporter  *Server
	dnsInflight    map[string]*backendConn

	// seq identifies the batch of epoll events currently being processed.
	// Dialling happens inside that batch, so a fresh socket can reuse a
	// descriptor that an earlier event in the same batch just closed. Stamping
	// each connection with the batch that created it lets the dispatcher drop
	// the stale events, which would otherwise land on the wrong connection.
	seq uint32
}

// beSink is the part of an exchange's lifetime that depends on where the
// response is going. The eventLoop writes into an inConn; an epollWorker
// writes into the client's epollConn.
type beSink interface {
	exchangeDone(ex *Exchange)
	shouldStreamResponse(c *backendConn, contentLen int64) bool
	beginStreamResponse(c *backendConn, p *h1Parser, contentLen int64)
	streamResponseChunk(c *backendConn, data []byte)
	endStreamResponse(ex *Exchange)
	beginTunnel(c *backendConn, p *h1Parser) bool
	tunnelToClient(c *backendConn, data []byte)
	closeTunnelPeer(c *backendConn)
}

func (l *beLoop) init(ep int, cfg *fpConfig, sink beSink) {
	l.ep = ep
	l.cfg = cfg
	l.sink = sink
	l.idle = make(map[poolKey]*fpIdleList)
	l.h2conns = make(map[poolKey]*backendConn)
	l.dnsInflight = make(map[string]*backendConn)
	l.scratch = make([]byte, loopScratchSize)
}

func (l *beLoop) nowNano() int64 {
	return turbo.UnixNano()
}

// closeAll drops every backend connection this loop owns. The epoll fd belongs
// to the host, so it is deliberately left open.
func (l *beLoop) closeAll() {
	for _, c := range l.dnsInflight {
		l.dnsFail(c, errFPClientClosed)
	}
	for _, c := range l.conns {
		if c != nil && c.state != connClosed {
			l.closeConn(c, errFPClientClosed)
		}
	}
}

func (l *beLoop) ensureFD(fd int) {
	for fd >= len(l.conns) {
		l.conns = append(l.conns, nil)
	}
}

func (l *beLoop) startExchange(ex *Exchange) {
	now := l.nowNano()
	l.tightenSweep(ex, now)
	if now >= ex.deadline {
		l.finish(ex, errFPTimeout)
		return
	}
	if ex.key.h2 {
		if c := l.h2conns[ex.key]; c != nil && c.state != connClosed && !c.h2.goAway {
			l.assign(c, ex)
			return
		}
		l.newConn(ex)
		return
	}
	idle := l.idle[ex.key]
	for ex.body == nil && idle != nil && len(idle.conns) > 0 {
		c := idle.pop()
		c.inIdle = false
		if c.state != connReady {
			continue
		}
		if now > c.idleDeadline {
			l.closeConn(c, nil)
			continue
		}
		c.reused = true
		l.assign(c, ex)
		return
	}
	l.newConn(ex)
}

func (l *beLoop) newTransport(ex *Exchange) transport {
	if ex.key.tls {
		return newTLSTransport(ex)
	}
	return &plainTransport{h2: ex.key.h2}
}

func (l *beLoop) removeIdle(c *backendConn) {
	if !c.inIdle {
		return
	}
	c.inIdle = false
	idle := l.idle[c.key]
	if idle == nil {
		return
	}
	list := idle.conns
	for i, v := range list {
		if v == c {
			list[i] = list[len(list)-1]
			list[len(list)-1] = nil
			idle.conns = list[:len(list)-1]
			return
		}
	}
}

type fpIdleList struct {
	conns []*backendConn
}

func (il *fpIdleList) pop() *backendConn {
	last := len(il.conns) - 1
	c := il.conns[last]
	il.conns[last] = nil
	il.conns = il.conns[:last]
	return c
}

func (l *beLoop) idlePut(c *backendConn) {
	maxIdle := c.maxIdle
	if maxIdle <= 0 {
		maxIdle = l.maxIdlePerBackend()
	}
	idle := l.idle[c.key]
	if idle == nil {
		idle = &fpIdleList{}
		l.idle[c.key] = idle
	}
	if len(idle.conns) >= maxIdle {
		l.closeConn(c, nil)
		return
	}
	idleTimeout := c.idleTimeoutNano
	if idleTimeout <= 0 {
		idleTimeout = l.cfg.IdleTimeout.Nanoseconds()
	}
	l.resumeBackendRead(c)
	c.inIdle = true
	c.reused = false
	c.idleDeadline = l.nowNano() + idleTimeout
	idle.conns = append(idle.conns, c)
}

func (l *beLoop) maxIdlePerBackend() int {
	if l.liveMaxIdle != nil {
		return int(l.liveMaxIdle.Load())
	}
	return l.cfg.MaxIdlePerBackend
}

func (l *beLoop) completeH1(c *backendConn) {
	ex := c.cur
	if ex == nil {
		return
	}
	c.cur = nil
	p := &c.h1
	if ex.body.incomplete() {
		p.keepAlive = false
	}
	if p.stream {
		ex.resp.Status = p.status
		ex.resp.hdrRaw = p.hdr
		if ex.done != nil || ex.sink != nil {
			ex.resp.Headers = p.stringHeaders()
		}
		ex.finished = true
		l.sink.endStreamResponse(ex)
		if c.proto.canIdle(c) {
			l.idlePut(c)
			return
		}
		l.closeConn(c, nil)
		return
	}
	ex.resp.Status = p.status
	ex.resp.hdrRaw = p.hdr
	if ex.done != nil {
		// Only a client-style caller reads the response after finish returns,
		// so it is the only one that needs headers detached from the parser.
		ex.resp.Headers = append([][2]string(nil), p.stringHeaders()...)
	} else if ex.sink != nil {
		ex.resp.Headers = p.stringHeaders()
	}
	ex.resp.Body = p.body
	if ex.done != nil {
		// Only an asynchronous caller still holds the body once finish
		// returns, so it takes the buffer with it. Every other consumer copies
		// it out synchronously and the parser keeps the allocation.
		p.body = nil
	}
	l.finish(ex, nil)
	if c.proto.canIdle(c) {
		l.idlePut(c)
		return
	}
	l.closeConn(c, nil)
}

// sweepBackends expires idle, timed-out and stalled backend connections.
func (l *beLoop) sweepBackends(now int64) {
	for _, c := range l.conns {
		if c == nil || c.state == connClosed {
			continue
		}
		l.sweepConn(c, now)
	}
}

func (l *beLoop) sweepConn(c *backendConn, now int64) {
	defer l.recoverSweep(c)
	// A tunnel has no request cadence, so no request deadline applies.
	if c.tunnelClient != nil {
		return
	}
	if c.inIdle {
		if now > c.idleDeadline {
			l.closeConn(c, nil)
		}
		return
	}
	if c.dns != nil {
		l.sweepDNSWaiters(c, now)
	}
	if c.h2 != nil && c.dns == nil {
		l.sweepH2(c, now)
		return
	}
	if c.cur != nil && now > c.cur.deadline {
		l.closeConn(c, errFPTimeout)
		return
	}
	if c.dns != nil && now > c.dns.deadline {
		l.dnsNext(c, false)
	}
}

func (l *beLoop) sweepH2(c *backendConn, now int64) {
	for id, st := range c.h2.streams {
		if !st.ended && now > st.ex.deadline {
			st.ended = true
			delete(c.h2.streams, id)
			c.send(h2Frame(h2FrameRSTStream, 0, id, h2RSTCancelPayload))
			l.flushWrites(c)
			l.finish(st.ex, errFPTimeout)
		}
	}
	l.h2proto.closeIfExhausted(c)
}

// fpNoDeadline marks a connection that must not be reaped on a timer, such as
// one carrying an established tunnel.
const fpNoDeadline = int64(1<<63 - 1)

// isHopByHopStr reports whether a header governs a single transport hop and so
// must not be relayed to the next one.
// respHeaders is a response header list in whichever form avoided a copy: raw
// when it came from the H1 parser, str when it came from HPACK, was rewritten by
// a hook, or has to outlive the parser. The accessors keep the filtering logic
// in one place at the call sites while staying allocation-free for both forms,
// since appending and comparing work the same for a string and a byte slice.
type respHeaders struct {
	raw [][2][]byte
	str [][2]string
}

func (h respHeaders) count() int {
	if h.raw != nil {
		return len(h.raw)
	}
	return len(h.str)
}

func (h respHeaders) nameIs(i int, lower string) bool {
	if h.raw != nil {
		return headerNameIsBytes(h.raw[i][0], lower)
	}
	return headerNameIs(h.str[i][0], lower)
}

func (h respHeaders) hopByHop(i int) bool {
	if h.raw != nil {
		return isHopByHopBytes(h.raw[i][0])
	}
	return isHopByHopStr(h.str[i][0])
}

func (h respHeaders) appendPair(dst []byte, i int) []byte {
	if h.raw != nil {
		dst = append(dst, h.raw[i][0]...)
		dst = append(dst, ": "...)
		return append(dst, h.raw[i][1]...)
	}
	dst = append(dst, h.str[i][0]...)
	dst = append(dst, ": "...)
	return append(dst, h.str[i][1]...)
}

// intValue parses the value at i as a non-negative integer. The string
// conversion does not escape, so it costs no allocation.
func (h respHeaders) intValue(i int) (int64, bool) {
	var s string
	if h.raw != nil {
		s = string(h.raw[i][1])
	} else {
		s = h.str[i][1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// The H1 parser lowercases names in place, so the byte forms compare directly.
// Go allocates nothing for string(b) in a comparison or a switch.
func headerNameIsBytes(name []byte, lower string) bool { return string(name) == lower }
