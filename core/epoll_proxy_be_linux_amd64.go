//go:build linux && amd64

package core

import (
	"log"

	"golang.org/x/sys/unix"
)

// The epoll worker owns the client socket of every connection it accepts. It
// also hosts a beLoop bound to its own epoll fd, so the backend socket of a
// proxied request lives in the same event loop as the client it answers. One
// thread then drives the whole exchange with no cross-loop handoff.

// initBackendLoop binds the worker's backend engine to the worker's own epoll
// fd. Loop counts are meaningless here because the worker is the loop, so only
// the pool and timeout settings are filled in.
func (w *epollWorker) initBackendLoop() {
	w.beCfg.Loops = 1
	w.beCfg.LoopsPerOrigin = 1
	w.beCfg.fill(1)
	w.be.init(w.epfd, &w.beCfg, w)
}

// backendEvent dispatches an epoll event that carries the backend class tag.
func (w *epollWorker) backendEvent(fd int, evs uint32) {
	if fd < 0 || fd >= len(w.be.conns) {
		return
	}
	c := w.be.conns[fd]
	if c == nil || c.state == connClosed || w.be.staleInBatch(c) {
		return
	}
	if evs&unix.EPOLLERR != 0 {
		err := socketError(c.fd)
		if err == nil {
			err = fpErrConnClosed
		}
		if c.state == connConnecting {
			err = fpErrDialFailed
		}
		w.be.closeConn(c, err)
		return
	}
	if c.state == connConnecting && evs&(unix.EPOLLOUT|unix.EPOLLHUP) != 0 {
		w.be.onConnConnected(c)
		if c.state == connClosed {
			return
		}
	}
	if evs&(unix.EPOLLIN|unix.EPOLLRDHUP|unix.EPOLLHUP) != 0 {
		w.be.readable(c)
		if c.state == connClosed {
			return
		}
	}
	if evs&unix.EPOLLOUT != 0 && c.wbuf.length() > 0 {
		w.be.flushWrites(c)
	}
}

// resumeRelayIfDrained re-arms a backend read side that was disarmed because
// this client could not keep up with a relayed response.
func (w *epollWorker) resumeRelayIfDrained(c *epollConn) {
	bc := c.pausedBackend
	if bc == nil {
		return
	}
	if len(c.writeBuf)-c.writeSent > proxyStreamLowWater {
		return
	}
	c.pausedBackend = nil
	if bc.state != connClosed {
		w.be.resumeBackendRead(bc)
	}
}

// abortProxyExchange drops an in-flight exchange when its client goes away, so
// the backend socket is not left relaying into a closed connection.
func (w *epollWorker) abortProxyExchange(c *epollConn) {
	px := c.proxyEx
	if px == nil {
		return
	}
	c.proxyEx = nil
	if px.h2Stream != nil {
		w.abortProxyStream(px)
	}
	px.c = nil
	if bc := c.pausedBackend; bc != nil {
		c.pausedBackend = nil
		if bc.state != connClosed {
			w.be.resumeBackendRead(bc)
		}
	}
	if px.b != nil {
		px.b.ActiveConns.Add(-1)
		px.b = nil
	}
	for _, bc := range w.be.conns {
		if bc != nil && bc.cur == &px.Exchange {
			w.be.closeConn(bc, fpErrClientClosed)
			return
		}
	}
	w.pxPut(px)
}

func (w *epollWorker) exGet() *Exchange {
	ex := w.exFree
	if ex != nil {
		w.exFree = ex.pnext
		*ex = Exchange{req: ex.req}
		return ex
	}
	return &Exchange{req: &fpRequest{}}
}

func (w *epollWorker) exPut(ex *Exchange) {
	req := ex.req
	*req = fpRequest{}
	*ex = Exchange{req: req}
	ex.pnext = w.exFree
	w.exFree = ex
}

// onForwardDone only fires for exchanges carrying an inConn, which belong to
// the standalone event loop. Worker-hosted exchanges never set one.
func (w *epollWorker) onForwardDone(ex *Exchange) {
	log.Printf("[EPOLL-BUG] worker %d: inbound completion on a worker exchange", w.coreID)
	w.exPut(ex)
}

// exchangeDone delivers a fully buffered upstream response to the client. It is
// the terminal callback for exchanges that carry neither an inConn nor a done
// channel, which is exactly those created by beginProxy.
func (w *epollWorker) exchangeDone(ex *Exchange) {
	px := proxyExchangeOf(ex)
	if px.w != w {
		w.exPut(ex)
		return
	}
	if px.b != nil {
		px.b.ActiveConns.Add(-1)
	}
	if ex.err != nil {
		if px.h2Stream != nil {
			w.proxyRetryOrFailH2(px, ex.err)
		} else {
			w.proxyRetryOrFail(px, ex.err)
		}
		return
	}
	if px.streaming {
		w.proxyEndStream(px)
		return
	}
	status, headers, hooked := w.applyResponseHook(px, ex.resp.Status, ex.resp.headers())
	if px.pe.Cache != nil {
		w.proxyMaybeCache(px, status, headers, ex.resp.Body, hooked)
	}
	if px.b != nil {
		px.b = nil
	}
	if px.h2Stream != nil {
		w.finishProxyStream(px, status, headers, ex.resp.Body, "")
		return
	}
	w.proxyFinishClient(px, status, headers, ex.resp.Body, "")
}

// shouldStreamResponse keeps small, known-length responses buffered so a failed
// attempt can still be retried and the cache has a body to store. Anything
// larger, or of unknown length, is relayed as it arrives.
func (w *epollWorker) shouldStreamResponse(c *backendConn, contentLen int64) bool {
	if c.cur == nil {
		return false
	}
	px := proxyExchangeOf(c.cur)
	// An HTTP/2 stream is framed out of a completed response under flow
	// control, so there is nothing to relay into incrementally.
	if px.h2Stream != nil {
		return false
	}
	// A response of unknown length has to be relayed; there is no way to know
	// whether it would ever fit anywhere.
	if contentLen < 0 {
		return true
	}
	// A cacheable response that the cache would accept is buffered so it can
	// actually be stored. Without this a CDN silently stops caching everything
	// above the buffering threshold, which is the opposite of what it wants.
	if px.mayCache && contentLen <= px.pe.Cache.maxCacheableSize() {
		return false
	}
	return contentLen > proxyBufferedResponseLimit
}

// beginStreamResponse emits the response head and switches the exchange to
// relaying body bytes straight into the client's write buffer.
func (w *epollWorker) beginStreamResponse(c *backendConn, p *h1Parser, contentLen int64) {
	ex := c.cur
	if ex == nil {
		return
	}
	px := proxyExchangeOf(ex)
	cc := px.c
	if cc == nil || cc.generation != px.cGen || cc.fd < 0 {
		return
	}
	status, headers, _ := w.applyResponseHook(px, p.status, respHeaders{raw: p.hdr})

	if !cc.tls {
		cc.writeBuf = appendProxyStreamHead(cc.writeBuf, status, headers, contentLen, px.keepClient)
	} else {
		scratch := w.beScratch[:0]
		scratch = appendProxyStreamHead(scratch, status, headers, contentLen, px.keepClient)
		w.beScratch = scratch[:0]
		cc.writeBuf = cc.sealTLSAppData(cc.writeBuf, scratch)
	}

	px.streaming = true
	px.streamChunked = contentLen < 0
	px.headersOut = true
	if px.b != nil {
		px.b.ActiveConns.Add(-1)
		px.b = nil
	}
	w.flush(cc)
}

// streamResponseChunk relays one body chunk and applies backpressure: when the
// client falls behind, the backend read side is disarmed until it catches up.
func (w *epollWorker) streamResponseChunk(c *backendConn, data []byte) {
	ex := c.cur
	if ex == nil {
		return
	}
	px := proxyExchangeOf(ex)
	cc := px.c
	if cc == nil || cc.generation != px.cGen || cc.fd < 0 {
		w.be.closeConn(c, fpErrClientClosed)
		return
	}
	if px.streamChunked {
		scratch := w.beScratch[:0]
		scratch = appendChunkFrame(scratch, data)
		w.beScratch = scratch[:0]
		w.clientAppend(cc, scratch)
	} else {
		w.clientAppend(cc, data)
	}
	w.flush(cc)
	if cc.fd >= 0 && len(cc.writeBuf)-cc.writeSent > proxyStreamHighWater && cc.pausedBackend == nil {
		cc.pausedBackend = c
		w.be.pauseBackendRead(c)
	}
}

// endStreamResponse is the completion callback for a streamed response.
func (w *epollWorker) endStreamResponse(ex *Exchange) {
	px := proxyExchangeOf(ex)
	if px.b != nil {
		px.b.ActiveConns.Add(-1)
		px.b = nil
	}
	w.proxyEndStream(px)
}

func (w *epollWorker) proxyEndStream(px *proxyExchange) {
	cc := px.c
	if cc == nil || cc.generation != px.cGen || cc.fd < 0 {
		w.pxPut(px)
		return
	}
	if px.streamChunked {
		w.clientAppend(cc, []byte("0\r\n\r\n"))
	}
	cc.proxyEx = nil
	cc.dispatching = false
	cc.releaseH1BodyBudget()
	if cc.inFlight > 0 {
		cc.inFlight--
	}
	if cc.pausedBackend != nil {
		cc.pausedBackend = nil
	}
	if !px.keepClient {
		cc.closeAfter = true
	}
	w.pxPut(px)
	w.proxyResume(cc)
}

// applyResponseHook lets OnResponse observe and rewrite a live upstream
// response, which previously only ran for cache hits.
func (w *epollWorker) applyResponseHook(px *proxyExchange, status int, headers respHeaders) (int, respHeaders, *ProxyResponse) {
	if px.pe == nil || px.pe.OnResponse == nil {
		return status, headers, nil
	}
	// A hook is handed real strings and may keep or rewrite them, so its result
	// travels onwards in string form.
	current := w.headerStrings(headers)
	pr := &ProxyResponse{
		Domain:     px.ds.config.Domain,
		Backend:    px.backendAddr(),
		ClientAddr: px.clientAddr,
		Method:     px.method,
		Path:       px.path,
		StatusCode: status,
		Headers:    append(make([][2]string, 0, len(current)), current...),
	}
	px.pe.OnResponse(pr)
	return pr.StatusCode, respHeaders{str: pr.Headers}, pr
}

func (px *proxyExchange) backendAddr() string {
	if px.b == nil {
		return ""
	}
	return px.b.Addr
}
