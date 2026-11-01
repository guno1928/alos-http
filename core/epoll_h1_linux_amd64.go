//go:build linux && amd64

package core

import "github.com/guno1928/turbo"

const (
	h1StepNeedInput = iota
	h1StepDispatched
	h1StepClose
	h1StepProxyInFlight
	h1StepDetached
)

func (c *epollConn) h1Unread() []byte {
	if c.tls {
		return c.appBuf[c.appBufOff:]
	}
	return c.readBuf[c.h1Off:c.readN]
}

func (c *epollConn) h1Advance(n int) {
	if c.tls {
		c.appBufOff += n
	} else {
		c.h1Off += n
	}
}

func (c *epollConn) h1OutBegin() []byte {
	if c.tls {
		return c.plainBuf[:0]
	}
	return c.writeBuf
}

func (c *epollConn) h1OutEnd(out []byte) {
	if c.tls {
		if len(out) > 0 {
			c.writeBuf = c.sealTLSAppData(c.writeBuf, out)
		}
		c.plainBuf = out[:0]
		return
	}
	c.writeBuf = out
}

func (c *epollConn) h1PendingWrite(out []byte) int {
	if c.tls {
		return len(c.writeBuf) - c.writeSent + len(out)
	}
	return len(out) - c.writeSent
}

func (c *epollConn) h1Reject(out []byte, status int, msg string) []byte {
	statsRawBlocked()
	c.resp.Reset()
	c.resp.Status(status).String(msg)
	return appendPlainResponseClose(&c.resp, out)
}

func (c *epollConn) h1ServiceUnavailable(out []byte, keepAlive bool) []byte {
	statsBlocked()
	c.resp.Reset()
	c.resp.Status(503).String("Service Unavailable")
	return appendPlainResponseMode(&c.resp, out, keepAlive, true)
}

func (c *epollConn) h1BodyReadDeadline() int64 {
	if c.h1BodyDeadline == 0 {
		c.h1BodyDeadline = deadlineFrom(c.worker.readTO)
	}
	return c.h1BodyDeadline
}

const (
	tlsDirectSealMinBody   = 16 << 10
	tls12DirectSealMinBody = 2 * MaxRecordPayload
)

func (c *epollConn) directSealMinBody() int {
	if c.tls12 != nil {
		return tls12DirectSealMinBody
	}
	return tlsDirectSealMinBody
}

func (c *epollConn) h1AppendResponse(out []byte, keepAlive bool) []byte {
	if !c.tls || c.resp.BodyLen() < c.directSealMinBody() || c.resp.transmittedBodyLen() == 0 {
		return appendPlainResponseMode(&c.resp, out, keepAlive, true)
	}
	head := appendPlainResponseMode(&c.resp, out, keepAlive, false)
	c.writeBuf = c.sealTLSResponseBody(c.writeBuf, head, c.resp.bodyBytesUnsafe())
	c.resp.releaseSentBody()
	return head[:0]
}

func (c *epollConn) h1WriteResponse(keepAlive bool) {
	if c.tls {
		addAltSvcHeader(&c.resp, c.worker.server)
		plain := c.h1AppendResponse(c.plainBuf[:0], keepAlive)
		if len(plain) > 0 {
			c.writeBuf = c.sealTLSAppData(c.writeBuf, plain)
		}
		c.plainBuf = plain[:0]
		return
	}
	c.writeBuf = appendPlainResponseMode(&c.resp, c.writeBuf, keepAlive, true)
}

func (c *epollConn) epollProcessH1(srv *Server) int {
	out, step := c.serveH1(srv, c.writeBuf)
	c.writeBuf = out
	switch step {
	case h1StepClose:
		return epollActionCloseAfterFlush
	case h1StepProxyInFlight:
		return epollActionProxyInFlight
	case h1StepDispatched:
		return epollActionNeedRead
	case h1StepDetached:
		return epollActionDetached
	}
	c.compactH1ReadBuffer()
	return epollActionNeedRead
}

func (c *epollConn) epollTLSHTTP1(srv *Server) int {
	out, step := c.serveH1(srv, c.plainBuf[:0])
	switch step {
	case h1StepProxyInFlight:
		c.plainBuf = out[:0]
		return epollActionProxyInFlight
	case h1StepDetached:
		c.plainBuf = out[:0]
		return epollActionDetached
	case h1StepClose:
		c.h1OutEnd(out)
		return epollActionCloseAfterFlush
	case h1StepDispatched:
		c.h1OutEnd(out)
		c.compactAppConsumed()
		if c.h1BodyWantsInput() {
			return epollTLSContinue
		}
		return epollActionNeedRead
	}
	c.h1OutEnd(out)
	c.compactAppConsumed()
	return epollTLSContinue
}

func (c *epollConn) compactAppConsumed() {
	if c.appBufOff > 0 {
		c.compactApp(c.appBufOff)
		c.appBufOff = 0
	}
}

func (c *epollConn) serveH1(srv *Server, out []byte) ([]byte, int) {
	if c.ws != nil {
		return c.wsServe(out)
	}
	maxRead := srv.effectiveReadCap()
	proxyActive := srv.httpRouter.Load() != nil
	if c.h1In != nil {
		c.h1FeedBody(c.worker)
	}
	if c.dispatching {
		return out, h1StepDispatched
	}
	for len(c.h1Unread()) > 0 {
		if c.h1PendingWrite(out) > c.worker.maxPendingWrite {
			return out, h1StepClose
		}
		data := c.h1Unread()
		if len(data) >= 2 && data[0] == '\r' && data[1] == '\n' {
			c.h1Advance(2)
			continue
		}
		if resp, consumed, closeConn, ok := srv.matchPlainRootFastRequest(data, c.tls); ok && !proxyActive && !srv.shuttingDown.Load() {
			c.worker.reqs++
			if srv.tryAcquireRequestSlot() {
				srv.releaseRequestSlot()
				out = appendMemoizedResponse(out, resp)
			} else {
				out = c.h1ServiceUnavailable(out, !closeConn)
			}
			c.h1Advance(consumed)
			if closeConn {
				return out, h1StepClose
			}
			continue
		}

		c.req.resetFastH1()
		headerEnd, contentLength, hasContentLength, closeConn, reject, chunked, tooLarge, ok := parseH1RequestHead(data, &c.req, c.worker.maxHeaderSize, srv.config.MaxHeaderCount)
		if tooLarge {
			return c.h1Reject(out, 431, "Request Header Fields Too Large"), h1StepClose
		}
		if !ok {
			return out, h1StepNeedInput
		}
		closeConn = closeConn || srv.shuttingDown.Load()
		consumed := headerEnd
		if reject != h1RejectNone {
			Stats.H1Rejected.Add(1)
			return c.h1Reject(out, 400, "Bad Request"), h1StepClose
		}
		if c.req.expect == h1ExpectUnknown {
			return c.h1Reject(out, 417, "Expectation Failed"), h1StepClose
		}
		streamBody := c.worker.streamsH1Body(chunked, hasContentLength, contentLength)
		if chunked && !streamBody {
			scanFrom := headerEnd
			if c.chunkScanPos > headerEnd && c.chunkScanPos <= len(data) {
				scanFrom = c.chunkScanPos
			}
			bodyEnd, status, resume := asyncChunkedComplete(data, scanFrom)
			if status == -1 {
				c.chunkScanPos = 0
				return c.h1Reject(out, 400, "Bad Request"), h1StepClose
			}
			received := len(data) - headerEnd
			if status != 0 {
				received = bodyEnd - headerEnd
			}
			if !c.reserveH1BodyBudget(srv, received) {
				return c.h1Reject(out, 503, "Request Body Capacity Exhausted"), h1StepClose
			}
			if status == 0 {
				c.chunkScanPos = resume
				if c.worker.bodyTooLarge(int64(len(data)-headerEnd) - chunkedFramingSlack) {
					return c.h1Reject(out, 413, "Payload Too Large"), h1StepClose
				}
				c.deadline = c.h1BodyReadDeadline()
				return c.h1Continue(out), h1StepNeedInput
			}
			c.chunkScanPos = 0
			if c.readScratch {
				c.ownReadBuf(c.worker)
				data = c.h1Unread()
			}
			decoded, trailers, dok := decodeChunkedInto(c.reqBodyCopy[:0], data[headerEnd:bodyEnd])
			if !dok {
				return c.h1Reject(out, 400, "Bad Request"), h1StepClose
			}
			if c.worker.bodyTooLarge(int64(len(decoded))) {
				return c.h1Reject(out, 413, "Payload Too Large"), h1StepClose
			}
			c.reqBodyCopy = decoded
			c.req.Body = decoded
			c.req.trailers = trailers
			consumed = bodyEnd
		}
		if hasContentLength {
			if contentLength < 0 {
				return c.h1Reject(out, 400, "Bad Request"), h1StepClose
			}
			if c.worker.bodyTooLarge(int64(contentLength)) {
				return c.h1Reject(out, 413, "Payload Too Large"), h1StepClose
			}
		}
		if hasContentLength && !streamBody {
			bodyEnd := headerEnd + contentLength
			if bodyEnd < headerEnd {
				return c.h1Reject(out, 400, "Bad Request"), h1StepClose
			}
			if bodyEnd > maxRead {
				return c.h1Reject(out, 413, "Payload Too Large"), h1StepClose
			}
			if !c.reserveH1BodyBudget(srv, min(len(data), bodyEnd)-headerEnd) {
				return c.h1Reject(out, 503, "Request Body Capacity Exhausted"), h1StepClose
			}
			if bodyEnd > len(data) {
				if !c.tls && c.h1Off+bodyEnd > cap(c.readBuf) {
					c.compactH1ReadBuffer()
				}
				c.deadline = c.h1BodyReadDeadline()
				return c.h1Continue(out), h1StepNeedInput
			}
			c.reqBodyCopy = append(c.reqBodyCopy[:0], data[headerEnd:bodyEnd]...)
			c.req.Body = c.reqBodyCopy
			consumed = bodyEnd
		}

		c.h1BodyDeadline = 0
		c.worker.reqs++
		c.req.StreamWriter = nil
		c.req.swFactory = nil
		c.req.bodyStream = nil
		c.req.conn = nil
		c.req.server = srv
		c.req.Host = c.req.cachedHost
		c.req.setOwnedRemoteAddr(c.remoteAddr)
		c.req.IsTLS = c.tls
		c.req.peerCerts = c.peerCerts
		c.req.TLSVersion = c.tlsVersion
		if srv.misdirectsClientAuth(c.tlsCertEntry, c.req.Host) {
			return c.h1Reject(out, 421, "Misdirected Request"), h1StepClose
		}
		if !c.acquireIPConn(srv, &c.req) {
			statsBlocked()
			c.resp.resetFastH1()
			c.resp.Status(429).String("Your IP has too many connections open")
			return appendPlainResponseClose(&c.resp, out), h1StepClose
		}
		c.resp.resetFastH1()
		c.resp.SetSW(nil)
		c.resp.lazyReq = &c.req

		c.h1Advance(consumed)
		c.h1ContinueSent = false
		c.dispatching = true
		c.inFlight++
		gen := c.generation
		w := c.worker

		// A proxied request never leaves this thread: the backend socket joins
		// the same epoll set, so no goroutine, wake-up or hand-off is involved.
		// An upgrade answered with 101 turns the same pair into a byte tunnel.
		pe, ds := srv.matchProxyTarget(&c.req)
		if ds != nil && c.readScratch {
			promoteRequestHeadArena(&c.req, data[:headerEnd], &w.promote)
		}
		if ds != nil && !srv.proxyNeedsDispatch(pe, &c.req) {
			c.h1OutEnd(out)
			out = c.h1OutBegin()
			start := w.beginProxy(pe, ds, c, closeConn)
			if start == proxyStartPending {
				return out, h1StepProxyInFlight
			}
			if start == proxyStartServed {
				c.releaseH1BodyBudget()
				c.dispatching = false
				if c.inFlight > 0 {
					c.inFlight--
				}
				out = appendPlainResponseMode(&c.resp, out, !closeConn, true)
				if closeConn {
					return out, h1StepClose
				}
				continue
			}
		}
		c.req.connTakenOver = false
		c.h1Cancel.attach(&c.req)
		c.req.attachConn = w.cachedH1Attacher(c)
		c.h1DispatchGen = gen
		c.h1DispatchClose = closeConn
		c.req.swFactory = c
		promoteRequestHeadArena(&c.req, data[:headerEnd], &w.promote)
		if streamBody {
			out = c.startH1BodyStream(w, out, chunked, contentLength)
		}
		c.h1DispatchFast = srv.fastDispatch.Load()
		if ds == nil && !streamBody && w.inlineCandidate() && w.queueH1Inline(c) {
			return out, h1StepDispatched
		}
		w.spawned++
		w.handlers.run(c.h1AsyncRunner())
		return out, h1StepDispatched
	}
	return out, h1StepNeedInput
}

func (c *epollConn) h1AsyncRunner() func() {
	if c.h1AsyncFn == nil {
		c.h1AsyncFn = c.runH1Async
	}
	return c.h1AsyncFn
}

func (c *epollConn) runH1Async() { c.runH1(false) }

func (c *epollConn) runH1(inline bool) {
	w := c.worker
	srv := w.server
	handler, route := c.h1Handler, c.h1Route
	c.h1Handler, c.h1Route = nil, nil
	var start int64
	if route != nil {
		start = turbo.Now()
	}
	returned := false
	defer func() {
		r := recover()
		if r != nil {
			srv.reportPanic(&c.req, r)
			c.resp.resetFastH1()
			c.resp.Status(500).String("Internal Server Error")
		}
		if route != nil {
			srv.Router.observeDemoted(route, turbo.Since(start))
		}
		if inline {
			w.endInlineHandler(&c.h1InlineSeq, r == nil && !returned)
		}
		w.pushH1Done(c)
	}()
	switch {
	case handler != nil:
		handler(&c.req, &c.resp)
	case c.h1DispatchFast:
		srv.Router.Lookup(c.req.Method, c.req.Path, &c.req)(&c.req, &c.resp)
	default:
		srv.dispatch(&c.req, &c.resp)
	}
	returned = true
}

func (c *epollConn) finishH1TakenOver() {
	if !c.req.hijacked {
		if c.resp.IsStreamed() {
			releaseStreamWriter(c.req.StreamWriter)
		}
		if c.req.conn != nil {
			_ = c.req.conn.Close()
		}
	}
	c.req.conn = nil
	c.req.attachConn = nil
	c.req.StreamWriter = nil
	c.releaseH1BodyBudget()
	c.dispatching = false
	if c.inFlight > 0 {
		c.inFlight--
	}
}

func (c *epollConn) finishH1Dispatch(w *epollWorker, gen uint32, reqClose bool) {
	c.req.finishContext()
	if c.h1EndBodyStream() || w.server.shuttingDown.Load() {
		reqClose = true
	}
	sw, _ := c.resp.sw.(*epollH1StreamWriter)
	if sw != nil {
		c.resp.sw = nil
		c.req.StreamWriter = nil
	}
	if ev := c.wsPending; ev != nil {
		if sw != nil {
			sw.release()
		}
		w.finishWSUpgrade(c, gen, ev)
		return
	}
	if c.req.connTakenOver {
		if sw != nil {
			sw.release()
		}
		c.finishH1TakenOver()
		if c.inFlight == 0 {
			w.putTakenOver(c)
		}
		return
	}
	c.releaseH1BodyBudget()
	if c.inFlight > 0 {
		c.inFlight--
	}
	c.req.attachConn = nil
	if c.generation != gen || c.fd < 0 {
		if sw != nil {
			sw.fail(ErrStreamClosed)
			sw.release()
		}
		if c.fd < 0 && c.inFlight == 0 {
			w.pool.put(c)
		}
		return
	}
	c.dispatching = false
	if sw != nil {
		if sw.headerReady && !c.req.hijacked {
			c.h1FinishStreamed(w, sw, !reqClose)
			return
		}
		sw.release()
	}
	if c.req.hijacked || c.resp.IsStreamed() {
		c.resp.Reset()
		c.resp.Status(500).String("Streaming/Hijack unavailable")
		c.h1WriteResponse(false)
		c.closeAfter = true
		w.markFlush(c)
		return
	}
	if c.h1LargeBody() {
		c.h1StartProgressiveBody(w, !reqClose)
		return
	}
	c.h1WriteResponse(!reqClose)
	if reqClose {
		c.closeAfter = true
		w.markFlush(c)
		return
	}
	w.markFlush(c)
	w.resumeConn(c)
}

func (c *epollConn) compactH1ReadBuffer() {
	if c.h1Off == 0 {
		return
	}
	remaining := c.readN - c.h1Off
	if remaining > 0 {
		copy(c.readBuf, c.readBuf[c.h1Off:c.readN])
	}
	c.readN = remaining
	c.h1Off = 0
}

const chunkedFramingSlack = 1 << 16

func decodeChunkedInto(dst, src []byte) ([]byte, [][2]string, bool) {
	d := chunkedDecoder{captureTrailers: true}
	pos := 0
	for !d.done() {
		n, data, err := d.next(src[pos:])
		if err != nil || n == 0 {
			return nil, nil, false
		}
		dst = append(dst, data...)
		pos += n
	}
	return dst, d.trailers, true
}
