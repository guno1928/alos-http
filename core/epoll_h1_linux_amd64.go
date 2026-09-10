//go:build linux && amd64

package core

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

func (c *epollConn) h1WriteResponse(keepAlive bool) {
	if c.tls {
		plain := appendPlainResponseMode(&c.resp, c.plainBuf[:0], keepAlive, true)
		c.writeBuf = c.sealTLSAppData(c.writeBuf, plain)
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
	maxRead := srv.effectiveReadCap()
	proxyActive := srv.httpRouter != nil
	for len(c.h1Unread()) > 0 {
		if c.h1PendingWrite(out) > epollMaxPendingWrite {
			return out, h1StepClose
		}
		data := c.h1Unread()
		if resp, consumed, closeConn, ok := srv.matchPlainRootFastRequest(data); ok && !proxyActive {
			if !srv.tryAcquireRequestSlot() {
				return out, h1StepNeedInput
			}
			Stats.TotalReqs.Add(1)
			Stats.RawReqs.Add(1)
			srv.releaseRequestSlot()
			out = append(out, resp...)
			c.h1Advance(consumed)
			if closeConn {
				return out, h1StepClose
			}
			continue
		}

		c.req.resetFastH1()
		headerEnd, contentLength, hasContentLength, closeConn, badTE, chunked, tooLarge, ok := ParseH1RequestHead(data, &c.req, srv.config.MaxHeaderSize, srv.config.MaxHeaderCount)
		if tooLarge {
			return c.h1Reject(out, 431, "Request Header Fields Too Large"), h1StepClose
		}
		if !ok {
			return out, h1StepNeedInput
		}
		consumed := headerEnd
		if badTE {
			return c.h1Reject(out, 400, "Bad Request"), h1StepClose
		}
		if chunked {
			if !c.reserveH1BodyBudget(srv, h1ChunkedBodyReservation(srv)) {
				return c.h1Reject(out, 503, "Request Body Capacity Exhausted"), h1StepClose
			}
			scanFrom := headerEnd
			if c.chunkScanPos > headerEnd && c.chunkScanPos <= len(data) {
				scanFrom = c.chunkScanPos
			}
			bodyEnd, status, resume := asyncChunkedComplete(data, scanFrom)
			if status == -1 {
				c.chunkScanPos = 0
				return c.h1Reject(out, 400, "Bad Request"), h1StepClose
			}
			if status == 0 {
				c.chunkScanPos = resume
				if srv.config.MaxBodySize > 0 && int64(len(data)-headerEnd) > srv.config.MaxBodySize+chunkedFramingSlack {
					return c.h1Reject(out, 413, "Payload Too Large"), h1StepClose
				}
				c.deadline = deadlineFrom(c.worker.readTO)
				return out, h1StepNeedInput
			}
			c.chunkScanPos = 0
			decoded, dok := decodeChunkedInto(c.reqBodyCopy[:0], data[headerEnd:bodyEnd])
			if !dok {
				return c.h1Reject(out, 400, "Bad Request"), h1StepClose
			}
			if srv.config.MaxBodySize > 0 && int64(len(decoded)) > srv.config.MaxBodySize {
				return c.h1Reject(out, 413, "Payload Too Large"), h1StepClose
			}
			c.reqBodyCopy = decoded
			c.req.Body = decoded
			consumed = bodyEnd
		}
		if hasContentLength {
			if contentLength < 0 {
				return c.h1Reject(out, 400, "Bad Request"), h1StepClose
			}
			if srv.config.MaxBodySize > 0 && int64(contentLength) > srv.config.MaxBodySize {
				return c.h1Reject(out, 413, "Payload Too Large"), h1StepClose
			}
			if !c.reserveH1BodyBudget(srv, contentLength) {
				return c.h1Reject(out, 503, "Request Body Capacity Exhausted"), h1StepClose
			}
			bodyEnd := headerEnd + contentLength
			if bodyEnd < headerEnd {
				return c.h1Reject(out, 400, "Bad Request"), h1StepClose
			}
			if bodyEnd > len(data) {
				if !c.tls && c.h1Off+bodyEnd > cap(c.readBuf) && !c.growReadBuf(c.h1Off+bodyEnd, maxRead) {
					return out, h1StepClose
				}
				c.deadline = deadlineFrom(c.worker.readTO)
				return out, h1StepNeedInput
			}
			c.reqBodyCopy = append(c.reqBodyCopy[:0], data[headerEnd:bodyEnd]...)
			c.req.Body = c.reqBodyCopy
			consumed = bodyEnd
		}

		Stats.TotalReqs.Add(1)
		Stats.RawReqs.Add(1)
		c.req.StreamWriter = nil
		c.req.conn = nil
		c.req.server = srv
		c.req.Host = c.req.cachedHost
		c.req.RemoteAddr = c.remoteAddr
		c.req.IsTLS = c.tls
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
		c.dispatching = true
		c.inFlight++
		gen := c.generation
		w := c.worker

		// A proxied request never leaves this thread: the backend socket joins
		// the same epoll set, so no goroutine, wake-up or hand-off is involved.
		// An upgrade answered with 101 turns the same pair into a byte tunnel.
		if pe, ds := srv.matchProxyTarget(&c.req); ds != nil {
			c.h1OutEnd(out)
			out = c.h1OutBegin()
			if w.beginProxy(pe, ds, c, closeConn) == proxyStartPending {
				return out, h1StepProxyInFlight
			}
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
		c.req.connTakenOver = false
		if srv.config.InlineHandlers {
			c.req.attachConn = w.inlineH1Attacher(c)
			promoteRequestStrings(&c.req)
			c.runH1Inline(srv)
			if c.req.connTakenOver {
				c.finishH1TakenOver()
				return out, h1StepDetached
			}
			c.req.attachConn = nil
			c.dispatching = false
			if c.inFlight > 0 {
				c.inFlight--
			}
			c.releaseH1BodyBudget()
			if c.req.hijacked || c.resp.IsStreamed() {
				c.resp.Reset()
				c.resp.Status(500).String("Streaming/Hijack unavailable")
				return appendPlainResponseClose(&c.resp, out), h1StepClose
			}
			out = appendPlainResponseMode(&c.resp, out, !closeConn, true)
			if closeConn {
				return out, h1StepClose
			}
			continue
		}
		c.req.attachConn = w.h1Attacher(c, gen)
		promoteRequestStrings(&c.req)
		cc := c
		fast := srv.fastDispatch.Load()
		reqClose := closeConn
		w.spawned++
		go func() {
			defer func() {
				if r := recover(); r != nil {
					cc.resp.resetFastH1()
					cc.resp.Status(500).String("Internal Server Error")
				}
				w.postTask(func(w *epollWorker) { cc.finishH1Dispatch(w, gen, reqClose) })
			}()
			if fast {
				handler := srv.Router.Lookup(cc.req.Method, cc.req.Path, &cc.req)
				handler(&cc.req, &cc.resp)
			} else {
				srv.dispatch(&cc.req, &cc.resp)
			}
		}()
		return out, h1StepDispatched
	}
	return out, h1StepNeedInput
}

func (c *epollConn) runH1Inline(srv *Server) {
	defer func() {
		if r := recover(); r != nil {
			c.resp.resetFastH1()
			c.resp.Status(500).String("Internal Server Error")
		}
	}()
	if srv.fastDispatch.Load() {
		handler := srv.Router.Lookup(c.req.Method, c.req.Path, &c.req)
		handler(&c.req, &c.resp)
		return
	}
	srv.dispatch(&c.req, &c.resp)
}

func (c *epollConn) finishH1TakenOver() {
	if c.resp.IsStreamed() && !c.req.hijacked {
		releaseStreamWriter(c.req.StreamWriter)
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
	if c.req.connTakenOver {
		c.finishH1TakenOver()
		if c.inFlight == 0 {
			w.pool.put(c)
		}
		return
	}
	c.releaseH1BodyBudget()
	if c.inFlight > 0 {
		c.inFlight--
	}
	c.req.attachConn = nil
	if c.generation != gen || c.fd < 0 {
		if c.fd < 0 && c.inFlight == 0 {
			w.pool.put(c)
		}
		return
	}
	c.dispatching = false
	if c.req.hijacked || c.resp.IsStreamed() {
		c.resp.Reset()
		c.resp.Status(500).String("Streaming/Hijack unavailable")
		c.h1WriteResponse(false)
		c.closeAfter = true
		w.markFlush(c)
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

func (c *epollConn) growReadBuf(minCap, maxRead int) bool {
	grown, ok := growPlainReadBuffer(c.readBuf[:c.readN], minCap-c.readN, maxRead)
	if !ok {
		return false
	}
	c.readBuf = grown[:cap(grown)]
	return true
}

const chunkedFramingSlack = 1 << 16

func decodeChunkedInto(dst, src []byte) ([]byte, bool) {
	pos := 0
	for {
		nl := indexByteFrom(src, '\n', pos)
		if nl < 0 {
			return nil, false
		}
		line := src[pos:nl]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if semi := indexByteFrom(line, ';', 0); semi >= 0 {
			line = line[:semi]
		}
		line = trimASCIISpaceBytes(line)
		size, ok := parseHex64Bytes(line)
		if !ok {
			return nil, false
		}
		pos = nl + 1
		if size == 0 {
			return dst, true
		}
		if size > int64(len(src)-pos) {
			return nil, false
		}
		end := pos + int(size)
		dst = append(dst, src[pos:end]...)
		pos = end
		nl2 := indexByteFrom(src, '\n', pos)
		if nl2 < 0 {
			return nil, false
		}
		pos = nl2 + 1
	}
}
