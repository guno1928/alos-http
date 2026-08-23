//go:build linux && amd64

package core

func (c *epollConn) epollProcessH1(srv *Server) int {
	maxRead := srv.effectiveReadCap()
	proxyActive := srv.httpRouter != nil
	for c.readN-c.h1Off > 0 {
		if len(c.writeBuf)-c.writeSent > epollMaxPendingWrite {
			return epollActionCloseAfterFlush
		}
		data := c.readBuf[c.h1Off:c.readN]
		if resp, consumed, closeConn, ok := srv.matchPlainRootFastRequest(data); ok && !proxyActive {
			if !srv.tryAcquireRequestSlot() {
				break
			}
			Stats.TotalReqs.Add(1)
			Stats.RawReqs.Add(1)
			srv.releaseRequestSlot()
			c.writeBuf = append(c.writeBuf, resp...)
			c.h1Off += consumed
			if closeConn {
				return epollActionCloseAfterFlush
			}
			continue
		}

		c.req.resetFastH1()
		headerEnd, contentLength, hasContentLength, closeConn, badTE, chunked, tooLarge, ok := ParseH1RequestHead(data, &c.req, srv.config.MaxHeaderSize, srv.config.MaxHeaderCount)
		if tooLarge {
			statsRawBlocked()
			c.resp.Reset()
			c.resp.Status(431).String("Request Header Fields Too Large")
			c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
			return epollActionCloseAfterFlush
		}
		if !ok {
			c.compactH1ReadBuffer()
			return epollActionNeedRead
		}
		consumed := headerEnd
		if badTE {
			statsRawBlocked()
			c.resp.Reset()
			c.resp.Status(400).String("Bad Request")
			c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
			return epollActionCloseAfterFlush
		}
		if chunked {
			if !c.reserveH1BodyBudget(srv, h1ChunkedBodyReservation(srv)) {
				statsRawBlocked()
				c.resp.Reset()
				c.resp.Status(503).String("Request Body Capacity Exhausted")
				c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
				return epollActionCloseAfterFlush
			}
			scanFrom := headerEnd
			if c.chunkScanPos > headerEnd && c.chunkScanPos <= len(data) {
				scanFrom = c.chunkScanPos
			}
			bodyEnd, status, resume := asyncChunkedComplete(data, scanFrom)
			if status == -1 {
				statsRawBlocked()
				c.chunkScanPos = 0
				c.resp.Reset()
				c.resp.Status(400).String("Bad Request")
				c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
				return epollActionCloseAfterFlush
			}
			if status == 0 {
				c.chunkScanPos = resume
				if srv.config.MaxBodySize > 0 && int64(len(data)-headerEnd) > srv.config.MaxBodySize+chunkedFramingSlack {
					statsRawBlocked()
					c.resp.Reset()
					c.resp.Status(413).String("Payload Too Large")
					c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
					return epollActionCloseAfterFlush
				}
				c.deadline = deadlineFrom(c.worker.readTO)
				c.compactH1ReadBuffer()
				return epollActionNeedRead
			}
			c.chunkScanPos = 0
			decoded, dok := decodeChunkedInto(c.reqBodyCopy[:0], data[headerEnd:bodyEnd])
			if !dok {
				statsRawBlocked()
				c.resp.Reset()
				c.resp.Status(400).String("Bad Request")
				c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
				return epollActionCloseAfterFlush
			}
			if srv.config.MaxBodySize > 0 && int64(len(decoded)) > srv.config.MaxBodySize {
				statsRawBlocked()
				c.resp.Reset()
				c.resp.Status(413).String("Payload Too Large")
				c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
				return epollActionCloseAfterFlush
			}
			c.reqBodyCopy = decoded
			c.req.Body = decoded
			consumed = bodyEnd
		}
		if hasContentLength {
			if contentLength < 0 {
				statsRawBlocked()
				c.resp.Reset()
				c.resp.Status(400).String("Bad Request")
				c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
				return epollActionCloseAfterFlush
			}
			if srv.config.MaxBodySize > 0 && int64(contentLength) > srv.config.MaxBodySize {
				statsRawBlocked()
				c.resp.Reset()
				c.resp.Status(413).String("Payload Too Large")
				c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
				return epollActionCloseAfterFlush
			}
			if !c.reserveH1BodyBudget(srv, contentLength) {
				statsRawBlocked()
				c.resp.Reset()
				c.resp.Status(503).String("Request Body Capacity Exhausted")
				c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
				return epollActionCloseAfterFlush
			}
			bodyEnd := headerEnd + contentLength
			if bodyEnd < headerEnd {
				statsRawBlocked()
				c.resp.Reset()
				c.resp.Status(400).String("Bad Request")
				c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
				return epollActionCloseAfterFlush
			}
			if bodyEnd > len(data) {
				if c.h1Off+bodyEnd > cap(c.readBuf) && !c.growReadBuf(c.h1Off+bodyEnd, maxRead) {
					return epollActionCloseAfterFlush
				}
				c.deadline = deadlineFrom(c.worker.readTO)
				c.compactH1ReadBuffer()
				return epollActionNeedRead
			}
			c.req.Body = data[headerEnd:bodyEnd]
			consumed = bodyEnd
		}

		Stats.TotalReqs.Add(1)
		Stats.RawReqs.Add(1)
		c.req.StreamWriter = nil
		c.req.conn = nil
		c.req.server = srv
		c.req.Host = c.req.cachedHost
		c.req.RemoteAddr = c.remoteAddr
		if len(c.req.Body) > 0 {
			c.reqBodyCopy = append(c.reqBodyCopy[:0], c.req.Body...)
			c.req.Body = c.reqBodyCopy
		}
		if !c.acquireIPConn(srv, &c.req) {
			statsBlocked()
			c.resp.resetFastH1()
			c.resp.Status(429).String("Your IP has too many connections open")
			c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
			return epollActionCloseAfterFlush
		}
		c.resp.resetFastH1()
		c.resp.SetSW(nil)
		c.resp.lazyReq = &c.req

		c.h1Off += consumed
		c.dispatching = true
		c.inFlight++
		gen := c.generation
		w := c.worker

		// A proxied request never leaves this thread: the backend socket joins
		// the same epoll set, so no goroutine, wake-up or hand-off is involved.
		// An upgrade answered with 101 turns the same pair into a byte tunnel.
		if pe, ds := srv.matchProxyTarget(&c.req); ds != nil {
			{
				c.req.RemoteAddr = c.remoteAddr
				if w.beginProxy(pe, ds, c, closeConn) == proxyStartPending {
					return epollActionProxyInFlight
				}
				c.releaseH1BodyBudget()
				c.dispatching = false
				if c.inFlight > 0 {
					c.inFlight--
				}
				c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
				if closeConn {
					return epollActionCloseAfterFlush
				}
				continue
			}
		}
		c.req.connTakenOver = false
		c.req.attachConn = w.plainH1Attacher(c, gen)
		cc := c
		fast := srv.fastDispatch.Load()
		reqClose := closeConn
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
		return epollActionNeedRead
	}
	c.compactH1ReadBuffer()
	return epollActionNeedRead
}

func (c *epollConn) finishH1Dispatch(w *epollWorker, gen uint32, reqClose bool) {
	c.releaseH1BodyBudget()
	if c.inFlight > 0 {
		c.inFlight--
	}
	if c.req.connTakenOver {
		if c.resp.IsStreamed() && !c.req.hijacked {
			releaseStreamWriter(c.req.StreamWriter)
			if c.req.conn != nil {
				_ = c.req.conn.Close()
			}
		}
		c.req.conn = nil
		c.req.attachConn = nil
		c.req.StreamWriter = nil
		if c.inFlight == 0 {
			w.pool.put(c)
		}
		return
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
		c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
		c.closeAfter = true
		w.markFlush(c)
		return
	}
	c.writeBuf = appendPlainResponse(&c.resp, c.writeBuf)
	if reqClose {
		c.closeAfter = true
		w.markFlush(c)
		return
	}
	w.markFlush(c)
	w.readable(c, false)
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
