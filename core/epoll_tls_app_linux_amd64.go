//go:build linux && amd64

package core

func (c *epollConn) sealTLSAppData(dst, plain []byte) []byte {
	if c.tls12 != nil {
		return buildTLS12AppDataRecords(dst, c.tls12.writer, plain)
	}
	return buildTLSAppDataRecords(dst, c.appWriter, plain)
}

func (c *epollConn) epollTLSEncryptResponse(srv *Server, plain []byte) {
	c.writeBuf = c.sealTLSAppData(c.writeBuf, plain)
}

func (c *epollConn) epollTLSHTTP1(srv *Server) int {
	proxyActive := srv.httpRouter != nil
	scratch := c.plainBuf[:0]
	for c.appBufOff < len(c.appBuf) {
		if len(c.writeBuf)-c.writeSent+len(scratch) > epollMaxPendingWrite {
			c.plainBuf = scratch[:0]
			c.epollTLSEncryptResponse(srv, scratch)
			return epollActionCloseAfterFlush
		}
		data := c.appBuf[c.appBufOff:]
		if resp, consumed, closeConn, ok := srv.matchPlainRootFastRequest(data); ok && !proxyActive {
			if !srv.tryAcquireRequestSlot() {
				break
			}
			Stats.TotalReqs.Add(1)
			srv.releaseRequestSlot()
			scratch = append(scratch, resp...)
			c.appBufOff += consumed
			if closeConn {
				c.plainBuf = scratch[:0]
				c.epollTLSEncryptResponse(srv, scratch)
				return epollActionCloseAfterFlush
			}
			continue
		}

		c.req.resetFastH1()
		headerEnd, contentLength, hasContentLength, closeConn, badTE, chunked, tooLarge, ok := ParseH1RequestHead(data, &c.req, srv.config.MaxHeaderSize, srv.config.MaxHeaderCount)
		if tooLarge {
			c.resp.Reset()
			c.resp.Status(431).String("Request Header Fields Too Large")
			scratch = appendPlainResponse(&c.resp, scratch)
			c.plainBuf = scratch[:0]
			c.epollTLSEncryptResponse(srv, scratch)
			return epollActionCloseAfterFlush
		}
		if !ok {
			break
		}
		consumed := headerEnd
		if badTE {
			c.resp.Reset()
			c.resp.Status(400).String("Bad Request")
			scratch = appendPlainResponse(&c.resp, scratch)
			c.plainBuf = scratch[:0]
			c.epollTLSEncryptResponse(srv, scratch)
			return epollActionCloseAfterFlush
		}
		if chunked {
			scanFrom := headerEnd
			if c.chunkScanPos > headerEnd && c.chunkScanPos <= len(data) {
				scanFrom = c.chunkScanPos
			}
			bodyEnd, status, resume := asyncChunkedComplete(data, scanFrom)
			if status == -1 {
				c.chunkScanPos = 0
				c.resp.Reset()
				c.resp.Status(400).String("Bad Request")
				scratch = appendPlainResponse(&c.resp, scratch)
				c.plainBuf = scratch[:0]
				c.epollTLSEncryptResponse(srv, scratch)
				return epollActionCloseAfterFlush
			}
			if status == 0 {
				c.chunkScanPos = resume
				if srv.config.MaxBodySize > 0 && int64(len(data)-headerEnd) > srv.config.MaxBodySize+chunkedFramingSlack {
					c.resp.Reset()
					c.resp.Status(413).String("Payload Too Large")
					scratch = appendPlainResponse(&c.resp, scratch)
					c.plainBuf = scratch[:0]
					c.epollTLSEncryptResponse(srv, scratch)
					return epollActionCloseAfterFlush
				}
				break
			}
			c.chunkScanPos = 0
			decoded, dok := decodeChunkedInto(c.reqBodyCopy[:0], data[headerEnd:bodyEnd])
			if !dok || (srv.config.MaxBodySize > 0 && int64(len(decoded)) > srv.config.MaxBodySize) {
				c.resp.Reset()
				if dok {
					c.resp.Status(413).String("Payload Too Large")
				} else {
					c.resp.Status(400).String("Bad Request")
				}
				scratch = appendPlainResponse(&c.resp, scratch)
				c.plainBuf = scratch[:0]
				c.epollTLSEncryptResponse(srv, scratch)
				return epollActionCloseAfterFlush
			}
			c.reqBodyCopy = decoded
			c.req.Body = decoded
			consumed = bodyEnd
		}
		if hasContentLength {
			if contentLength < 0 || (srv.config.MaxBodySize > 0 && int64(contentLength) > srv.config.MaxBodySize) {
				c.resp.Reset()
				if contentLength < 0 {
					c.resp.Status(400).String("Bad Request")
				} else {
					c.resp.Status(413).String("Payload Too Large")
				}
				scratch = appendPlainResponse(&c.resp, scratch)
				c.plainBuf = scratch[:0]
				c.epollTLSEncryptResponse(srv, scratch)
				return epollActionCloseAfterFlush
			}
			bodyEnd := headerEnd + contentLength
			if bodyEnd < headerEnd {
				c.resp.Reset()
				c.resp.Status(400).String("Bad Request")
				scratch = appendPlainResponse(&c.resp, scratch)
				c.plainBuf = scratch[:0]
				c.epollTLSEncryptResponse(srv, scratch)
				return epollActionCloseAfterFlush
			}
			if bodyEnd > len(data) {
				break
			}
			c.req.Body = data[headerEnd:bodyEnd]
			consumed = bodyEnd
		}

		if proxyActive {
			if route := srv.httpRouter.match(c.req.Path); route != nil {
				respBytes := srv.proxyFetchRaw(route, data[:consumed])
				scratch = append(scratch, respBytes...)
				c.appBufOff += consumed
				continue
			}
		}

		Stats.TotalReqs.Add(1)
		c.req.StreamWriter = nil
		c.req.conn = nil
		c.req.server = srv
		c.req.Host = c.req.cachedHost
		c.req.RemoteAddr = c.remoteAddr
		if !c.acquireIPConn(srv, &c.req) {
			c.resp.Reset()
			c.resp.Status(429).String("Your IP has too many connections open")
			scratch = appendPlainResponse(&c.resp, scratch)
			c.plainBuf = scratch[:0]
			c.epollTLSEncryptResponse(srv, scratch)
			return epollActionCloseAfterFlush
		}
		c.resp.resetFastH1()
		c.resp.SetSW(nil)
		c.resp.lazyReq = &c.req
		if len(scratch) > 0 {
			c.plainBuf = scratch[:0]
			c.epollTLSEncryptResponse(srv, scratch)
			scratch = c.plainBuf[:0]
		}
		c.req.connTakenOver = false
		c.req.attachConn = c.worker.tlsH1Attacher(c, consumed)
		if srv.fastDispatch.Load() {
			handler := srv.Router.Lookup(c.req.Method, c.req.Path, &c.req)
			handler(&c.req, &c.resp)
		} else {
			srv.dispatch(&c.req, &c.resp)
		}
		if c.req.connTakenOver {
			if c.resp.IsStreamed() && !c.req.hijacked {
				releaseStreamWriter(c.req.StreamWriter)
				if c.req.conn != nil {
					_ = c.req.conn.Close()
				}
			}
			c.req.attachConn = nil
			return epollActionDetached
		}
		c.req.attachConn = nil
		if c.req.hijacked || c.resp.IsStreamed() {
			c.resp.Reset()
			c.resp.Status(500).String("Streaming/Hijack unavailable")
			scratch = appendPlainResponse(&c.resp, scratch)
			c.plainBuf = scratch[:0]
			c.epollTLSEncryptResponse(srv, scratch)
			return epollActionCloseAfterFlush
		}
		scratch = appendPlainResponse(&c.resp, scratch)
		c.appBufOff += consumed
		if closeConn {
			c.plainBuf = scratch[:0]
			c.epollTLSEncryptResponse(srv, scratch)
			return epollActionCloseAfterFlush
		}
	}
	c.plainBuf = scratch[:0]
	if len(scratch) > 0 {
		c.epollTLSEncryptResponse(srv, scratch)
	}
	if c.appBufOff > 0 {
		c.compactApp(c.appBufOff)
		c.appBufOff = 0
	}
	return epollTLSContinue
}

func (c *epollConn) epollTLSApplicationH2(srv *Server) int {
	for {
		action, gotData := c.epollTLSDecryptToApp(srv)
		if action == epollActionNeedRead || action == epollActionCloseAfterFlush {
			if act := c.epollTLSH2Drain(srv); act == epollActionCloseAfterFlush {
				return act
			}
			return action
		}
		if !gotData {
			return epollActionNeedRead
		}
		if act := c.epollTLSH2Drain(srv); act == epollActionCloseAfterFlush {
			return act
		}
	}
}

func (c *epollConn) epollTLSH2Drain(srv *Server) int {
	if c.appBufOff >= len(c.appBuf) && len(c.appBuf) == 0 {
		return epollTLSContinue
	}
	savedWrite := c.writeBuf
	c.writeBuf = c.plainBuf[:0]
	action := c.epollProcessH2FramesTLS(srv)
	plain := c.writeBuf
	c.plainBuf = plain[:0]
	c.writeBuf = savedWrite
	if len(plain) > 0 {
		c.epollTLSEncryptResponse(srv, plain)
	}
	if c.appBufOff > 0 {
		c.compactApp(c.appBufOff)
		c.appBufOff = 0
		c.h2.appBufOff = 0
	}
	if action == epollActionCloseAfterFlush {
		return epollActionCloseAfterFlush
	}
	return epollTLSContinue
}
