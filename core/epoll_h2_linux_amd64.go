//go:build linux && amd64

package core

import "log"

func (c *epollConn) epollProcessH2Frames(srv *Server) int {
	st := &c.h2
	if !st.prefaceReceived {
		if c.readN-st.appBufOff < H2PrefaceLen {
			return epollActionNeedRead
		}
		st.prefaceReceived = true
		st.appBufOff += H2PrefaceLen
	}

	for {
		if len(c.writeBuf)-c.writeSent > epollMaxPendingWrite {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
			return epollActionCloseAfterFlush
		}
		avail := c.readN - st.appBufOff
		if avail < 9 {
			c.compactH2ReadBuffer(false)
			return epollActionNeedRead
		}
		base := st.appBufOff
		frameLen := int(c.readBuf[base])<<16 | int(c.readBuf[base+1])<<8 | int(c.readBuf[base+2])
		frameType := c.readBuf[base+3]
		frameFlags := c.readBuf[base+4]
		streamID := (uint32(c.readBuf[base+5])<<24 | uint32(c.readBuf[base+6])<<16 | uint32(c.readBuf[base+7])<<8 | uint32(c.readBuf[base+8])) & 0x7fffffff
		if frameLen > int(srv.h2MaxFrameSize()) {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFrameSize)
			return epollActionCloseAfterFlush
		}
		totalLen := 9 + frameLen
		if avail < totalLen {
			c.compactH2ReadBuffer(false)
			return epollActionNeedRead
		}
		payload := c.readBuf[base+9 : base+totalLen]

		if st.expectContinuation != 0 {
			if frameType != H2FrameContinuation || streamID != st.expectContinuation {
				c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
				return epollActionCloseAfterFlush
			}
			closeConn := c.epollH2Continuation(srv, streamID, frameFlags, payload)
			st.appBufOff += totalLen
			if closeConn {
				return epollActionCloseAfterFlush
			}
			continue
		}

		closeConn := c.epollH2Frame(srv, frameType, frameFlags, streamID, payload)
		st.appBufOff += totalLen
		if closeConn {
			return epollActionCloseAfterFlush
		}
	}
}

func (c *epollConn) epollH2Frame(srv *Server, frameType, frameFlags byte, streamID uint32, payload []byte) bool {
	st := &c.h2
	switch frameType {
	case H2FrameSettings, H2FramePing, H2FramePriority, H2FrameWindowUpdate:
		if st.countCtrl() {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
			return true
		}
	case H2FrameData:
		if len(payload) == 0 && st.countCtrl() {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
			return true
		}
	}
	switch frameType {
	case H2FrameSettings:
		if streamID != 0 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
			return true
		}
		if frameFlags&H2FlagAck != 0 {
			if len(payload) > 0 {
				c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFrameSize)
				return true
			}
			return false
		}
		if len(payload)%6 != 0 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFrameSize)
			return true
		}
		if !c.epollH2Settings(payload) {
			return true
		}
		c.writeBuf = appendH2SettingsAckFrame(c.writeBuf)
		return false
	case H2FrameHeaders:
		return c.epollH2Headers(srv, streamID, frameFlags, payload)
	case H2FrameContinuation:
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
		return true
	case H2FrameData:
		return c.epollH2Data(srv, streamID, frameFlags, payload)
	case H2FrameWindowUpdate:
		return c.epollH2WindowUpdate(streamID, payload)
	case H2FramePing:
		if streamID != 0 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
			return true
		}
		if len(payload) != 8 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFrameSize)
			return true
		}
		if frameFlags&H2FlagAck == 0 {
			var pingData [8]byte
			copy(pingData[:], payload)
			c.writeBuf = appendH2PingFrame(c.writeBuf, true, pingData)
		}
		return false
	case H2FrameRSTStream:
		if streamID == 0 || len(payload) != 4 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
			return true
		}
		epollReleaseH2Stream(st, streamID)
		if st.countReset() {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
			return true
		}
		return false
	case H2FrameGoAway:
		return true
	case H2FramePriority:
		if streamID == 0 || len(payload) != 5 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
			return true
		}
		return false
	case H2FramePushPromise:
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
		return true
	default:
		return false
	}
}

func (c *epollConn) epollH2Settings(payload []byte) bool {
	st := &c.h2
	windowChanged := false
	oldWindow := st.initialWindowSize
	for i := 0; i+6 <= len(payload); i += 6 {
		id := uint16(payload[i])<<8 | uint16(payload[i+1])
		val := uint32(payload[i+2])<<24 | uint32(payload[i+3])<<16 | uint32(payload[i+4])<<8 | uint32(payload[i+5])
		switch id {
		case H2SettingMaxFrameSize:
			if val < 16384 || val > uint32(H2MaxFrameSize) {
				c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
				return false
			}
			st.maxFrameSize = val
		case H2SettingInitialWindowSize:
			if val > 2147483647 {
				c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFlowControl)
				return false
			}
			st.initialWindowSize = val
			windowChanged = true
		case H2SettingHeaderTableSize:
			if val > 65536 {
				val = 65536
			}
			st.decoder.protocolMaxSize = int(val)
			st.decoder.setMaxSize(int(val))
		}
	}
	if windowChanged {
		if delta := int64(st.initialWindowSize) - int64(oldWindow); delta != 0 {
			for id, stream := range st.streams {
				newWindow := stream.Window.Load() + delta
				if newWindow > 2147483647 {
					c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, id, H2ErrFlowControl)
					epollReleaseH2Stream(st, id)
					continue
				}
				stream.Window.Store(newWindow)
			}
		}
	}
	return true
}

func (c *epollConn) epollH2Headers(srv *Server, streamID uint32, frameFlags byte, payload []byte) bool {
	st := &c.h2
	if streamID == 0 {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
		return true
	}
	if frameFlags&H2FlagPadded != 0 {
		if len(payload) == 0 {
			c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrProtocol)
			return false
		}
		padLen := int(payload[0])
		payload = payload[1:]
		if padLen > len(payload) {
			c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrProtocol)
			return false
		}
		payload = payload[:len(payload)-padLen]
	}
	if frameFlags&H2FlagPriority != 0 {
		if len(payload) < 5 {
			c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrFrameSize)
			return false
		}
		payload = payload[5:]
	}
	if frameFlags&H2FlagEndHeaders == 0 {
		st.expectContinuation = streamID
		st.headerEndStream = frameFlags&H2FlagEndStream != 0
		st.headerAccum = append(st.headerAccum[:0], payload...)
		return false
	}
	return c.epollH2DecodedHeaders(srv, streamID, payload, frameFlags&H2FlagEndStream != 0)
}

func (c *epollConn) epollH2Continuation(srv *Server, streamID uint32, frameFlags byte, payload []byte) bool {
	st := &c.h2
	st.headerAccum = append(st.headerAccum, payload...)
	if len(st.headerAccum) > H2MaxHeaderListSize*4 {
		st.expectContinuation = 0
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
		return true
	}
	if frameFlags&H2FlagEndHeaders == 0 {
		return false
	}
	endStream := st.headerEndStream
	st.expectContinuation = 0
	return c.epollH2DecodedHeaders(srv, streamID, st.headerAccum, endStream)
}

func (c *epollConn) epollH2DecodedHeaders(srv *Server, streamID uint32, headerBlock []byte, endStream bool) bool {
	st := &c.h2
	if streamID%2 == 0 || (st.lastStreamID > 0 && streamID <= st.lastStreamID) {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
		return true
	}
	fastRoot := srv.h2RootFast.enabled && srv.httpRouter == nil

	if endStream && fastRoot && matchIndexedH2FastRootHeaderBlock(headerBlock) {
		if srv.tryAcquireRequestSlot() {
			st.lastStreamID = streamID
			Stats.TotalReqs.Add(1)
			Stats.RawReqs.Add(1)
			c.writeBuf = appendFastH2RootResponse(c.writeBuf, srv.h2RootFast, streamID, int(st.maxFrameSize))
			srv.releaseRequestSlot()
			return false
		}
	}

	if endStream && fastRoot {
		meta, ok, err := st.decoder.DecodeFastRootRequest(headerBlock)
		if err != nil {
			c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrCompression)
			return false
		}
		if ok {
			if srv.tryAcquireRequestSlot() {
				st.lastStreamID = streamID
				_ = meta
				Stats.TotalReqs.Add(1)
				Stats.RawReqs.Add(1)
				c.writeBuf = appendFastH2RootResponse(c.writeBuf, srv.h2RootFast, streamID, int(st.maxFrameSize))
				srv.releaseRequestSlot()
				return false
			}
		}
	}

	headers, meta, err := st.decoder.DecodeIntoRequest(st.headersBuf[:0], headerBlock)
	st.headersBuf = headers[:0]
	if err != nil {
		c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrCompression)
		return false
	}
	if endStream && fastRoot && meta.method == "GET" && meta.path == "/" {
		if srv.tryAcquireRequestSlot() {
			st.lastStreamID = streamID
			Stats.TotalReqs.Add(1)
			Stats.RawReqs.Add(1)
			c.writeBuf = appendFastH2RootResponse(c.writeBuf, srv.h2RootFast, streamID, int(st.maxFrameSize))
			srv.releaseRequestSlot()
			return false
		}
	}
	if len(headers) > 128 {
		c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrEnhanceYourCalm)
		return false
	}
	if len(st.streams)+len(st.sending)+c.inFlight >= int(srv.h2MaxStreams()) {
		c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrRefusedStream)
		return false
	}
	if meta.method == "" || meta.path == "" {
		c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrProtocol)
		if st.countReset() {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
			return true
		}
		return false
	}

	stream := StreamPool.Get().(*H2Stream)
	stream.Reset()
	stream.ID = streamID
	stream.Window.Store(int64(st.initialWindowSize))
	stream.RecvWindow = int64(srv.h2InitialWindow())
	stream.Method = meta.method
	stream.Path = meta.path
	stream.RawPath = meta.rawPath
	stream.Query = meta.query
	stream.Scheme = meta.scheme
	stream.Auth = meta.authority
	for i := range headers {
		switch headers[i][0] {
		case ":method", ":path", ":scheme", ":authority":
		default:
			stream.Headers = append(stream.Headers, headers[i])
		}
	}

	st.lastStreamID = streamID
	st.streams[streamID] = stream
	if endStream {
		return c.epollH2Dispatch(srv, streamID)
	}
	stream.State.Store(StreamOpen)
	return false
}

func (c *epollConn) epollH2Data(srv *Server, streamID uint32, frameFlags byte, payload []byte) bool {
	st := &c.h2
	if streamID == 0 {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
		return true
	}
	stream := st.streams[streamID]
	if stream == nil {
		return false
	}
	if stream.State.Load() >= StreamHalfClosed {
		c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrStreamClosed)
		return false
	}
	frameConsumed := len(payload)
	if frameFlags&H2FlagPadded != 0 {
		if len(payload) == 0 {
			c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrProtocol)
			return false
		}
		padLen := int(payload[0])
		payload = payload[1:]
		if padLen > len(payload) {
			c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrProtocol)
			return false
		}
		payload = payload[:len(payload)-padLen]
	}

	consumed := int64(frameConsumed)
	st.recvConnWindow -= consumed
	if st.recvConnWindow < 0 {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFlowControl)
		return true
	}
	stream.RecvWindow -= consumed
	if stream.RecvWindow < 0 {
		c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrFlowControl)
		epollReleaseH2Stream(st, streamID)
		return false
	}

	if len(payload) > 0 {
		if !srv.tryReserveBodyBytes(len(payload)) {
			c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrEnhanceYourCalm)
			epollReleaseH2Stream(st, streamID)
			return false
		}
		stream.bodyOwner = srv
		stream.bodyAccounted += int64(len(payload))
		stream.Body = append(stream.Body, payload...)
	}
	if srv.requestBodyTooLarge(len(stream.Body)) {
		c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrCancel)
		epollReleaseH2Stream(st, streamID)
		return false
	}

	consumedWindow := uint32(frameConsumed)
	st.pendingConnWindow += consumedWindow
	if st.pendingConnWindow > H2ConnectionWindowSize/2 {
		connUpdate := st.pendingConnWindow
		st.pendingConnWindow = 0
		st.recvConnWindow += int64(connUpdate)
		c.writeBuf = appendH2WindowUpdateFrame(c.writeBuf, 0, connUpdate)
	}
	c.writeBuf = appendH2WindowUpdateFrame(c.writeBuf, streamID, consumedWindow)
	stream.RecvWindow += int64(consumedWindow)

	if frameFlags&H2FlagEndStream == 0 {
		return false
	}
	stream.State.Store(StreamHalfClosed)
	return c.epollH2Dispatch(srv, streamID)
}

func (c *epollConn) epollH2WindowUpdate(streamID uint32, payload []byte) bool {
	st := &c.h2
	if len(payload) != 4 {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFrameSize)
		return true
	}
	increment := (uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])) & 0x7fffffff
	if increment == 0 {
		if streamID == 0 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
			return true
		}
		c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrProtocol)
		return false
	}
	if streamID == 0 {
		st.connWindow += int64(increment)
		if st.connWindow > 2147483647 {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFlowControl)
			return true
		}
		c.h2ResumeSending(0)
		return false
	}
	if stream := st.streams[streamID]; stream != nil {
		newWindow := stream.Window.Load() + int64(increment)
		if newWindow > 2147483647 {
			c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrFlowControl)
			epollReleaseH2Stream(st, streamID)
			return false
		}
		stream.Window.Store(newWindow)
		return false
	}
	if stream := st.sending[streamID]; stream != nil {
		newWindow := stream.Window.Load() + int64(increment)
		if newWindow > 2147483647 {
			c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrFlowControl)
			delete(st.sending, streamID)
			stream.Reset()
			StreamPool.Put(stream)
			return false
		}
		stream.Window.Store(newWindow)
		c.h2ResumeSending(streamID)
	}
	return false
}

func (c *epollConn) epollH2Dispatch(srv *Server, streamID uint32) bool {
	st := &c.h2
	stream := st.streams[streamID]
	if stream == nil {
		return false
	}

	Stats.TotalReqs.Add(1)
	Stats.RawReqs.Add(1)
	if srv.logRequests.Load() {
		log.Printf("[H2-EPOLL] stream %d: %s %s", stream.ID, stream.Method, stream.Path)
	}

	stream.req.Reset()
	stream.req.Method = stream.Method
	stream.req.Path = stream.Path
	stream.req.RawPath = stream.RawPath
	stream.req.Query = stream.Query
	stream.req.Proto = "HTTP/2"
	stream.req.Headers = append(stream.req.Headers[:0], stream.Headers...)
	stream.req.Body = stream.Body
	stream.req.StreamID = stream.ID
	stream.req.IsH2 = true
	stream.req.Host = stream.Auth
	stream.req.cachedHost = stream.Auth
	stream.req.headerCacheMask = headerCacheHost
	stream.req.RemoteAddr = c.remoteAddr
	stream.req.server = srv
	stream.req.StreamWriter = nil
	stream.req.conn = nil
	stream.req.tlsReader = nil
	stream.req.tlsWriter = nil
	stream.req.hdrBuf = nil

	if !c.acquireIPConn(srv, &stream.req) {
		statsBlocked()
		stream.Reset()
		StreamPool.Put(stream)
		delete(st.streams, streamID)
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
		return true
	}

	stream.resp.Reset()
	stream.resp.SetSW(nil)
	stream.resp.lazyReq = &stream.req

	delete(st.streams, streamID)
	stream.asyncBusy = true
	c.inFlight++

	gen := c.generation
	w := c.worker
	cc := c
	sid := streamID

	// A proxied stream is driven in this loop. Previously it parked a goroutine
	// on the backend, which also meant per-domain timeouts were ignored because
	// the blocking path used one process-global upstream client.
	if pe, ds := srv.matchProxyTarget(&stream.req); ds != nil {
		{
			if w.beginProxyH2(pe, ds, c, stream, streamID) == proxyStartPending {
				return false
			}
			c.finishH2Dispatch(w, gen, sid, stream)
			return false
		}
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				stream.resp.Reset()
				stream.resp.Status(500).String("Internal Server Error")
			}
			w.postTask(func(w *epollWorker) { cc.finishH2Dispatch(w, gen, sid, stream) })
		}()
		if srv.fastDispatch.Load() {
			promoteRequestStrings(&stream.req)
			handler := srv.Router.Lookup(stream.req.Method, stream.req.Path, &stream.req)
			handler(&stream.req, &stream.resp)
		} else {
			srv.dispatch(&stream.req, &stream.resp)
		}
	}()
	return false
}

func (c *epollConn) finishH2Dispatch(w *epollWorker, gen uint32, streamID uint32, stream *H2Stream) {
	if c.inFlight > 0 {
		c.inFlight--
	}
	if c.generation != gen || c.fd < 0 {
		stream.asyncBusy = false
		stream.Reset()
		StreamPool.Put(stream)
		if c.fd < 0 && c.inFlight == 0 {
			w.pool.put(c)
		}
		return
	}
	stream.asyncBusy = false
	st := &c.h2
	resp := &stream.resp
	if stream.req.hijacked || resp.IsStreamed() {
		resp.Reset()
		resp.Status(500).String("Streaming/Hijack unsupported in epoll HTTP/2 backend")
	}
	if w.server.config.MaxWriteSize > 0 && int64(resp.transmittedBodyLen()) > w.server.config.MaxWriteSize {
		resp.Reset()
		resp.Status(500).String("Response Too Large")
	}

	stream.respHeadersSent = false
	stream.respOff = 0
	var done bool
	if c.tls {
		plain, d := c.h2AppendWindowed(w.h2FinishScratch[:0], stream, streamID)
		done = d
		w.h2FinishScratch = plain[:0]
		c.writeBuf = c.sealTLSAppData(c.writeBuf, plain)
	} else {
		c.writeBuf, done = c.h2AppendWindowed(c.writeBuf, stream, streamID)
	}
	if done {
		stream.Reset()
		StreamPool.Put(stream)
	} else {
		st.sending[streamID] = stream
		stream.stallBytes = len(resp.transmittedBodyBytes())
		st.sendingBytes += int64(stream.stallBytes)
		if st.sendingBytes > epollMaxPendingWrite {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
			c.closeAfter = true
		}
	}
	w.markFlush(c)
}

func (c *epollConn) h2AppendWindowed(dst []byte, stream *H2Stream, streamID uint32) ([]byte, bool) {
	st := &c.h2
	resp := &stream.resp
	body := resp.transmittedBodyBytes()
	if !stream.respHeadersSent {
		dst = appendH2ResponseHeadersFrame(dst, streamID, resp, len(body) == 0)
		stream.respHeadersSent = true
	}
	frameLimit := int(st.maxFrameSize)
	if frameLimit <= 0 {
		frameLimit = H2DefaultMaxFrameSize
	}
	for stream.respOff < len(body) {
		avail := stream.Window.Load()
		if st.connWindow < avail {
			avail = st.connWindow
		}
		if avail <= 0 {
			break
		}
		n := len(body) - stream.respOff
		if int64(n) > avail {
			n = int(avail)
		}
		if n > frameLimit {
			n = frameLimit
		}
		end := stream.respOff+n == len(body)
		flags := byte(0)
		if end {
			flags = H2FlagEndStream
		}
		dst = appendH2Frame(dst, H2FrameData, flags, streamID, body[stream.respOff:stream.respOff+n])
		stream.respOff += n
		st.connWindow -= int64(n)
		stream.Window.Add(-int64(n))
	}
	return dst, stream.respOff >= len(body)
}

func (c *epollConn) h2ResumeSending(streamID uint32) {
	st := &c.h2
	if streamID != 0 {
		stream := st.sending[streamID]
		if stream == nil {
			return
		}
		var done bool
		c.writeBuf, done = c.h2AppendWindowed(c.writeBuf, stream, streamID)
		if done {
			delete(st.sending, streamID)
			st.sendingBytes -= int64(stream.stallBytes)
			stream.Reset()
			StreamPool.Put(stream)
		}
		return
	}
	for id, stream := range st.sending {
		var done bool
		c.writeBuf, done = c.h2AppendWindowed(c.writeBuf, stream, id)
		if done {
			delete(st.sending, id)
			st.sendingBytes -= int64(stream.stallBytes)
			stream.Reset()
			StreamPool.Put(stream)
		}
	}
}

func epollReleaseH2Stream(st *tlsWorkerH2State, streamID uint32) {
	stream := st.streams[streamID]
	if stream == nil {
		return
	}
	delete(st.streams, streamID)
	stream.Reset()
	StreamPool.Put(stream)
}
