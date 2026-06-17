//go:build linux && amd64

package core

import "log"

func (worker *plainUringWorker) processHTTP2(conn *plainWorkerConn) error {
	for {
		action, err := worker.processHTTP2Frames(conn)
		if err != nil {
			return err
		}
		switch action {
		case tlsWorkerActionContinue:
			continue
		case tlsWorkerActionNeedRead:
			return worker.queueRead(conn)
		case tlsWorkerActionWrote:
			return nil
		case tlsWorkerActionClose:
			return worker.closeConnection(conn)
		default:
			return nil
		}
	}
}

func (worker *plainUringWorker) processHTTP2Frames(conn *plainWorkerConn) (int, error) {
	st := &conn.h2
	if !st.prefaceReceived {
		avail := conn.readN - st.appBufOff
		if avail < H2PrefaceLen {
			return worker.flushHTTP2Frames(conn, false)
		}
		for i := 0; i < H2PrefaceLen; i++ {
			if conn.readBuf[st.appBufOff+i] != H2ClientPreface[i] {
				conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf[:0], st.lastStreamID, H2ErrProtocol)
				return worker.flushHTTP2Frames(conn, true)
			}
		}
		st.prefaceReceived = true
		st.appBufOff += H2PrefaceLen
	}

	for {
		avail := conn.readN - st.appBufOff
		if avail < 9 {
			worker.compactHTTP2ReadBuffer(conn, false)
			return worker.flushHTTP2Frames(conn, false)
		}
		base := st.appBufOff
		frameLen := int(conn.readBuf[base])<<16 | int(conn.readBuf[base+1])<<8 | int(conn.readBuf[base+2])
		frameType := conn.readBuf[base+3]
		frameFlags := conn.readBuf[base+4]
		streamID := (uint32(conn.readBuf[base+5])<<24 | uint32(conn.readBuf[base+6])<<16 | uint32(conn.readBuf[base+7])<<8 | uint32(conn.readBuf[base+8])) & 0x7fffffff
		if frameLen > int(H2MaxFrameSize) {
			conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf[:0], st.lastStreamID, H2ErrFrameSize)
			return worker.flushHTTP2Frames(conn, true)
		}
		totalLen := 9 + frameLen
		if avail < totalLen {
			worker.compactHTTP2ReadBuffer(conn, false)
			return worker.flushHTTP2Frames(conn, false)
		}
		payload := conn.readBuf[base+9 : base+totalLen]

		if st.expectContinuation != 0 {
			if frameType != H2FrameContinuation || streamID != st.expectContinuation {
				conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf[:0], st.lastStreamID, H2ErrProtocol)
				return worker.flushHTTP2Frames(conn, true)
			}
			action, closeConn := worker.handleHTTP2Continuation(conn, streamID, frameFlags, payload)
			st.appBufOff += totalLen
			if closeConn {
				return worker.flushHTTP2Frames(conn, true)
			}
			if action != tlsWorkerActionContinue {
				return worker.flushHTTP2Frames(conn, false)
			}
			continue
		}

		action, closeConn := worker.handleHTTP2Frame(conn, frameType, frameFlags, streamID, payload)
		st.appBufOff += totalLen
		if closeConn {
			return worker.flushHTTP2Frames(conn, true)
		}
		if action != tlsWorkerActionContinue {
			return worker.flushHTTP2Frames(conn, false)
		}
	}
}

func (worker *plainUringWorker) handleHTTP2Frame(conn *plainWorkerConn, frameType, frameFlags byte, streamID uint32, payload []byte) (int, bool) {
	st := &conn.h2
	switch frameType {
	case H2FrameSettings:
		if streamID != 0 {
			conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrProtocol)
			return tlsWorkerActionWrote, true
		}
		if frameFlags&H2FlagAck != 0 {
			if len(payload) > 0 {
				conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrFrameSize)
				return tlsWorkerActionWrote, true
			}
			return tlsWorkerActionContinue, false
		}
		if len(payload)%6 != 0 {
			conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrFrameSize)
			return tlsWorkerActionWrote, true
		}
		if !worker.processHTTP2Settings(conn, payload) {
			return tlsWorkerActionWrote, true
		}
		conn.writeBuf = appendH2SettingsAckFrame(conn.writeBuf)
		return tlsWorkerActionContinue, false
	case H2FrameHeaders:
		return worker.handleHTTP2Headers(conn, streamID, frameFlags, payload)
	case H2FrameContinuation:
		conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrProtocol)
		return tlsWorkerActionWrote, true
	case H2FrameData:
		return worker.handleHTTP2Data(conn, streamID, frameFlags, payload)
	case H2FrameWindowUpdate:
		return worker.handleHTTP2WindowUpdate(conn, streamID, payload)
	case H2FramePing:
		if streamID != 0 {
			conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrProtocol)
			return tlsWorkerActionWrote, true
		}
		if len(payload) != 8 {
			conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrFrameSize)
			return tlsWorkerActionWrote, true
		}
		if frameFlags&H2FlagAck == 0 {
			var pingData [8]byte
			copy(pingData[:], payload)
			conn.writeBuf = appendH2PingFrame(conn.writeBuf, true, pingData)
		}
		return tlsWorkerActionContinue, false
	case H2FrameRSTStream:
		if streamID == 0 || len(payload) != 4 {
			conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrProtocol)
			return tlsWorkerActionWrote, true
		}
		worker.releaseHTTP2Stream(st, streamID)
		return tlsWorkerActionContinue, false
	case H2FrameGoAway:
		return tlsWorkerActionClose, true
	case H2FramePriority:
		if streamID == 0 || len(payload) != 5 {
			conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrProtocol)
			return tlsWorkerActionWrote, true
		}
		return tlsWorkerActionContinue, false
	case H2FramePushPromise:
		conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrProtocol)
		return tlsWorkerActionWrote, true
	default:
		return tlsWorkerActionContinue, false
	}
}

func (worker *plainUringWorker) processHTTP2Settings(conn *plainWorkerConn, payload []byte) bool {
	st := &conn.h2
	for i := 0; i+6 <= len(payload); i += 6 {
		id := uint16(payload[i])<<8 | uint16(payload[i+1])
		val := uint32(payload[i+2])<<24 | uint32(payload[i+3])<<16 | uint32(payload[i+4])<<8 | uint32(payload[i+5])
		switch id {
		case H2SettingMaxFrameSize:
			if val < 16384 || val > uint32(H2MaxFrameSize) {
				conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrProtocol)
				return false
			}
			st.maxFrameSize = val
		case H2SettingInitialWindowSize:
			if val > 2147483647 {
				conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrFlowControl)
				return false
			}
			delta := int64(val) - int64(st.initialWindowSize)
			st.initialWindowSize = val
			for id, stream := range st.streams {
				newWindow := stream.Window.Load() + delta
				if newWindow > 2147483647 {
					conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, id, H2ErrFlowControl)
					worker.releaseHTTP2Stream(st, id)
					continue
				}
				stream.Window.Store(newWindow)
			}
		case H2SettingHeaderTableSize:
			if val > 65536 {
				val = 65536
			}
			st.decoder.protocolMaxSize = int(val)
			st.decoder.setMaxSize(int(val))
		}
	}
	return true
}

func (worker *plainUringWorker) handleHTTP2Headers(conn *plainWorkerConn, streamID uint32, frameFlags byte, payload []byte) (int, bool) {
	st := &conn.h2
	if streamID == 0 {
		conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrProtocol)
		return tlsWorkerActionWrote, true
	}
	if frameFlags&H2FlagPadded != 0 {
		if len(payload) == 0 {
			conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, streamID, H2ErrProtocol)
			return tlsWorkerActionWrote, false
		}
		padLen := int(payload[0])
		payload = payload[1:]
		if padLen > len(payload) {
			conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, streamID, H2ErrProtocol)
			return tlsWorkerActionWrote, false
		}
		payload = payload[:len(payload)-padLen]
	}
	if frameFlags&H2FlagPriority != 0 {
		if len(payload) < 5 {
			conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, streamID, H2ErrFrameSize)
			return tlsWorkerActionWrote, false
		}
		payload = payload[5:]
	}
	if frameFlags&H2FlagEndHeaders == 0 {
		st.expectContinuation = streamID
		st.headerEndStream = frameFlags&H2FlagEndStream != 0
		st.headerAccum = append(st.headerAccum[:0], payload...)
		return tlsWorkerActionContinue, false
	}
	return worker.processHTTP2DecodedHeaders(conn, streamID, payload, frameFlags&H2FlagEndStream != 0)
}

func (worker *plainUringWorker) handleHTTP2Continuation(conn *plainWorkerConn, streamID uint32, frameFlags byte, payload []byte) (int, bool) {
	st := &conn.h2
	st.headerAccum = append(st.headerAccum, payload...)
	if len(st.headerAccum) > H2MaxHeaderListSize*4 {
		st.expectContinuation = 0
		conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
		return tlsWorkerActionWrote, true
	}
	if frameFlags&H2FlagEndHeaders == 0 {
		return tlsWorkerActionContinue, false
	}
	endStream := st.headerEndStream
	st.expectContinuation = 0
	return worker.processHTTP2DecodedHeaders(conn, streamID, st.headerAccum, endStream)
}

func (worker *plainUringWorker) processHTTP2DecodedHeaders(conn *plainWorkerConn, streamID uint32, headerBlock []byte, endStream bool) (int, bool) {
	st := &conn.h2
	if streamID%2 == 0 || (st.lastStreamID > 0 && streamID <= st.lastStreamID) {
		conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrProtocol)
		return tlsWorkerActionWrote, true
	}

	if endStream && worker.server.h2RootFast.enabled && matchIndexedH2FastRootHeaderBlock(headerBlock) {
		if worker.server.tryAcquireRequestSlot() {
			st.lastStreamID = streamID
			if worker.server.logRequests.Load() {
				log.Printf("[H2C] stream %d: GET / (native fast)", streamID)
			}
			Stats.TotalReqs.Add(1)
			conn.closeAfter = false
			conn.writeBuf = appendFastH2RootResponse(conn.writeBuf, worker.server.h2RootFast, streamID, int(st.maxFrameSize))
			worker.server.releaseRequestSlot()
			return tlsWorkerActionWrote, false
		}
	}

	if endStream && worker.server.h2RootFast.enabled {
		meta, ok, err := st.decoder.DecodeFastRootRequest(headerBlock)
		if err != nil {
			conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, streamID, H2ErrCompression)
			return tlsWorkerActionWrote, false
		}
		if ok {
			if worker.server.tryAcquireRequestSlot() {
				st.lastStreamID = streamID
				if worker.server.logRequests.Load() {
					log.Printf("[H2C] stream %d: %s %s (native fast meta)", streamID, meta.method, meta.path)
				}
				Stats.TotalReqs.Add(1)
				conn.closeAfter = false
				conn.writeBuf = appendFastH2RootResponse(conn.writeBuf, worker.server.h2RootFast, streamID, int(st.maxFrameSize))
				worker.server.releaseRequestSlot()
				return tlsWorkerActionWrote, false
			}
		}
	}

	headers, meta, err := st.decoder.DecodeIntoRequest(st.headersBuf[:0], headerBlock)
	st.headersBuf = headers[:0]
	if err != nil {
		conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, streamID, H2ErrCompression)
		return tlsWorkerActionWrote, false
	}
	if endStream && worker.server.h2RootFast.enabled && meta.method == "GET" && meta.path == "/" {
		if worker.server.tryAcquireRequestSlot() {
			st.lastStreamID = streamID
			if worker.server.logRequests.Load() {
				log.Printf("[H2C] stream %d: %s %s (native fast)", streamID, meta.method, meta.path)
			}
			Stats.TotalReqs.Add(1)
			conn.closeAfter = false
			conn.writeBuf = appendFastH2RootResponse(conn.writeBuf, worker.server.h2RootFast, streamID, int(st.maxFrameSize))
			worker.server.releaseRequestSlot()
			return tlsWorkerActionWrote, false
		}
	}
	if len(headers) > 128 {
		conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, streamID, H2ErrEnhanceYourCalm)
		return tlsWorkerActionWrote, false
	}
	if len(st.streams) >= H2MaxConcurrentStream {
		conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, streamID, H2ErrRefusedStream)
		return tlsWorkerActionWrote, false
	}
	if meta.method == "" || meta.path == "" {
		conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, streamID, H2ErrProtocol)
		return tlsWorkerActionWrote, false
	}

	stream := StreamPool.Get().(*H2Stream)
	stream.Reset()
	stream.ID = streamID
	stream.Window.Store(int64(st.initialWindowSize))
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
		return worker.dispatchHTTP2Stream(conn, streamID)
	}
	stream.State.Store(StreamOpen)
	return tlsWorkerActionContinue, false
}

func (worker *plainUringWorker) handleHTTP2Data(conn *plainWorkerConn, streamID uint32, frameFlags byte, payload []byte) (int, bool) {
	st := &conn.h2
	if streamID == 0 {
		conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrProtocol)
		return tlsWorkerActionWrote, true
	}
	stream := st.streams[streamID]
	if stream == nil {
		return tlsWorkerActionContinue, false
	}
	if stream.State.Load() >= StreamHalfClosed {
		conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, streamID, H2ErrStreamClosed)
		return tlsWorkerActionWrote, false
	}
	frameConsumed := len(payload)
	if frameFlags&H2FlagPadded != 0 {
		if len(payload) == 0 {
			conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, streamID, H2ErrProtocol)
			return tlsWorkerActionWrote, false
		}
		padLen := int(payload[0])
		payload = payload[1:]
		if padLen > len(payload) {
			conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, streamID, H2ErrProtocol)
			return tlsWorkerActionWrote, false
		}
		payload = payload[:len(payload)-padLen]
	}

	consumed := int64(frameConsumed)
	st.recvConnWindow -= consumed
	if st.recvConnWindow < 0 {
		conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrFlowControl)
		return tlsWorkerActionWrote, true
	}

	stream.Body = append(stream.Body, payload...)
	if worker.server.config.MaxBodySize > 0 && int64(len(stream.Body)) > worker.server.config.MaxBodySize {
		conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, streamID, H2ErrCancel)
		worker.releaseHTTP2Stream(st, streamID)
		return tlsWorkerActionWrote, false
	}

	consumedWindow := uint32(frameConsumed)
	st.pendingConnWindow += consumedWindow
	if st.pendingConnWindow > H2ConnectionWindowSize/2 {
		connUpdate := st.pendingConnWindow
		st.pendingConnWindow = 0
		st.recvConnWindow += int64(connUpdate)
		conn.writeBuf = appendH2WindowUpdateFrame(conn.writeBuf, 0, connUpdate)
	}
	conn.writeBuf = appendH2WindowUpdateFrame(conn.writeBuf, streamID, consumedWindow)

	if frameFlags&H2FlagEndStream == 0 {
		return tlsWorkerActionContinue, false
	}
	stream.State.Store(StreamHalfClosed)
	return worker.dispatchHTTP2Stream(conn, streamID)
}

func (worker *plainUringWorker) handleHTTP2WindowUpdate(conn *plainWorkerConn, streamID uint32, payload []byte) (int, bool) {
	st := &conn.h2
	if len(payload) != 4 {
		conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrFrameSize)
		return tlsWorkerActionWrote, true
	}
	increment := (uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])) & 0x7fffffff
	if increment == 0 {
		if streamID == 0 {
			conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrProtocol)
			return tlsWorkerActionWrote, true
		}
		conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, streamID, H2ErrProtocol)
		return tlsWorkerActionWrote, false
	}
	if streamID == 0 {
		st.connWindow += int64(increment)
		if st.connWindow > 2147483647 {
			conn.writeBuf = appendH2GoAwayFrame(conn.writeBuf, st.lastStreamID, H2ErrFlowControl)
			return tlsWorkerActionWrote, true
		}
		return tlsWorkerActionContinue, false
	}
	stream := st.streams[streamID]
	if stream == nil {
		return tlsWorkerActionContinue, false
	}
	newWindow := stream.Window.Load() + int64(increment)
	if newWindow > 2147483647 {
		conn.writeBuf = appendH2RSTStreamFrame(conn.writeBuf, streamID, H2ErrFlowControl)
		worker.releaseHTTP2Stream(st, streamID)
		return tlsWorkerActionWrote, false
	}
	stream.Window.Store(newWindow)
	return tlsWorkerActionContinue, false
}

func (worker *plainUringWorker) dispatchHTTP2Stream(conn *plainWorkerConn, streamID uint32) (int, bool) {
	st := &conn.h2
	stream := st.streams[streamID]
	if stream == nil {
		return tlsWorkerActionContinue, false
	}

	Stats.TotalReqs.Add(1)
	if worker.server.logRequests.Load() {
		log.Printf("[H2C] stream %d: %s %s (native)", stream.ID, stream.Method, stream.Path)
	}

	conn.req.Reset()
	conn.req.Method = stream.Method
	conn.req.Path = stream.Path
	conn.req.RawPath = stream.RawPath
	conn.req.Query = stream.Query
	conn.req.Proto = "HTTP/2"
	conn.req.Headers = append(conn.req.Headers[:0], stream.Headers...)
	conn.req.Body = stream.Body
	conn.req.StreamID = stream.ID
	conn.req.IsH2 = true
	conn.req.Host = stream.Auth
	conn.req.cachedHost = stream.Auth
	conn.req.headerCacheMask = headerCacheHost
	conn.req.RemoteAddr = conn.remoteAddr
	conn.req.server = worker.server
	conn.req.StreamWriter = nil
	conn.req.conn = nil
	conn.req.tlsReader = nil
	conn.req.tlsWriter = nil
	conn.req.hdrBuf = nil

	conn.resp.Reset()
	conn.resp.SetSW(nil)
	conn.resp.lazyReq = &conn.req
	if worker.server.fastDispatch.Load() {
		handler := worker.server.Router.Lookup(conn.req.Method, conn.req.Path, &conn.req)
		handler(&conn.req, &conn.resp)
	} else {
		worker.server.dispatch(&conn.req, &conn.resp)
	}
	if conn.req.hijacked || conn.resp.IsStreamed() {
		conn.resp.Reset()
		conn.resp.Status(500).String("Streaming/Hijack unsupported in plain io_uring HTTP/2 backend")
	}
	if worker.server.config.MaxWriteSize > 0 && int64(conn.resp.transmittedBodyLen()) > worker.server.config.MaxWriteSize {
		conn.resp.Reset()
		conn.resp.Status(500).String("Response Too Large")
	}

	start := len(conn.writeBuf)
	conn.writeBuf = appendH2ResponseFrames(conn.writeBuf, streamID, &conn.resp, st.maxFrameSize)
	bodyLen := int64(conn.resp.transmittedBodyLen())
	if bodyLen > 0 {
		streamWindow := stream.Window.Load()
		if bodyLen > st.connWindow || bodyLen > streamWindow {
			conn.resp.Reset()
			conn.resp.Status(500).String("HTTP/2 flow control window exhausted")
			conn.writeBuf = conn.writeBuf[:start]
			conn.writeBuf = appendH2ResponseFrames(conn.writeBuf, streamID, &conn.resp, st.maxFrameSize)
		} else {
			st.connWindow -= bodyLen
			stream.Window.Add(-bodyLen)
		}
	}
	worker.releaseHTTP2Stream(st, streamID)
	return tlsWorkerActionWrote, false
}

func (worker *plainUringWorker) releaseHTTP2Stream(st *tlsWorkerH2State, streamID uint32) {
	stream := st.streams[streamID]
	if stream == nil {
		return
	}
	delete(st.streams, streamID)
	stream.Reset()
	StreamPool.Put(stream)
}

func (worker *plainUringWorker) flushHTTP2Frames(conn *plainWorkerConn, closeAfter bool) (int, error) {
	if len(conn.writeBuf) == 0 {
		if closeAfter {
			return tlsWorkerActionClose, nil
		}
		return tlsWorkerActionNeedRead, nil
	}
	return worker.queueHTTP2Frames(conn, closeAfter)
}

func (worker *plainUringWorker) queueHTTP2Frames(conn *plainWorkerConn, closeAfter bool) (int, error) {
	conn.closeAfter = closeAfter
	conn.writeN = len(conn.writeBuf)
	conn.writeSent = 0
	conn.state = plainConnStateWriting
	if err := worker.ring.prepSendUser(conn.fd, conn.writeBuf[:conn.writeN], plainEncodeUserData(plainUringOpWrite, int(conn.index), conn.generation)); err != nil {
		return tlsWorkerActionClose, nil
	}
	return tlsWorkerActionWrote, nil
}

func (worker *plainUringWorker) compactHTTP2ReadBuffer(conn *plainWorkerConn, force bool) {
	st := &conn.h2
	if st.appBufOff == 0 {
		return
	}
	if !force && st.appBufOff <= cap(conn.readBuf)/2 {
		return
	}
	remaining := conn.readN - st.appBufOff
	if remaining > 0 {
		copy(conn.readBuf, conn.readBuf[st.appBufOff:conn.readN])
	}
	conn.readN = remaining
	conn.readBuf = conn.readBuf[:remaining]
	st.appBufOff = 0
}
