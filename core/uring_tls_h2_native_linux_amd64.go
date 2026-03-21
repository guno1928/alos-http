//go:build linux && amd64

package core

import "log"

type tlsWorkerH2State struct {
	decoder           *HpackDecoder
	streams           map[uint32]*H2Stream
	initialWindowSize uint32
	maxFrameSize      uint32
	connWindow        int64
	recvConnWindow    int64
	pendingConnWindow uint32
	lastStreamID      uint32

	prefaceReceived   bool
	expectContinuation uint32
	headerEndStream   bool
	appBufOff         int
	headerAccum       []byte
	headersBuf        [][2]string
}

func (st *tlsWorkerH2State) init() {
	if st.decoder == nil {
		st.decoder = NewHpackDecoder()
	} else {
		*st.decoder = HpackDecoder{
			maxTableSize:    H2HeaderTableSize,
			protocolMaxSize: H2HeaderTableSize,
		}
	}
	if st.streams == nil {
		st.streams = make(map[uint32]*H2Stream, 4)
	} else {
		for id, stream := range st.streams {
			stream.Reset()
			StreamPool.Put(stream)
			delete(st.streams, id)
		}
	}
	st.initialWindowSize = H2DefaultWindowSize
	st.maxFrameSize = H2DefaultMaxFrameSize
	st.connWindow = int64(H2DefaultWindowSize)
	st.recvConnWindow = int64(H2ConnectionWindowSize)
	st.pendingConnWindow = 0
	st.lastStreamID = 0
	st.prefaceReceived = false
	st.expectContinuation = 0
	st.headerEndStream = false
	st.appBufOff = 0
	st.headerAccum = st.headerAccum[:0]
	st.headersBuf = st.headersBuf[:0]
}

func (st *tlsWorkerH2State) reset() {
	if st.streams != nil {
		for id, stream := range st.streams {
			stream.Reset()
			StreamPool.Put(stream)
			delete(st.streams, id)
		}
	}
	if st.decoder != nil {
		*st.decoder = HpackDecoder{
			maxTableSize:    H2HeaderTableSize,
			protocolMaxSize: H2HeaderTableSize,
		}
	}
	st.initialWindowSize = 0
	st.maxFrameSize = 0
	st.connWindow = 0
	st.recvConnWindow = 0
	st.pendingConnWindow = 0
	st.lastStreamID = 0
	st.prefaceReceived = false
	st.expectContinuation = 0
	st.headerEndStream = false
	st.appBufOff = 0
	st.headerAccum = st.headerAccum[:0]
	st.headersBuf = st.headersBuf[:0]
}

func (worker *tlsUringWorker) initHTTP2(conn *tlsWorkerConn) (int, error) {
	conn.h2.init()
	conn.phase = tlsConnPhaseH2Native
	Stats.H2Conns.Add(1)
	if ok := worker.primeHTTP2FromBufferedCipher(conn); !ok {
		return tlsWorkerActionClose, nil
	}
	action, err := worker.processHTTP2Frames(conn)
	if err != nil {
		return action, err
	}
	if action == tlsWorkerActionContinue {
		return tlsWorkerActionNeedRead, nil
	}
	return action, nil
}

func appendH2ServerSettingsFlight(dst []byte) []byte {
	settings := [5][2]uint32{
		{uint32(H2SettingHeaderTableSize), 0},
		{uint32(H2SettingMaxConcurrentStreams), H2MaxConcurrentStream},
		{uint32(H2SettingInitialWindowSize), H2StreamWindowSize},
		{uint32(H2SettingMaxFrameSize), H2DefaultMaxFrameSize},
		{uint32(H2SettingMaxHeaderListSize), H2MaxHeaderListSize},
	}
	settingsFrame := H2WriteSettings(nil, settings[:])
	dst = append(dst, settingsFrame...)
	windowFrame := H2WriteWindowUpdate(nil, 0, uint32(H2ConnectionWindowSize-H2DefaultWindowSize))
	dst = append(dst, windowFrame...)
	return dst
}

func (worker *tlsUringWorker) processHTTP2(conn *tlsWorkerConn) (int, error) {
	for {
		if action, err := worker.processHTTP2Frames(conn); action != tlsWorkerActionContinue || err != nil {
			return action, err
		}
		ct, payload, totalLen, ok, err := nextTLSRecord(conn.readBuf[:conn.readN])
		if err != nil {
			return tlsWorkerActionClose, nil
		}
		if !ok {
			return tlsWorkerActionNeedRead, nil
		}
		worker.compactCipherBuffer(conn, totalLen)
		switch ct {
		case 0x14:
			continue
		case 0x15:
			return tlsWorkerActionClose, nil
		case 0x17:
			pt, err := conn.appReader.Decrypt(payload)
			if err != nil {
				return tlsWorkerActionClose, nil
			}
			appContent, appCT, err := StripInnerPlaintext(pt)
			if err != nil {
				return tlsWorkerActionClose, nil
			}
			switch appCT {
			case 0x15:
				return tlsWorkerActionClose, nil
			case 0x17:
				if !worker.appendHTTP2AppData(conn, appContent) {
					return tlsWorkerActionClose, nil
				}
			default:
			}
		default:
		}
	}
}

func (worker *tlsUringWorker) processHTTP2Frames(conn *tlsWorkerConn) (int, error) {
	st := &conn.h2
	if !st.prefaceReceived {
		avail := len(conn.appBuf) - st.appBufOff
		if avail < H2PrefaceLen {
			return worker.flushHTTP2Frames(conn, false)
		}
		for i := 0; i < H2PrefaceLen; i++ {
			if conn.appBuf[st.appBufOff+i] != H2ClientPreface[i] {
				conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf[:0], st.lastStreamID, H2ErrProtocol)
				return worker.flushHTTP2Frames(conn, true)
			}
		}
		st.prefaceReceived = true
		st.appBufOff += H2PrefaceLen
	}

	for {
		avail := len(conn.appBuf) - st.appBufOff
		if avail < 9 {
			worker.compactHTTP2AppBuffer(conn, false)
			return worker.flushHTTP2Frames(conn, false)
		}
		base := st.appBufOff
		frameLen := int(conn.appBuf[base])<<16 | int(conn.appBuf[base+1])<<8 | int(conn.appBuf[base+2])
		if frameLen > int(H2MaxFrameSize) {
			conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf[:0], st.lastStreamID, H2ErrFrameSize)
			return worker.flushHTTP2Frames(conn, true)
		}
		totalLen := 9 + frameLen
		if avail < totalLen {
			worker.compactHTTP2AppBuffer(conn, false)
			return worker.flushHTTP2Frames(conn, false)
		}
		frameType := conn.appBuf[base+3]
		frameFlags := conn.appBuf[base+4]
		streamID := (uint32(conn.appBuf[base+5])<<24 | uint32(conn.appBuf[base+6])<<16 | uint32(conn.appBuf[base+7])<<8 | uint32(conn.appBuf[base+8])) & 0x7fffffff
		payload := conn.appBuf[base+9 : base+totalLen]

		if st.expectContinuation != 0 {
			if frameType != H2FrameContinuation || streamID != st.expectContinuation {
				conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf[:0], st.lastStreamID, H2ErrProtocol)
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

func (worker *tlsUringWorker) handleHTTP2Frame(conn *tlsWorkerConn, frameType, frameFlags byte, streamID uint32, payload []byte) (int, bool) {
	st := &conn.h2
	switch frameType {
	case H2FrameSettings:
		if streamID != 0 {
			conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrProtocol)
			return tlsWorkerActionWrote, true
		}
		if frameFlags&H2FlagAck != 0 {
			if len(payload) > 0 {
				conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrFrameSize)
				return tlsWorkerActionWrote, true
			}
			return tlsWorkerActionContinue, false
		}
		if len(payload)%6 != 0 {
			conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrFrameSize)
			return tlsWorkerActionWrote, true
		}
		if !worker.processHTTP2Settings(conn, payload) {
			return tlsWorkerActionWrote, true
		}
		conn.plainBuf = appendH2SettingsAckFrame(conn.plainBuf)
		return tlsWorkerActionContinue, false
	case H2FrameHeaders:
		return worker.handleHTTP2Headers(conn, streamID, frameFlags, payload)
	case H2FrameContinuation:
		conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrProtocol)
		return tlsWorkerActionWrote, true
	case H2FrameData:
		return worker.handleHTTP2Data(conn, streamID, frameFlags, payload)
	case H2FrameWindowUpdate:
		return worker.handleHTTP2WindowUpdate(conn, streamID, payload)
	case H2FramePing:
		if streamID != 0 {
			conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrProtocol)
			return tlsWorkerActionWrote, true
		}
		if len(payload) != 8 {
			conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrFrameSize)
			return tlsWorkerActionWrote, true
		}
		if frameFlags&H2FlagAck == 0 {
			var pingData [8]byte
			copy(pingData[:], payload)
			conn.plainBuf = appendH2PingFrame(conn.plainBuf, true, pingData)
		}
		return tlsWorkerActionContinue, false
	case H2FrameRSTStream:
		if streamID == 0 || len(payload) != 4 {
			conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrProtocol)
			return tlsWorkerActionWrote, true
		}
		worker.releaseHTTP2Stream(st, streamID)
		return tlsWorkerActionContinue, false
	case H2FrameGoAway:
		return tlsWorkerActionClose, true
	case H2FramePriority:
		if streamID == 0 || len(payload) != 5 {
			conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrProtocol)
			return tlsWorkerActionWrote, true
		}
		return tlsWorkerActionContinue, false
	case H2FramePushPromise:
		conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrProtocol)
		return tlsWorkerActionWrote, true
	default:
		return tlsWorkerActionContinue, false
	}
}

func (worker *tlsUringWorker) processHTTP2Settings(conn *tlsWorkerConn, payload []byte) bool {
	st := &conn.h2
	for i := 0; i+6 <= len(payload); i += 6 {
		id := uint16(payload[i])<<8 | uint16(payload[i+1])
		val := uint32(payload[i+2])<<24 | uint32(payload[i+3])<<16 | uint32(payload[i+4])<<8 | uint32(payload[i+5])
		switch id {
		case H2SettingMaxFrameSize:
			if val < 16384 || val > uint32(H2MaxFrameSize) {
				conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrProtocol)
				return false
			}
			st.maxFrameSize = val
		case H2SettingInitialWindowSize:
			if val > 2147483647 {
				conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrFlowControl)
				return false
			}
			delta := int64(val) - int64(st.initialWindowSize)
			st.initialWindowSize = val
			for id, stream := range st.streams {
				newWindow := stream.Window.Load() + delta
				if newWindow > 2147483647 {
					conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, id, H2ErrFlowControl)
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

func (worker *tlsUringWorker) handleHTTP2Headers(conn *tlsWorkerConn, streamID uint32, frameFlags byte, payload []byte) (int, bool) {
	st := &conn.h2
	if streamID == 0 {
		conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrProtocol)
		return tlsWorkerActionWrote, true
	}
	if frameFlags&H2FlagPadded != 0 {
		if len(payload) == 0 {
			conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrProtocol)
			return tlsWorkerActionWrote, false
		}
		padLen := int(payload[0])
		payload = payload[1:]
		if padLen > len(payload) {
			conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrProtocol)
			return tlsWorkerActionWrote, false
		}
		payload = payload[:len(payload)-padLen]
	}
	if frameFlags&H2FlagPriority != 0 {
		if len(payload) < 5 {
			conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrFrameSize)
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

func (worker *tlsUringWorker) handleHTTP2Continuation(conn *tlsWorkerConn, streamID uint32, frameFlags byte, payload []byte) (int, bool) {
	st := &conn.h2
	st.headerAccum = append(st.headerAccum, payload...)
	if len(st.headerAccum) > H2MaxHeaderListSize*4 {
		st.expectContinuation = 0
		conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
		return tlsWorkerActionWrote, true
	}
	if frameFlags&H2FlagEndHeaders == 0 {
		return tlsWorkerActionContinue, false
	}
	endStream := st.headerEndStream
	st.expectContinuation = 0
	return worker.processHTTP2DecodedHeaders(conn, streamID, st.headerAccum, endStream)
}

func (worker *tlsUringWorker) processHTTP2DecodedHeaders(conn *tlsWorkerConn, streamID uint32, headerBlock []byte, endStream bool) (int, bool) {
	st := &conn.h2
	if streamID%2 == 0 || (st.lastStreamID > 0 && streamID <= st.lastStreamID) {
		conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrProtocol)
		return tlsWorkerActionWrote, true
	}

	headers, meta, err := st.decoder.DecodeIntoRequest(st.headersBuf[:0], headerBlock)
	st.headersBuf = headers[:0]
	if err != nil {
		conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrCompression)
		return tlsWorkerActionWrote, false
	}
	if endStream && worker.server.h2RootFast.enabled && meta.method == "GET" && meta.path == "/" {
		st.lastStreamID = streamID
		if worker.server.logRequests.Load() {
			log.Printf("[H2] stream %d: %s %s (native fast)", streamID, meta.method, meta.path)
		}
		Stats.TotalReqs.Add(1)
		if len(conn.plainBuf) == 0 && len(worker.server.h2RootFast.tlsInner) > 0 {
			conn.closeAfter = false
			conn.writeBuf = appendFastH2RootTLSRecord(conn.writeBuf[:0], conn.appWriter, worker.server.h2RootFast, streamID, &conn.innerScratch)
			conn.writeN = len(conn.writeBuf)
			conn.writeSent = 0
			if conn.writeN == 0 {
				return tlsWorkerActionClose, true
			}
			conn.state = tlsConnStateWriting
			if err := worker.ring.prepSendUserWithFlags(conn.fd, conn.writeBuf[:conn.writeN], tlsEncodeUserData(tlsUringOpWrite, int(conn.index), conn.generation), worker.shouldPollFirstSend()); err != nil {
				return tlsWorkerActionClose, true
			}
			return tlsWorkerActionWrote, false
		}
		conn.plainBuf = appendFastH2RootResponse(conn.plainBuf, worker.server.h2RootFast, streamID, int(st.maxFrameSize))
		return tlsWorkerActionWrote, false
	}
	if len(headers) > 128 {
		conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrEnhanceYourCalm)
		return tlsWorkerActionWrote, false
	}
	if len(st.streams) >= H2MaxConcurrentStream {
		conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrRefusedStream)
		return tlsWorkerActionWrote, false
	}
	if meta.method == "" || meta.path == "" {
		conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrProtocol)
		return tlsWorkerActionWrote, false
	}

	stream := StreamPool.Get().(*H2Stream)
	stream.Reset()
	stream.ID = streamID
	stream.Window.Store(int64(st.initialWindowSize))
	stream.Method = meta.method
	stream.Path = meta.path
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

func (worker *tlsUringWorker) handleHTTP2Data(conn *tlsWorkerConn, streamID uint32, frameFlags byte, payload []byte) (int, bool) {
	st := &conn.h2
	if streamID == 0 {
		conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrProtocol)
		return tlsWorkerActionWrote, true
	}
	stream := st.streams[streamID]
	if stream == nil {
		return tlsWorkerActionContinue, false
	}
	if stream.State.Load() >= StreamHalfClosed {
		conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrStreamClosed)
		return tlsWorkerActionWrote, false
	}

	if frameFlags&H2FlagPadded != 0 {
		if len(payload) == 0 {
			conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrProtocol)
			return tlsWorkerActionWrote, false
		}
		padLen := int(payload[0])
		payload = payload[1:]
		if padLen > len(payload) {
			conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrProtocol)
			return tlsWorkerActionWrote, false
		}
		payload = payload[:len(payload)-padLen]
	}

	consumed := int64(len(payload))
	st.recvConnWindow -= consumed
	if st.recvConnWindow < 0 {
		conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrFlowControl)
		return tlsWorkerActionWrote, true
	}

	stream.Body = append(stream.Body, payload...)
	if worker.server.config.MaxBodySize > 0 && int64(len(stream.Body)) > worker.server.config.MaxBodySize {
		conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrCancel)
		worker.releaseHTTP2Stream(st, streamID)
		return tlsWorkerActionWrote, false
	}

	consumedWindow := uint32(len(payload))
	st.pendingConnWindow += consumedWindow
	if st.pendingConnWindow > H2ConnectionWindowSize/2 {
		connUpdate := st.pendingConnWindow
		st.pendingConnWindow = 0
		st.recvConnWindow += int64(connUpdate)
		conn.plainBuf = appendH2WindowUpdateFrame(conn.plainBuf, 0, connUpdate)
	}
	conn.plainBuf = appendH2WindowUpdateFrame(conn.plainBuf, streamID, consumedWindow)

	if frameFlags&H2FlagEndStream == 0 {
		return tlsWorkerActionContinue, false
	}
	stream.State.Store(StreamHalfClosed)
	return worker.dispatchHTTP2Stream(conn, streamID)
}

func (worker *tlsUringWorker) handleHTTP2WindowUpdate(conn *tlsWorkerConn, streamID uint32, payload []byte) (int, bool) {
	st := &conn.h2
	if len(payload) != 4 {
		conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrFrameSize)
		return tlsWorkerActionWrote, true
	}
	increment := (uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])) & 0x7fffffff
	if increment == 0 {
		if streamID == 0 {
			conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrProtocol)
			return tlsWorkerActionWrote, true
		}
		conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrProtocol)
		return tlsWorkerActionWrote, false
	}
	if streamID == 0 {
		st.connWindow += int64(increment)
		if st.connWindow > 2147483647 {
			conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrFlowControl)
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
		conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrFlowControl)
		worker.releaseHTTP2Stream(st, streamID)
		return tlsWorkerActionWrote, false
	}
	stream.Window.Store(newWindow)
	return tlsWorkerActionContinue, false
}

func (worker *tlsUringWorker) dispatchHTTP2Stream(conn *tlsWorkerConn, streamID uint32) (int, bool) {
	st := &conn.h2
	stream := st.streams[streamID]
	if stream == nil {
		return tlsWorkerActionContinue, false
	}

	Stats.TotalReqs.Add(1)
	if worker.server.logRequests.Load() {
		log.Printf("[H2] stream %d: %s %s (native)", stream.ID, stream.Method, stream.Path)
	}

	conn.req.Reset()
	conn.req.Method = stream.Method
	conn.req.Path = stream.Path
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
		conn.resp.Status(500).String("Streaming/Hijack unsupported in native TLS io_uring HTTP/2 backend")
	}
	if worker.server.config.MaxWriteSize > 0 && int64(conn.resp.BodyLen()) > worker.server.config.MaxWriteSize {
		conn.resp.Reset()
		conn.resp.Status(500).String("Response Too Large")
	}

	conn.plainBuf = appendH2ResponseFrames(conn.plainBuf, streamID, &conn.resp, st.maxFrameSize)
	bodyLen := int64(conn.resp.BodyLen())
	if bodyLen > 0 {
		streamWindow := stream.Window.Load()
		if bodyLen > st.connWindow || bodyLen > streamWindow {
			conn.resp.Reset()
			conn.resp.Status(500).String("HTTP/2 flow control window exhausted")
			conn.plainBuf = appendH2ResponseFrames(conn.plainBuf[:0], streamID, &conn.resp, st.maxFrameSize)
		} else {
			st.connWindow -= bodyLen
			stream.Window.Add(-bodyLen)
		}
	}
	worker.releaseHTTP2Stream(st, streamID)
	return tlsWorkerActionWrote, false
}

func (worker *tlsUringWorker) releaseHTTP2Stream(st *tlsWorkerH2State, streamID uint32) {
	stream := st.streams[streamID]
	if stream == nil {
		return
	}
	delete(st.streams, streamID)
	stream.Reset()
	StreamPool.Put(stream)
}

func (worker *tlsUringWorker) flushHTTP2Frames(conn *tlsWorkerConn, closeAfter bool) (int, error) {
	if len(conn.plainBuf) == 0 {
		if closeAfter {
			return tlsWorkerActionClose, nil
		}
		return tlsWorkerActionContinue, nil
	}
	return worker.queueH2Frames(conn, closeAfter)
}

func (worker *tlsUringWorker) queueH2Frames(conn *tlsWorkerConn, closeAfter bool) (int, error) {
	conn.closeAfter = closeAfter
	conn.writeBuf = buildTLSAppDataRecords(conn.writeBuf[:0], conn.appWriter, conn.plainBuf, &conn.innerScratch)
	conn.plainBuf = conn.plainBuf[:0]
	conn.writeN = len(conn.writeBuf)
	conn.writeSent = 0
	if conn.writeN == 0 {
		if closeAfter {
			return tlsWorkerActionClose, nil
		}
		return tlsWorkerActionContinue, nil
	}
	conn.state = tlsConnStateWriting
	if err := worker.ring.prepSendUserWithFlags(conn.fd, conn.writeBuf[:conn.writeN], tlsEncodeUserData(tlsUringOpWrite, int(conn.index), conn.generation), worker.shouldPollFirstSend()); err != nil {
		return tlsWorkerActionClose, nil
	}
	return tlsWorkerActionWrote, nil
}

func (worker *tlsUringWorker) primeHTTP2FromBufferedCipher(conn *tlsWorkerConn) bool {
	for {
		ct, payload, totalLen, ok, err := nextTLSRecord(conn.readBuf[:conn.readN])
		if err != nil {
			return false
		}
		if !ok {
			return true
		}
		worker.compactCipherBuffer(conn, totalLen)
		switch ct {
		case 0x14:
			continue
		case 0x15:
			return false
		case 0x17:
			pt, err := conn.appReader.Decrypt(payload)
			if err != nil {
				return false
			}
			appContent, appCT, err := StripInnerPlaintext(pt)
			if err != nil {
				return false
			}
			switch appCT {
			case 0x15:
				return false
			case 0x17:
				if !worker.appendHTTP2AppData(conn, appContent) {
					return false
				}
			}
		}
	}
}

func (worker *tlsUringWorker) appendHTTP2AppData(conn *tlsWorkerConn, appContent []byte) bool {
	maxRead := int(defaultInt64(worker.server.config.MaxReadSize, 2<<20))
	worker.compactHTTP2AppBuffer(conn, false)
	if !worker.ensureAppCapacity(conn, len(appContent), maxRead) {
		worker.compactHTTP2AppBuffer(conn, true)
		if !worker.ensureAppCapacity(conn, len(appContent), maxRead) {
			return false
		}
	}
	conn.appBuf = append(conn.appBuf, appContent...)
	return true
}

func (worker *tlsUringWorker) compactHTTP2AppBuffer(conn *tlsWorkerConn, force bool) {
	st := &conn.h2
	if st.appBufOff == 0 {
		return
	}
	if !force && st.appBufOff <= cap(conn.appBuf)/2 {
		return
	}
	remaining := len(conn.appBuf) - st.appBufOff
	if remaining > 0 {
		copy(conn.appBuf, conn.appBuf[st.appBufOff:])
	}
	conn.appBuf = conn.appBuf[:remaining]
	st.appBufOff = 0
}

func appendFastH2RootResponse(dst []byte, fast h2RootFastResponse, streamID uint32, maxFrame int) []byte {
	off := len(dst)
	if len(fast.framed) > 0 {
		dst = append(dst, fast.framed...)
		dst[off+5] = byte(streamID >> 24)
		dst[off+6] = byte(streamID >> 16)
		dst[off+7] = byte(streamID >> 8)
		dst[off+8] = byte(streamID)
		if fast.dataFrameOff >= 0 {
			dataOff := off + fast.dataFrameOff
			dst[dataOff+5] = byte(streamID >> 24)
			dst[dataOff+6] = byte(streamID >> 16)
			dst[dataOff+7] = byte(streamID >> 8)
			dst[dataOff+8] = byte(streamID)
		}
		return dst
	}
	if len(fast.body) == 0 {
		return appendH2Frame(dst, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, streamID, fast.headerPayload)
	}
	dst = appendH2Frame(dst, H2FrameHeaders, H2FlagEndHeaders, streamID, fast.headerPayload)
	remaining := fast.body
	for len(remaining) > 0 {
		chunk := remaining
		if len(chunk) > maxFrame {
			chunk = chunk[:maxFrame]
		}
		flags := byte(0)
		if len(chunk) == len(remaining) {
			flags = H2FlagEndStream
		}
		dst = appendH2Frame(dst, H2FrameData, flags, streamID, chunk)
		remaining = remaining[len(chunk):]
	}
	return dst
}

func appendFastH2RootTLSRecord(dst []byte, writer *TrafficAEAD, fast h2RootFastResponse, streamID uint32, scratch *[]byte) []byte {
	if len(fast.tlsInner) == 0 || writer == nil {
		return dst
	}
	if cap(*scratch) < len(fast.tlsInner) {
		*scratch = make([]byte, len(fast.tlsInner))
	}
	inner := (*scratch)[:len(fast.tlsInner)]
	copy(inner, fast.tlsInner)
	inner[fast.headerIDOff] = byte(streamID >> 24)
	inner[fast.headerIDOff+1] = byte(streamID >> 16)
	inner[fast.headerIDOff+2] = byte(streamID >> 8)
	inner[fast.headerIDOff+3] = byte(streamID)
	if fast.dataIDOff >= 0 {
		inner[fast.dataIDOff] = byte(streamID >> 24)
		inner[fast.dataIDOff+1] = byte(streamID >> 16)
		inner[fast.dataIDOff+2] = byte(streamID >> 8)
		inner[fast.dataIDOff+3] = byte(streamID)
	}
	return appendTLSInnerRecord(dst, writer, inner)
}

func appendH2ResponseFrames(dst []byte, streamID uint32, resp *Response, maxFrame uint32) []byte {
	bp := MediumBufPool.Get().(*[]byte)
	enc := HpackEncoder{}
	enc.Reset((*bp)[:0])
	enc.EncodeStatus(resp.StatusCode)
	if resp.ContentType != "" {
		enc.EncodeHeader("content-type", resp.ContentType)
	}
	var clBuf [20]byte
	clStr := appendUint(clBuf[:0], int64(resp.BodyLen()))
	enc.EncodeHeader("content-length", UnsafeString(clStr))
	for i := range resp.Headers {
		enc.EncodeHeader(resp.Headers[i][0], resp.Headers[i][1])
	}
	enc.EncodeHeader("server", "ALOS")

	body := resp.bodyBytesUnsafe()
	if len(body) == 0 {
		dst = appendH2Frame(dst, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, streamID, enc.Buf)
		*bp = enc.Buf[:0]
		MediumBufPool.Put(bp)
		return dst
	}

	frameLimit := int(maxFrame)
	if frameLimit <= 0 {
		frameLimit = H2DefaultMaxFrameSize
	}
	dst = appendH2Frame(dst, H2FrameHeaders, H2FlagEndHeaders, streamID, enc.Buf)
	remaining := body
	for len(remaining) > 0 {
		chunk := remaining
		if len(chunk) > frameLimit {
			chunk = chunk[:frameLimit]
		}
		flags := byte(0)
		if len(chunk) == len(remaining) {
			flags = H2FlagEndStream
		}
		dst = appendH2Frame(dst, H2FrameData, flags, streamID, chunk)
		remaining = remaining[len(chunk):]
	}
	*bp = enc.Buf[:0]
	MediumBufPool.Put(bp)
	return dst
}

func appendH2SettingsAckFrame(dst []byte) []byte {
	return appendH2Frame(dst, H2FrameSettings, H2FlagAck, 0, nil)
}

func appendH2WindowUpdateFrame(dst []byte, streamID, increment uint32) []byte {
	var payload [4]byte
	v := increment & 0x7fffffff
	payload[0] = byte(v >> 24)
	payload[1] = byte(v >> 16)
	payload[2] = byte(v >> 8)
	payload[3] = byte(v)
	return appendH2Frame(dst, H2FrameWindowUpdate, 0, streamID, payload[:])
}

func appendH2GoAwayFrame(dst []byte, lastStream, errCode uint32) []byte {
	var payload [8]byte
	payload[0] = byte(lastStream >> 24)
	payload[1] = byte(lastStream >> 16)
	payload[2] = byte(lastStream >> 8)
	payload[3] = byte(lastStream)
	payload[4] = byte(errCode >> 24)
	payload[5] = byte(errCode >> 16)
	payload[6] = byte(errCode >> 8)
	payload[7] = byte(errCode)
	return appendH2Frame(dst, H2FrameGoAway, 0, 0, payload[:])
}

func appendH2RSTStreamFrame(dst []byte, streamID, errCode uint32) []byte {
	var payload [4]byte
	payload[0] = byte(errCode >> 24)
	payload[1] = byte(errCode >> 16)
	payload[2] = byte(errCode >> 8)
	payload[3] = byte(errCode)
	return appendH2Frame(dst, H2FrameRSTStream, 0, streamID, payload[:])
}

func appendH2PingFrame(dst []byte, ack bool, data [8]byte) []byte {
	flags := byte(0)
	if ack {
		flags = H2FlagAck
	}
	return appendH2Frame(dst, H2FramePing, flags, 0, data[:])
}
