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

	prefaceReceived    bool
	expectContinuation uint32
	headerEndStream    bool
	appBufOff          int
	headerAccum        []byte
	headersBuf         [][2]string
}

func h2FrameTypeName(frameType byte) string {
	switch frameType {
	case H2FrameData:
		return "DATA"
	case H2FrameHeaders:
		return "HEADERS"
	case H2FramePriority:
		return "PRIORITY"
	case H2FrameRSTStream:
		return "RST_STREAM"
	case H2FrameSettings:
		return "SETTINGS"
	case H2FramePushPromise:
		return "PUSH_PROMISE"
	case H2FramePing:
		return "PING"
	case H2FrameGoAway:
		return "GOAWAY"
	case H2FrameWindowUpdate:
		return "WINDOW_UPDATE"
	case H2FrameContinuation:
		return "CONTINUATION"
	default:
		return "UNKNOWN"
	}
}

func h2SettingName(id uint16) string {
	switch id {
	case H2SettingHeaderTableSize:
		return "HEADER_TABLE_SIZE"
	case H2SettingEnablePush:
		return "ENABLE_PUSH"
	case H2SettingMaxConcurrentStreams:
		return "MAX_CONCURRENT_STREAMS"
	case H2SettingInitialWindowSize:
		return "INITIAL_WINDOW_SIZE"
	case H2SettingMaxFrameSize:
		return "MAX_FRAME_SIZE"
	case H2SettingMaxHeaderListSize:
		return "MAX_HEADER_LIST_SIZE"
	default:
		return "UNKNOWN"
	}
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
	conn.plainBuf = appendH2ServerSettingsFlight(conn.plainBuf[:0])
	if worker.server.IsDebug() {
		Dbg("[%s] worker init native HTTP/2 readN=%d appBuf=%d settings-bytes=%d", conn.remoteAddr, conn.readN, len(conn.appBuf), len(conn.plainBuf))
	}
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
			if worker.server.IsDebug() {
				Dbg("[%s] worker HTTP/2 nextTLSRecord error: %v", conn.remoteAddr, err)
			}
			return tlsWorkerActionClose, nil
		}
		if !ok {
			if worker.server.IsDebug() {
				Dbg("[%s] worker HTTP/2 awaiting more cipher bytes readN=%d appBuf=%d", conn.remoteAddr, conn.readN, len(conn.appBuf)-conn.h2.appBufOff)
			}
			return tlsWorkerActionNeedRead, nil
		}
		remainingRead := conn.readN - totalLen
		if worker.server.IsDebug() {
			Dbg("[%s] worker HTTP/2 tls record ct=0x%02x payload=%d remaining-read=%d", conn.remoteAddr, ct, len(payload), remainingRead)
		}
		switch ct {
		case 0x14:
			worker.compactCipherBuffer(conn, totalLen)
			continue
		case 0x15:
			if worker.server.IsDebug() {
				Dbg("[%s] worker HTTP/2 received alert record", conn.remoteAddr)
			}
			return tlsWorkerActionClose, nil
		case 0x17:
			pt, err := conn.appReader.Decrypt(payload)
			if err != nil {
				if worker.server.IsDebug() {
					Dbg("[%s] worker HTTP/2 decrypt failed: %v", conn.remoteAddr, err)
				}
				return tlsWorkerActionClose, nil
			}
			appContent, appCT, err := StripInnerPlaintext(pt)
			if err != nil {
				if worker.server.IsDebug() {
					Dbg("[%s] worker HTTP/2 strip inner plaintext failed: %v", conn.remoteAddr, err)
				}
				return tlsWorkerActionClose, nil
			}
			if worker.server.IsDebug() {
				Dbg("[%s] worker HTTP/2 inner content type=0x%02x len=%d", conn.remoteAddr, appCT, len(appContent))
			}
			switch appCT {
			case 0x15:
				return tlsWorkerActionClose, nil
			case 0x17:
				if !worker.appendHTTP2AppData(conn, appContent) {
					return tlsWorkerActionClose, nil
				}
				worker.compactCipherBuffer(conn, totalLen)
			default:
				worker.compactCipherBuffer(conn, totalLen)
			}
		default:
			worker.compactCipherBuffer(conn, totalLen)
		}
	}
}

func (worker *tlsUringWorker) processHTTP2Frames(conn *tlsWorkerConn) (int, error) {
	st := &conn.h2
	if !st.prefaceReceived {
		avail := len(conn.appBuf) - st.appBufOff
		if avail < H2PrefaceLen {
			if worker.server.IsDebug() {
				Dbg("[%s] worker HTTP/2 waiting for client preface have=%d need=%d", conn.remoteAddr, avail, H2PrefaceLen)
			}
			return worker.flushHTTP2Frames(conn, false)
		}
		for i := 0; i < H2PrefaceLen; i++ {
			if conn.appBuf[st.appBufOff+i] != H2ClientPreface[i] {
				if worker.server.IsDebug() {
					Dbg("[%s] worker HTTP/2 invalid client preface", conn.remoteAddr)
				}
				conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf[:0], st.lastStreamID, H2ErrProtocol)
				return worker.flushHTTP2Frames(conn, true)
			}
		}
		st.prefaceReceived = true
		st.appBufOff += H2PrefaceLen
		if worker.server.IsDebug() {
			Dbg("[%s] worker HTTP/2 client preface received", conn.remoteAddr)
		}
	}

	for {
		avail := len(conn.appBuf) - st.appBufOff
		if avail < 9 {
			if worker.server.IsDebug() {
				Dbg("[%s] worker HTTP/2 awaiting more frame header bytes avail=%d queued=%d", conn.remoteAddr, avail, len(conn.plainBuf))
			}
			worker.compactHTTP2AppBuffer(conn, false)
			return worker.flushHTTP2Frames(conn, false)
		}
		base := st.appBufOff
		frameLen := int(conn.appBuf[base])<<16 | int(conn.appBuf[base+1])<<8 | int(conn.appBuf[base+2])
		frameType := conn.appBuf[base+3]
		frameFlags := conn.appBuf[base+4]
		streamID := (uint32(conn.appBuf[base+5])<<24 | uint32(conn.appBuf[base+6])<<16 | uint32(conn.appBuf[base+7])<<8 | uint32(conn.appBuf[base+8])) & 0x7fffffff
		// RFC 9113 §4.2: enforce the SETTINGS_MAX_FRAME_SIZE we advertise
		// (H2DefaultMaxFrameSize), not the 24-bit protocol ceiling.
		if frameLen > int(H2DefaultMaxFrameSize) {
			if worker.server.IsDebug() {
				Dbg("[%s] worker HTTP/2 frame too large len=%d", conn.remoteAddr, frameLen)
			}
			conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf[:0], st.lastStreamID, H2ErrFrameSize)
			return worker.flushHTTP2Frames(conn, true)
		}
		totalLen := 9 + frameLen
		if avail < totalLen {
			if worker.server.IsDebug() {
				Dbg("[%s] worker HTTP/2 partial frame type=%s len=%d have=%d", conn.remoteAddr, h2FrameTypeName(frameType), frameLen, avail)
			}
			worker.compactHTTP2AppBuffer(conn, false)
			return worker.flushHTTP2Frames(conn, false)
		}
		payload := conn.appBuf[base+9 : base+totalLen]
		if worker.server.IsDebug() {
			Dbg("[%s] worker HTTP/2 frame type=%s(0x%02x) flags=0x%02x stream=%d len=%d queued=%d", conn.remoteAddr, h2FrameTypeName(frameType), frameType, frameFlags, streamID, len(payload), len(conn.plainBuf))
		}

		if st.expectContinuation != 0 {
			if frameType != H2FrameContinuation || streamID != st.expectContinuation {
				if worker.server.IsDebug() {
					Dbg("[%s] worker HTTP/2 expected CONTINUATION for stream=%d got type=%s stream=%d", conn.remoteAddr, st.expectContinuation, h2FrameTypeName(frameType), streamID)
				}
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
		if worker.server.IsDebug() {
			Dbg("[%s] worker HTTP/2 setting %s(%d)=%d", conn.remoteAddr, h2SettingName(id), id, val)
		}
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
	if worker.server.IsDebug() {
		Dbg("[%s] worker HTTP/2 HEADERS stream=%d flags=0x%02x len=%d", conn.remoteAddr, streamID, frameFlags, len(payload))
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
		if worker.server.IsDebug() {
			Dbg("[%s] worker HTTP/2 HEADERS awaiting CONTINUATION stream=%d len=%d endStream=%v", conn.remoteAddr, streamID, len(st.headerAccum), st.headerEndStream)
		}
		return tlsWorkerActionContinue, false
	}
	return worker.processHTTP2DecodedHeaders(conn, streamID, payload, frameFlags&H2FlagEndStream != 0)
}

func (worker *tlsUringWorker) handleHTTP2Continuation(conn *tlsWorkerConn, streamID uint32, frameFlags byte, payload []byte) (int, bool) {
	st := &conn.h2
	st.headerAccum = append(st.headerAccum, payload...)
	if worker.server.IsDebug() {
		Dbg("[%s] worker HTTP/2 CONTINUATION stream=%d flags=0x%02x total-header-bytes=%d", conn.remoteAddr, streamID, frameFlags, len(st.headerAccum))
	}
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

	if endStream && worker.server.h2RootFast.enabled && matchIndexedH2FastRootHeaderBlock(headerBlock) {
		if worker.server.tryAcquireRequestSlot() {
			st.lastStreamID = streamID
			if worker.server.logRequests.Load() {
				log.Printf("[H2] stream %d: GET / (native fast)", streamID)
			}
			Stats.TotalReqs.Add(1)
			if len(conn.plainBuf) == 0 && len(worker.server.h2RootFast.tlsInner) > 0 && !tlsHTTP2WriteInFlight(conn) {
				conn.closeAfter = false
				conn.writeBuf = appendFastH2RootTLSRecord(conn.writeBuf[:0], conn.appWriter, worker.server.h2RootFast, streamID, &conn.innerScratch)
				conn.writeN = len(conn.writeBuf)
				conn.writeSent = 0
				if conn.writeN == 0 {
					worker.server.releaseRequestSlot()
					return tlsWorkerActionClose, true
				}
				conn.state = tlsConnStateWriting
				if err := worker.ring.prepSendUserWithFlags(conn.fd, conn.writeBuf[:conn.writeN], tlsEncodeUserData(tlsUringOpWrite, int(conn.index), conn.generation), worker.shouldPollFirstSend()); err != nil {
					worker.server.releaseRequestSlot()
					return tlsWorkerActionClose, true
				}
				worker.server.releaseRequestSlot()
				return tlsWorkerActionWrote, false
			}
			conn.plainBuf = appendFastH2RootResponse(conn.plainBuf, worker.server.h2RootFast, streamID, int(st.maxFrameSize))
			worker.server.releaseRequestSlot()
			return tlsWorkerActionWrote, false
		}
	}

	if endStream && worker.server.h2RootFast.enabled {
		meta, ok, err := st.decoder.DecodeFastRootRequest(headerBlock)
		if err != nil {
			if worker.server.IsDebug() {
				Dbg("[%s] worker HTTP/2 meta decode failed stream=%d err=%v", conn.remoteAddr, streamID, err)
			}
			conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrCompression)
			return tlsWorkerActionWrote, false
		}
		if ok {
			if worker.server.tryAcquireRequestSlot() {
				st.lastStreamID = streamID
				if worker.server.logRequests.Load() {
					log.Printf("[H2] stream %d: %s %s (native fast meta)", streamID, meta.method, meta.path)
				}
				Stats.TotalReqs.Add(1)
				if len(conn.plainBuf) == 0 && len(worker.server.h2RootFast.tlsInner) > 0 && !tlsHTTP2WriteInFlight(conn) {
					conn.closeAfter = false
					conn.writeBuf = appendFastH2RootTLSRecord(conn.writeBuf[:0], conn.appWriter, worker.server.h2RootFast, streamID, &conn.innerScratch)
					conn.writeN = len(conn.writeBuf)
					conn.writeSent = 0
					if conn.writeN == 0 {
						worker.server.releaseRequestSlot()
						return tlsWorkerActionClose, true
					}
					conn.state = tlsConnStateWriting
					if err := worker.ring.prepSendUserWithFlags(conn.fd, conn.writeBuf[:conn.writeN], tlsEncodeUserData(tlsUringOpWrite, int(conn.index), conn.generation), worker.shouldPollFirstSend()); err != nil {
						worker.server.releaseRequestSlot()
						return tlsWorkerActionClose, true
					}
					worker.server.releaseRequestSlot()
					return tlsWorkerActionWrote, false
				}
				conn.plainBuf = appendFastH2RootResponse(conn.plainBuf, worker.server.h2RootFast, streamID, int(st.maxFrameSize))
				worker.server.releaseRequestSlot()
				return tlsWorkerActionWrote, false
			}
		}
	}

	headers, meta, err := st.decoder.DecodeIntoRequest(st.headersBuf[:0], headerBlock)
	st.headersBuf = headers[:0]
	if err != nil {
		if worker.server.IsDebug() {
			Dbg("[%s] worker HTTP/2 header decode failed stream=%d err=%v", conn.remoteAddr, streamID, err)
		}
		conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrCompression)
		return tlsWorkerActionWrote, false
	}
	if worker.server.IsDebug() {
		Dbg("[%s] worker HTTP/2 decoded headers stream=%d method=%q path=%q authority=%q headers=%d endStream=%v", conn.remoteAddr, streamID, meta.method, meta.path, meta.authority, len(headers), endStream)
	}
	if endStream && worker.server.h2RootFast.enabled && meta.method == "GET" && meta.path == "/" {
		if worker.server.tryAcquireRequestSlot() {
			st.lastStreamID = streamID
			if worker.server.logRequests.Load() {
				log.Printf("[H2] stream %d: %s %s (native fast)", streamID, meta.method, meta.path)
			}
			Stats.TotalReqs.Add(1)
			if len(conn.plainBuf) == 0 && len(worker.server.h2RootFast.tlsInner) > 0 && !tlsHTTP2WriteInFlight(conn) {
				conn.closeAfter = false
				conn.writeBuf = appendFastH2RootTLSRecord(conn.writeBuf[:0], conn.appWriter, worker.server.h2RootFast, streamID, &conn.innerScratch)
				conn.writeN = len(conn.writeBuf)
				conn.writeSent = 0
				if conn.writeN == 0 {
					worker.server.releaseRequestSlot()
					return tlsWorkerActionClose, true
				}
				conn.state = tlsConnStateWriting
				if err := worker.ring.prepSendUserWithFlags(conn.fd, conn.writeBuf[:conn.writeN], tlsEncodeUserData(tlsUringOpWrite, int(conn.index), conn.generation), worker.shouldPollFirstSend()); err != nil {
					worker.server.releaseRequestSlot()
					return tlsWorkerActionClose, true
				}
				worker.server.releaseRequestSlot()
				return tlsWorkerActionWrote, false
			}
			conn.plainBuf = appendFastH2RootResponse(conn.plainBuf, worker.server.h2RootFast, streamID, int(st.maxFrameSize))
			worker.server.releaseRequestSlot()
			return tlsWorkerActionWrote, false
		}
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

func tlsHTTP2WriteInFlight(conn *tlsWorkerConn) bool {
	return conn.state == tlsConnStateWriting || conn.writeSent < conn.writeN
}

func (worker *tlsUringWorker) handleHTTP2Data(conn *tlsWorkerConn, streamID uint32, frameFlags byte, payload []byte) (int, bool) {
	st := &conn.h2
	if streamID == 0 {
		conn.plainBuf = appendH2GoAwayFrame(conn.plainBuf, st.lastStreamID, H2ErrProtocol)
		return tlsWorkerActionWrote, true
	}
	stream := st.streams[streamID]
	if stream == nil {
		if worker.server.IsDebug() {
			Dbg("[%s] worker HTTP/2 DATA for unknown stream=%d len=%d", conn.remoteAddr, streamID, len(payload))
		}
		return tlsWorkerActionContinue, false
	}
	if worker.server.IsDebug() {
		Dbg("[%s] worker HTTP/2 DATA stream=%d flags=0x%02x len=%d", conn.remoteAddr, streamID, frameFlags, len(payload))
	}
	if stream.State.Load() >= StreamHalfClosed {
		conn.plainBuf = appendH2RSTStreamFrame(conn.plainBuf, streamID, H2ErrStreamClosed)
		return tlsWorkerActionWrote, false
	}

	frameConsumed := len(payload)
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

	consumed := int64(frameConsumed)
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

	consumedWindow := uint32(frameConsumed)
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
		if worker.server.IsDebug() {
			Dbg("[%s] worker HTTP/2 WINDOW_UPDATE conn +%d -> %d", conn.remoteAddr, increment, st.connWindow)
		}
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
	if worker.server.IsDebug() {
		Dbg("[%s] worker HTTP/2 WINDOW_UPDATE stream=%d +%d -> %d", conn.remoteAddr, streamID, increment, newWindow)
	}
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
	if worker.server.IsDebug() {
		Dbg("[%s] worker HTTP/2 dispatch stream=%d method=%s path=%s hdrs=%d body=%d connWindow=%d streamWindow=%d", conn.remoteAddr, stream.ID, stream.Method, stream.Path, len(stream.Headers), len(stream.Body), st.connWindow, stream.Window.Load())
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
	if worker.server.IsDebug() {
		Dbg("[%s] worker HTTP/2 response stream=%d status=%d body=%d headers=%d streamed=%v hijacked=%v", conn.remoteAddr, stream.ID, conn.resp.StatusCode, conn.resp.BodyLen(), len(conn.resp.Headers), conn.resp.IsStreamed(), conn.req.hijacked)
	}
	if conn.req.hijacked || conn.resp.IsStreamed() {
		conn.resp.Reset()
		conn.resp.Status(500).String("Streaming/Hijack unsupported in native TLS io_uring HTTP/2 backend")
	}
	if worker.server.config.MaxWriteSize > 0 && int64(conn.resp.transmittedBodyLen()) > worker.server.config.MaxWriteSize {
		conn.resp.Reset()
		conn.resp.Status(500).String("Response Too Large")
	}

	conn.plainBuf = appendH2ResponseFrames(conn.plainBuf, streamID, &conn.resp, st.maxFrameSize)
	bodyLen := int64(conn.resp.transmittedBodyLen())
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
		if worker.server.IsDebug() {
			Dbg("[%s] worker HTTP/2 flush no-op closeAfter=%v", conn.remoteAddr, closeAfter)
		}
		if closeAfter {
			return tlsWorkerActionClose, nil
		}
		return tlsWorkerActionContinue, nil
	}
	if tlsHTTP2WriteInFlight(conn) {
		if closeAfter {
			conn.closeAfter = true
		}
		if worker.server.IsDebug() {
			Dbg("[%s] worker HTTP/2 deferring flush while write in flight bytes=%d closeAfter=%v", conn.remoteAddr, len(conn.plainBuf), closeAfter)
		}
		return tlsWorkerActionContinue, nil
	}
	if worker.server.IsDebug() {
		Dbg("[%s] worker HTTP/2 flushing %d plain bytes closeAfter=%v", conn.remoteAddr, len(conn.plainBuf), closeAfter)
	}
	return worker.queueH2Frames(conn, closeAfter)
}

func (worker *tlsUringWorker) queueH2Frames(conn *tlsWorkerConn, closeAfter bool) (int, error) {
	conn.closeAfter = conn.closeAfter || closeAfter
	conn.writeBuf = buildTLSAppDataRecords(conn.writeBuf[:0], conn.appWriter, conn.plainBuf, &conn.innerScratch)
	conn.plainBuf = conn.plainBuf[:0]
	conn.writeN = len(conn.writeBuf)
	conn.writeSent = 0
	if worker.server.IsDebug() {
		Dbg("[%s] worker HTTP/2 queue write bytes=%d closeAfter=%v", conn.remoteAddr, conn.writeN, closeAfter)
	}
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
			if worker.server.IsDebug() {
				Dbg("[%s] worker HTTP/2 prime nextTLSRecord error: %v", conn.remoteAddr, err)
			}
			return false
		}
		if !ok {
			if worker.server.IsDebug() {
				Dbg("[%s] worker HTTP/2 prime has no buffered tls records", conn.remoteAddr)
			}
			return true
		}
		if worker.server.IsDebug() {
			Dbg("[%s] worker HTTP/2 prime tls record ct=0x%02x payload=%d", conn.remoteAddr, ct, len(payload))
		}
		switch ct {
		case 0x14:
			worker.compactCipherBuffer(conn, totalLen)
			continue
		case 0x15:
			return false
		case 0x17:
			pt, err := conn.appReader.Decrypt(payload)
			if err != nil {
				if worker.server.IsDebug() {
					Dbg("[%s] worker HTTP/2 prime decrypt failed: %v", conn.remoteAddr, err)
				}
				return false
			}
			appContent, appCT, err := StripInnerPlaintext(pt)
			if err != nil {
				if worker.server.IsDebug() {
					Dbg("[%s] worker HTTP/2 prime strip inner plaintext failed: %v", conn.remoteAddr, err)
				}
				return false
			}
			if worker.server.IsDebug() {
				Dbg("[%s] worker HTTP/2 prime inner content type=0x%02x len=%d", conn.remoteAddr, appCT, len(appContent))
			}
			switch appCT {
			case 0x15:
				return false
			case 0x17:
				if !worker.appendHTTP2AppData(conn, appContent) {
					return false
				}
				worker.compactCipherBuffer(conn, totalLen)
			default:
				worker.compactCipherBuffer(conn, totalLen)
			}
		default:
			worker.compactCipherBuffer(conn, totalLen)
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
	if worker.server.IsDebug() {
		Dbg("[%s] worker HTTP/2 buffered app data +%d total=%d off=%d", conn.remoteAddr, len(appContent), len(conn.appBuf), conn.h2.appBufOff)
	}
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
	encodeH2ResponseHeaders(&enc, resp.StatusCode, resp.ContentType, int64(resp.headerContentLength()), resp.Headers)

	body := resp.transmittedBodyBytes()
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
