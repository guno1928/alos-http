package core

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
	pendingBody        map[uint32][]byte
	sending            map[uint32]*H2Stream
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
	if st.sending == nil {
		st.sending = make(map[uint32]*H2Stream, 4)
	} else {
		for id, stream := range st.sending {
			stream.Reset()
			StreamPool.Put(stream)
			delete(st.sending, id)
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

func appendH2ServerSettingsFlight(dst []byte, s *Server) []byte {
	settings := [5][2]uint32{
		{uint32(H2SettingHeaderTableSize), 0},
		{uint32(H2SettingMaxConcurrentStreams), s.h2MaxStreams()},
		{uint32(H2SettingInitialWindowSize), s.h2InitialWindow()},
		{uint32(H2SettingMaxFrameSize), s.h2MaxFrameSize()},
		{uint32(H2SettingMaxHeaderListSize), H2MaxHeaderListSize},
	}
	settingsFrame := H2WriteSettings(nil, settings[:])
	dst = append(dst, settingsFrame...)
	windowFrame := H2WriteWindowUpdate(nil, 0, uint32(H2ConnectionWindowSize-H2DefaultWindowSize))
	dst = append(dst, windowFrame...)
	return dst
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

func appendH2ResponseHeadersFrame(dst []byte, streamID uint32, resp *Response, endStream bool) []byte {
	bp := MediumBufPool.Get().(*[]byte)
	enc := HpackEncoder{}
	enc.Reset((*bp)[:0])
	encodeH2ResponseHeaders(&enc, resp.StatusCode, resp.ContentType, int64(resp.headerContentLength()), resp.Headers, respServerName(resp))
	flags := byte(H2FlagEndHeaders)
	if endStream {
		flags |= H2FlagEndStream
	}
	dst = appendH2Frame(dst, H2FrameHeaders, flags, streamID, enc.Buf)
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
