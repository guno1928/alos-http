package core

import (
	"log"
)

type H3Conn struct {
	qconn      *QUICConn
	server     *Server
	remoteAddr string
	decoder    QPACKDecoder
}

func newH3Conn(qconn *QUICConn) *H3Conn {
	h3 := &H3Conn{
		qconn:      qconn,
		server:     qconn.server,
		remoteAddr: qconn.remoteAddr.String(),
	}
	qconn.h3 = h3
	return h3
}

func (h3 *H3Conn) start() {
	h3.sendControlStream()
	h3.sendQPACKStreams()
}

func (h3 *H3Conn) sendControlStream() {
	s := h3.qconn.openLocalUniStream()
	var buf []byte
	buf = h3AppendStreamType(buf, h3StreamControl)
	buf = h3AppendSettingsFrame(buf)
	s.Write(buf)
	h3.qconn.sendStreamData(s)
}

func (h3 *H3Conn) sendQPACKStreams() {
	enc := h3.qconn.openLocalUniStream()
	var encBuf []byte
	encBuf = h3AppendStreamType(encBuf, h3StreamQPACKEnc)
	enc.Write(encBuf)
	h3.qconn.sendStreamData(enc)

	dec := h3.qconn.openLocalUniStream()
	var decBuf []byte
	decBuf = h3AppendStreamType(decBuf, h3StreamQPACKDec)
	dec.Write(decBuf)
	h3.qconn.sendStreamData(dec)
}

func (h3 *H3Conn) handleRequestStream(s *QUICStream) {
	data, err := s.ReadAll()
	if err != nil {
		return
	}

	consumed := uint64(len(data))
	if consumed > 0 {
		// dataRecv is now maintained authoritatively on the receive path
		// (handleStreamFrameIncoming enforces connection flow control there);
		// do NOT add consumed here or it double-counts. Read it under the lock
		// to advertise an enlarged MAX_DATA window to the peer.
		h3.qconn.streamsMu.Lock()
		dataRecv := h3.qconn.dataRecv
		h3.qconn.streamsMu.Unlock()

		var fc []byte
		fc = quicAppendMaxStreamDataFrame(fc, s.id, s.recvOff+uint64(quicInitialMaxStreamData))
		fc = quicAppendMaxDataFrame(fc, dataRecv+uint64(quicInitialMaxData))
		h3.qconn.sendFrames(quicSpaceAppData, fc, false)
	}

	reader := h3FrameReader{data: data}

	var method, path, authority, scheme, query, rawPath string
	var reqHeaders [][2]string
	var body []byte

	for {
		frameType, payload, ok := reader.next()
		if !ok {
			break
		}
		switch frameType {
		case h3FrameHeaders:
			decoded, decErr := h3.decoder.Decode(payload)
			if decErr != nil {
				if debugFlag.Load() {
					log.Printf("[H3] QPACK decode error: %v", decErr)
				}
				return
			}
			for _, h := range decoded {
				switch h[0] {
				case ":method":
					method = h[1]
				case ":path":
					rawPath = h[1]
					path = sanitizeRequestPath(h[1])
					_, query = splitPathQuery(h[1])
				case ":authority":
					authority = h[1]
				case ":scheme":
					scheme = h[1]
				default:
					reqHeaders = append(reqHeaders, h)
				}
			}
		case h3FrameData:
			body = append(body, payload...)
		}
	}

	if method == "" || path == "" {
		return
	}
	_ = scheme

	req := RequestPool.Get().(*Request)
	req.Reset()
	req.Method = method
	req.Path = path
	req.RawPath = rawPath
	req.Query = query
	req.Proto = "HTTP/3"
	req.Host = authority
	req.cachedHost = authority
	req.headerCacheMask = headerCacheHost
	req.RemoteAddr = h3.remoteAddr
	req.Headers = append(req.Headers[:0], reqHeaders...)
	req.Body = body
	req.IsH2 = false
	req.server = h3.server

	resp := ResponsePool.Get().(*Response)
	resp.Reset()
	resp.lazyReq = req

	if h3.server.fastDispatch.Load() {
		handler := h3.server.Router.Lookup(req.Method, req.Path, req)
		handler(req, resp)
	} else {
		h3.server.dispatch(req, resp)
	}

	h3.writeResponse(s, resp)

	var maxUpdate []byte
	maxUpdate = quicAppendMaxStreamsFrame(maxUpdate, quicMaxBidiStreams, true)
	h3.qconn.sendFrames(quicSpaceAppData, maxUpdate, false)

	RequestPool.Put(req)
	ResponsePool.Put(resp)
}

func (h3 *H3Conn) writeResponse(s *QUICStream, resp *Response) {
	headerBlock := qpackEncodeResponseHeaders(
		resp.StatusCode,
		resp.ContentType,
		int64(resp.headerContentLength()),
		resp.Headers,
	)

	var frames []byte
	frames = h3AppendHeadersFrame(frames, headerBlock)

	bodyBytes := resp.transmittedBodyBytes()
	if len(bodyBytes) > 0 {
		frames = h3AppendDataFrame(frames, bodyBytes)
	}

	s.Write(frames)
	s.FinishWrite()
	h3.qconn.sendStreamData(s)
}
