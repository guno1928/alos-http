//go:build linux && amd64

package core

import ()

// H3Conn represents an HTTP/3 connection layered on a QUICConn. It manages
// the control and QPACK streams and dispatches incoming request streams to
// the server's handlers.
type H3Conn struct {
	qconn      *QUICConn
	server     *Server
	remoteAddr string
	decoder    QPACKDecoder

	controlID       uint64
	peerStreams     map[uint64]*h3PeerStream
	peerControlSeen bool
	peerEncoderSeen bool
	peerDecoderSeen bool
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
	for _, s := range h3.qconn.acquirePeerUniStreams() {
		h3.readPeerStream(s)
		h3.qconn.releaseStream(s)
	}
}

func (h3 *H3Conn) sendControlStream() {
	s := h3.qconn.openLocalUniStream()
	if s == nil {
		return
	}
	defer h3.qconn.releaseStream(s)
	h3.controlID = s.id
	var buf []byte
	buf = h3AppendStreamType(buf, h3StreamControl)
	buf = h3AppendSettingsFrame(buf, h3.server.h3FieldSectionLimit())
	s.Write(buf)
	h3.qconn.sendStreamData(s)
}

func (h3 *H3Conn) sendGoAway(id uint64) {
	s := h3.qconn.acquireStream(h3.controlID)
	if s == nil {
		return
	}
	defer h3.qconn.releaseStream(s)
	if s.Write(h3AppendFrame(nil, h3FrameGoaway, quicAppendVarint(nil, id))) == nil {
		h3.qconn.sendStreamData(s)
	}
}

func (h3 *H3Conn) sendQPACKStreams() {
	enc := h3.qconn.openLocalUniStream()
	if enc == nil {
		return
	}
	defer h3.qconn.releaseStream(enc)
	var encBuf []byte
	encBuf = h3AppendStreamType(encBuf, h3StreamQPACKEnc)
	enc.Write(encBuf)
	h3.qconn.sendStreamData(enc)

	dec := h3.qconn.openLocalUniStream()
	if dec == nil {
		return
	}
	defer h3.qconn.releaseStream(dec)
	var decBuf []byte
	decBuf = h3AppendStreamType(decBuf, h3StreamQPACKDec)
	dec.Write(decBuf)
	h3.qconn.sendStreamData(dec)
}

func (h3 *H3Conn) handleRequestStream(s *QUICStream) {
	var arenaPtr, trailerArenaPtr *[]byte
	var handlerReq *Request
	defer func() {
		r := recover()
		if r != nil {
			h3.server.reportPanic(handlerReq, r)
		}
		if handlerReq != nil {
			s.endHandler(handlerReq)
		}
		if arenaPtr != nil {
			putBoxedBufCapped(&qpackArenaPool, arenaPtr, qpackArenaPoolMaxCap)
		}
		if trailerArenaPtr != nil {
			putBoxedBufCapped(&qpackArenaPool, trailerArenaPtr, qpackArenaPoolMaxCap)
		}
		if r != nil {
			h3.writeErrorResponse(s, 500)
		}
	}()
	data, err := s.readRequest()
	if err != nil {
		return
	}
	if s.overflowed() {
		h3.writeErrorResponse(s, 413)
		return
	}

	req := RequestPool.Get().(*Request)
	req.Reset()

	var meta hpackRequestMeta
	headersSeen, trailersSeen := false, false
	reader := h3FrameReader{data: data}
	for {
		frameType, payload, ok := reader.next()
		if !ok {
			if reader.off != len(data) {
				releaseRequestToPool(req)
				h3.qconn.closeWithAppError(h3ErrFrame, "truncated request frame")
				return
			}
			break
		}
		switch frameType {
		case h3FrameHeaders:
			if trailersSeen {
				h3.abortRequestStream(req, "HEADERS frame after trailers")
				return
			}
			status := 0
			if headersSeen {
				trailersSeen = true
				trailerArenaPtr, status = h3.decodeTrailerSection(payload, req)
			} else {
				headersSeen = true
				meta, arenaPtr, status = h3.decodeRequestSection(payload, req)
			}
			if status != 0 {
				h3.rejectRequest(s, req, status)
				return
			}
		case h3FrameData:
			if !headersSeen || trailersSeen {
				h3.abortRequestStream(req, "DATA frame outside the request body")
				return
			}
			req.Body = append(req.Body, payload...)
			if h3.server.limits.Load().bodyTooLarge(int64(len(req.Body))) {
				h3.rejectRequest(s, req, 413)
				return
			}
		case h3FrameSettings, h3FrameGoaway, h3FrameMaxPushID, h3FrameCancelPush, h3FramePushPromise:
			h3.abortRequestStream(req, "control frame on a request stream")
			return
		default:
			if h3FrameTypeReservedFromHTTP2(frameType) {
				h3.abortRequestStream(req, "HTTP/2 frame type on a request stream")
				return
			}
		}
	}

	if !headersSeen || meta.path == "" {
		h3.rejectRequest(s, req, 400)
		return
	}
	if declared := meta.declaredLength(); declared >= 0 && declared != int64(len(req.Body)) {
		h3.rejectRequest(s, req, 400)
		return
	}

	Stats.RawReqs.Add(1)
	req.Method = meta.method
	req.Path = meta.path
	req.RawPath = meta.rawPath
	req.Query = meta.query
	req.Proto = "HTTP/3"
	req.Host = meta.authority
	req.cachedHost = meta.authority
	req.headerCacheMask = headerCacheHost
	req.RemoteAddr = h3.remoteAddr
	req.IsH2 = false
	req.IsTLS = true
	req.peerCerts = h3.qconn.peerCerts
	req.TLSVersion = TLSVersion13
	req.server = h3.server
	req.aliasesReadBuf = true
	if h3.server.misdirectsClientAuth(h3.qconn.tlsCertEntry, meta.authority) {
		releaseRequestToPool(req)
		h3.writeErrorResponse(s, 421)
		return
	}

	resp := ResponsePool.Get().(*Response)
	resp.Reset()
	resp.lazyReq = req

	Stats.TotalReqs.Add(1)
	handlerReq = req
	s.beginHandler(req)
	h3.dispatchRequest(req, resp)
	s.endHandler(req)
	handlerReq = nil
	h3.writeResponse(s, resp)

	releaseRequestToPool(req)
	releaseResponseToPool(resp)
}

func (h3 *H3Conn) dispatchRequest(req *Request, resp *Response) {
	if h3.server.fastDispatch.Load() {
		promoteRequestStrings(req)
		handler := h3.server.Router.Lookup(req.Method, req.Path, req)
		handler(req, resp)
		return
	}
	h3.server.dispatch(req, resp)
}

func (h3 *H3Conn) rejectRequest(s *QUICStream, req *Request, status int) {
	releaseRequestToPool(req)
	h3.writeErrorResponse(s, status)
}

func (h3 *H3Conn) abortRequestStream(req *Request, reason string) {
	releaseRequestToPool(req)
	h3.qconn.closeWithAppError(h3ErrFrameUnexpected, reason)
}

func (h3 *H3Conn) writeErrorResponse(s *QUICStream, status int) {
	resp := ResponsePool.Get().(*Response)
	resp.Reset()
	resp.Status(status).String(StatusText(status))
	h3.writeResponse(s, resp)
	releaseResponseToPool(resp)
}

func (h3 *H3Conn) writeResponse(s *QUICStream, resp *Response) {
	hbp := qpackEncodeResponseHeaders(
		resp.StatusCode,
		resp.ContentType,
		int64(resp.headerContentLength()),
		resp.Headers,
		h3.server.config.ServerName,
	)

	fbp := h3FrameBufPool.Get().(*[]byte)
	frames := h3AppendHeadersFrame((*fbp)[:0], *hbp)
	putBoxedBufCapped(&qpackEncodeBufPool, hbp, qpackEncodeBufPoolMaxCap)

	bodyBytes := resp.transmittedBodyBytes()
	if len(bodyBytes) > 0 {
		frames = h3AppendDataFrame(frames, bodyBytes)
	}

	s.setSendBuf(frames)
	h3.qconn.sendStreamData(s)
	if s.sendBufDrained() {
		*fbp = frames
		putBoxedBufCapped(&h3FrameBufPool, fbp, h3FrameBufPoolMaxCap)
		return
	}
	h3.qconn.trackStalledSend(s)
}
