package core

import (
	"log"
)

// H3Conn represents an HTTP/3 connection layered on a QUICConn. It manages
// the control and QPACK streams and dispatches incoming request streams to
// the server's handlers.
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
	var arenaPtr *[]byte
	defer func() {
		if arenaPtr != nil {
			putBoxedBufCapped(&qpackArenaPool, arenaPtr, qpackArenaPoolMaxCap)
		}
		if r := recover(); r != nil {
			log.Printf("[H3-PANIC] handleRequestStream: %v", r)
			h3.writeErrorResponse(s, 500)
		}
	}()
	data, err := s.ReadAll()
	if err != nil {
		return
	}
	if s.overflowed() {
		h3.writeErrorResponse(s, 413)
		return
	}

	req := RequestPool.Get().(*Request)
	req.Reset()

	reader := h3FrameReader{data: data}
	for {
		frameType, payload, ok := reader.next()
		if !ok {
			break
		}
		switch frameType {
		case h3FrameHeaders:
			var decErr error
			if cached, hit := qpackDecodedBlocks.get(payload); hit {
				req.Headers = append(req.Headers, cached...)
				break
			}
			hadHeaders := len(req.Headers) > 0
			var ap *[]byte
			req.Headers, ap, decErr = h3.decoder.DecodeAppend(payload, req.Headers)
			if arenaPtr == nil {
				arenaPtr = ap
			}
			if decErr == nil && !hadHeaders {
				qpackDecodedBlocks.put(payload, req.Headers)
			}
			if decErr != nil {
				if debugFlag.Load() {
					log.Printf("[H3] QPACK decode error: %v", decErr)
				}
				releaseRequestToPool(req)
				h3.writeErrorResponse(s, 400)
				return
			}
		case h3FrameData:
			req.Body = append(req.Body, payload...)
			if max := h3.server.config.MaxBodySize; max > 0 && int64(len(req.Body)) > max {
				releaseRequestToPool(req)
				h3.writeErrorResponse(s, 413)
				return
			}
		}
	}

	var method, path, authority, scheme, query, rawPath string
	n := 0
	for _, h := range req.Headers {
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
			req.Headers[n] = h
			n++
		}
	}
	req.Headers = req.Headers[:n]

	if method == "" || path == "" {
		releaseRequestToPool(req)
		h3.writeErrorResponse(s, 400)
		return
	}
	_ = scheme

	Stats.RawReqs.Add(1)
	req.Method = method
	req.Path = path
	req.RawPath = rawPath
	req.Query = query
	req.Proto = "HTTP/3"
	req.Host = authority
	req.cachedHost = authority
	req.headerCacheMask = headerCacheHost
	req.RemoteAddr = h3.remoteAddr
	req.IsH2 = false
	req.IsTLS = true
	req.server = h3.server
	req.aliasesReadBuf = true

	resp := ResponsePool.Get().(*Response)
	resp.Reset()
	resp.lazyReq = req

	if h3.server.fastDispatch.Load() {
		promoteRequestStrings(req)
		handler := h3.server.Router.Lookup(req.Method, req.Path, req)
		handler(req, resp)
	} else {
		h3.server.dispatch(req, resp)
	}

	h3.writeResponse(s, resp)

	releaseRequestToPool(req)
	releaseResponseToPool(resp)
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
	}
}
