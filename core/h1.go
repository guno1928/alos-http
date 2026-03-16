package core

import (
	"bytes"
	"io"
	"net"
)

func (s *Server) ServeH1(conn net.Conn, reader, writer *TrafficAEAD, hdrBuf []byte) {
	bc := NewBufConn(conn)
	defer bc.Release()
	remoteAddr := conn.RemoteAddr().String()
	idleTimeout := s.config.IdleTimeout
	fastDispatch := s.fastDispatch.Load()
	overhead := writer.Overhead()
	maxWrite := s.config.MaxWriteSize

	var req Request
	req.Headers = make([][2]string, 0, 16)
	req.Body = make([]byte, 0, 1024)
	req.Proto = "HTTP/1.1"
	var resp Response
	resp.Headers = make([][2]string, 0, 8)
	resp.body = make([]byte, 0, 4096)

	recBuf := make([]byte, 0, MaxRecordSize+5)
	innerBuf := make([]byte, 0, MaxRecordPayload)
	outBuf := make([]byte, 0, MaxRecordPayload+256)

	var localReqs uint64
	defer func() {
		if localReqs > 0 {
			Stats.TotalReqs.Add(localReqs)
		}
	}()

	for {
		if bc.br.Buffered() == 0 && idleTimeout > 0 {
			conn.SetDeadline(timeNow().Add(idleTimeout))
		}

		var ct byte
		var payload []byte
		for ccsSkips := 0; ; ccsSkips++ {
			hdr := hdrBuf[:5]
			if _, err := io.ReadFull(bc, hdr); err != nil {
				return
			}
			ct = hdr[0]
			length := int(hdr[3])<<8 | int(hdr[4])
			if length > MaxRecordSize {
				return
			}
			if cap(recBuf) < length {
				recBuf = make([]byte, 0, length)
			}
			payload = recBuf[:length]
			if _, err := io.ReadFull(bc, payload); err != nil {
				return
			}
			if ct != 0x14 {
				break
			}
			if ccsSkips >= 5 {
				return
			}
		}

		appPt, err := reader.Decrypt(payload)
		if err != nil {
			return
		}

		appContent, appCT, err := StripInnerPlaintext(appPt)
		if err != nil {
			return
		}

		if appCT == 0x15 {
			return
		}
		if appCT != 0x17 {
			continue
		}

		localReqs++
		if localReqs&63 == 0 {
			Stats.TotalReqs.Add(64)
			localReqs = 0
		}

		req.resetFastH1()

		bodyStart := ParseH1Request(appContent, &req)
		if debugFlag.Load() {
			Dbg("H1 request: %s %s", req.Method, req.Path)
		}

		if req.cachedTE != "" {
			resp.Reset()
			resp.Status(400).String("Bad Request")
			innerBuf, outBuf = writeH1ResponseFast(conn, writer, &resp, overhead, innerBuf, outBuf)
			return
		}

		clStr := req.cachedCL
		if clStr != "" {
			cl, ok := parseUint(clStr)
			if !ok {
				return
			}
			if bodyStart < 0 {
				bodyStart = len(appContent)
			}
			initialBody := appContent[bodyStart:]
			if len(initialBody) > cl {
				return
			}
			req.Body = append(req.Body[:0], initialBody...)
			for len(req.Body) < cl {
				_, nextRec, nextBP, err := ReadRecordSkipCCS(bc, hdrBuf)
				if err != nil {
					return
				}
				nextPt, err := reader.Decrypt(nextRec)
				if err != nil {
					ReleaseRecordBuf(nextBP)
					return
				}
				nextContent, nextCT, err := StripInnerPlaintext(nextPt)
				if err != nil || nextCT != 0x17 {
					ReleaseRecordBuf(nextBP)
					break
				}
				req.Body = append(req.Body, nextContent...)
				if s.config.MaxBodySize > 0 && int64(len(req.Body)) > s.config.MaxBodySize {
					ReleaseRecordBuf(nextBP)
					break
				}
				ReleaseRecordBuf(nextBP)
			}
			if s.config.MaxBodySize > 0 && int64(len(req.Body)) > s.config.MaxBodySize {
				resp.Reset()
				resp.Status(413).String("Payload Too Large")
				innerBuf, outBuf = writeH1ResponseFast(conn, writer, &resp, overhead, innerBuf, outBuf)
				return
			}
		} else if bodyStart >= 0 && bodyStart < len(appContent) {
			req.Body = append(req.Body[:0], appContent[bodyStart:]...)
		}

		resp.resetFastH1()

		req.StreamWriter = nil
		req.RemoteAddr = remoteAddr
		req.conn = conn
		req.server = s
		req.tlsReader = reader
		req.tlsWriter = writer
		req.hdrBuf = hdrBuf
		resp.SetSW(nil)
		resp.lazyReq = &req

		if fastDispatch {
			handler := s.Router.Lookup(req.Method, req.Path, &req)
			handler(&req, &resp)
			if maxWrite > 0 && int64(resp.BodyLen()) > maxWrite {
				resp.resetFastH1()
				resp.Status(500).String("Response Too Large")
			}
		} else {
			s.dispatch(&req, &resp)
		}

		if req.hijacked {
			return
		}

		if resp.IsStreamed() {
			if sw := req.StreamWriter; sw != nil {
				if h1sw, ok := sw.(*H1StreamWriter); ok {
					H1StreamWriterPool.Put(h1sw)
				}
			}
			continue
		}

		innerBuf, outBuf = writeH1ResponseFast(conn, writer, &resp, overhead, innerBuf, outBuf)

		if EqualFoldASCII(req.cachedConn, "close") {
			SendCloseNotify(conn, writer)
			return
		}
	}
}

func writeH1ResponseFast(conn net.Conn, writer *TrafficAEAD, resp *Response, overhead int, innerBuf, outBuf []byte) ([]byte, []byte) {
	const maxInner = MaxRecordPayload - 1

	innerBuf = appendPlainResponse(resp, innerBuf[:0])

	if len(innerBuf) > maxInner {
		WriteAppData(conn, writer, innerBuf)
		return innerBuf, outBuf
	}

	innerBuf = append(innerBuf, 0x17)

	ciphertextLen := len(innerBuf) + overhead
	needed := 5 + ciphertextLen
	if cap(outBuf) < needed {
		outBuf = make([]byte, 0, needed)
	}
	outBuf = outBuf[:0]
	outBuf = append(outBuf, 0x17, 0x03, 0x03, byte(ciphertextLen>>8), byte(ciphertextLen))
	outBuf = writer.EncryptAppend(outBuf, innerBuf)
	conn.Write(outBuf)
	return innerBuf, outBuf
}

func ParseH1Request(data []byte, req *Request) int {
	const maxHeaders = 128
	bodyStart := -1

	idx := bytes.IndexByte(data, '\r')
	if idx < 0 || idx+1 >= len(data) || data[idx+1] != '\n' {
		return bodyStart
	}
	lineEnd := idx
	rl := data[:lineEnd]

	sp1 := bytes.IndexByte(rl, ' ')
	if sp1 < 0 {
		return bodyStart
	}
	sp2 := bytes.IndexByte(rl[sp1+1:], ' ')
	if sp2 >= 0 {
		sp2 += sp1 + 1
	}

	methodBytes := rl[:sp1]
	switch {
	case len(methodBytes) == 3 && methodBytes[0] == 'G' && methodBytes[1] == 'E' && methodBytes[2] == 'T':
		req.Method = "GET"
	case len(methodBytes) == 4 && methodBytes[0] == 'P' && methodBytes[1] == 'O' && methodBytes[2] == 'S' && methodBytes[3] == 'T':
		req.Method = "POST"
	case len(methodBytes) == 3 && methodBytes[0] == 'P' && methodBytes[1] == 'U' && methodBytes[2] == 'T':
		req.Method = "PUT"
	case len(methodBytes) == 6 && methodBytes[0] == 'D':
		req.Method = "DELETE"
	case len(methodBytes) == 5 && methodBytes[0] == 'P' && methodBytes[1] == 'A':
		req.Method = "PATCH"
	case len(methodBytes) == 4 && methodBytes[0] == 'H':
		req.Method = "HEAD"
	case len(methodBytes) == 7 && methodBytes[0] == 'O':
		req.Method = "OPTIONS"
	default:
		req.Method = string(methodBytes)
	}

	if sp2 < 0 {
		req.Path = sanitizeRequestPath(UnsafeString(rl[sp1+1:]))
	} else {
		req.Path = sanitizeRequestPath(UnsafeString(rl[sp1+1 : sp2]))
	}

	for pos := lineEnd + 2; pos < len(data); {
		remaining := data[pos:]
		lineEndOff := bytes.IndexByte(remaining, '\r')
		if lineEndOff < 0 || pos+lineEndOff+1 >= len(data) || remaining[lineEndOff+1] != '\n' {
			break
		}
		nl := pos + lineEndOff
		if nl == pos {
			bodyStart = nl + 2
			break
		}

		line := data[pos:nl]
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			bodyStart = nl + 2
			continue
		}

		name := UnsafeString(line[:colon])
		val := line[colon+1:]
		if len(val) > 0 && val[0] == ' ' {
			val = val[1:]
		}
		valStr := UnsafeString(val)
		req.Headers = append(req.Headers, [2]string{name, valStr})
		if len(req.Headers) > maxHeaders {
			return bodyStart
		}

		switch colon {
		case 4:
			if (name[0] == 'H' || name[0] == 'h') && EqualFoldASCII(name, "Host") {
				req.Host = valStr
				req.cachedHost = valStr
				req.headerCacheMask |= headerCacheHost
			}
		case 6:
			if (name[0] == 'O' || name[0] == 'o') && EqualFoldASCII(name, "Origin") {
				req.cachedOrigin = valStr
				req.headerCacheMask |= headerCacheOrigin
			}
		case 7:
			if (name[0] == 'U' || name[0] == 'u') && EqualFoldASCII(name, "Upgrade") {
				req.cachedUpgrade = valStr
				req.headerCacheMask |= headerCacheUpgrade
			}
		case 9:
			if (name[0] == 'X' || name[0] == 'x') && EqualFoldASCII(name, "X-Real-IP") {
				req.cachedXRI = valStr
				req.headerCacheMask |= headerCacheXRealIP
			}
		case 10:
			if (name[0] == 'C' || name[0] == 'c') && EqualFoldASCII(name, "Connection") {
				req.cachedConn = valStr
				req.headerCacheMask |= headerCacheConnection
			}
		case 13:
			if (name[0] == 'A' || name[0] == 'a') && EqualFoldASCII(name, "Authorization") {
				req.cachedAuth = valStr
				req.headerCacheMask |= headerCacheAuthorization
			}
		case 14:
			if (name[0] == 'C' || name[0] == 'c') && EqualFoldASCII(name, "Content-Length") {
				req.cachedCL = valStr
				req.headerCacheMask |= headerCacheContentLength
			}
		case 15:
			if (name[0] == 'A' || name[0] == 'a') && EqualFoldASCII(name, "Accept-Encoding") {
				req.cachedAE = valStr
				req.headerCacheMask |= headerCacheAcceptEncoding
			} else if (name[0] == 'X' || name[0] == 'x') && EqualFoldASCII(name, "X-Forwarded-For") {
				req.cachedXFF = valStr
				req.headerCacheMask |= headerCacheXForwardedFor
			}
		case 17:
			if (name[0] == 'T' || name[0] == 't') && EqualFoldASCII(name, "Transfer-Encoding") {
				req.cachedTE = valStr
				req.headerCacheMask |= headerCacheTransferEncoding
			} else if (name[0] == 'S' || name[0] == 's') && EqualFoldASCII(name, "Sec-WebSocket-Key") {
				req.cachedWSKey = valStr
				req.headerCacheMask |= headerCacheWSKey
			}
		case 21:
			if (name[0] == 'S' || name[0] == 's') && EqualFoldASCII(name, "Sec-WebSocket-Version") {
				req.cachedWSVer = valStr
				req.headerCacheMask |= headerCacheWSVersion
			}
		}

		pos = nl + 2
		bodyStart = pos
	}

	return bodyStart
}

var statusLines [600][]byte

var smallCL [256][]byte

func init() {
	codes := map[int]string{
		200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 206: "Partial Content",
		301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
		400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
		405: "Method Not Allowed", 408: "Request Timeout", 413: "Payload Too Large",
		416: "Range Not Satisfiable", 426: "Upgrade Required", 429: "Too Many Requests",
		500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
	}
	for code, text := range codes {
		line := make([]byte, 0, 48)
		line = append(line, "HTTP/1.1 "...)
		line = appendUint(line, int64(code))
		line = append(line, ' ')
		line = append(line, text...)
		line = append(line, '\r', '\n')
		statusLines[code] = line
	}
	for i := 0; i < 256; i++ {
		b := make([]byte, 0, 32)
		b = append(b, "Content-Length: "...)
		b = appendUint(b, int64(i))
		b = append(b, '\r', '\n')
		smallCL[i] = b
	}
}

func appendStatusLine(buf []byte, code int) []byte {
	if code > 0 && code < len(statusLines) && statusLines[code] != nil {
		return append(buf, statusLines[code]...)
	}
	buf = append(buf, "HTTP/1.1 "...)
	buf = appendUint(buf, int64(code))
	buf = append(buf, ' ')
	buf = append(buf, StatusText(code)...)
	buf = append(buf, '\r', '\n')
	return buf
}

var (
	ctPrefixTextPlain = []byte("Content-Type: text/plain; charset=utf-8\r\n")
	ctPrefixTextHTML  = []byte("Content-Type: text/html; charset=utf-8\r\n")
	ctPrefixJSON      = []byte("Content-Type: application/json; charset=utf-8\r\n")
	ctPrefixOctet     = []byte("Content-Type: application/octet-stream\r\n")
	connKeepAlive     = []byte("Connection: keep-alive\r\nServer: ALOS\r\n")
)

var ctPrefixMap map[string][]byte

func init() {
	ctPrefixMap = map[string][]byte{
		"text/plain; charset=utf-8":       ctPrefixTextPlain,
		"text/html; charset=utf-8":        ctPrefixTextHTML,
		"application/json; charset=utf-8": ctPrefixJSON,
		"application/octet-stream":        ctPrefixOctet,
	}
}

func BuildH1Response(resp *Response) ([]byte, *[]byte) {
	bp := LargeBufPool.Get().(*[]byte)
	buf := (*bp)[:0]

	buf = appendStatusLine(buf, resp.StatusCode)

	if resp.ContentType != "" {
		if pre, ok := ctPrefixMap[resp.ContentType]; ok {
			buf = append(buf, pre...)
		} else {
			buf = append(buf, "Content-Type: "...)
			buf = append(buf, resp.ContentType...)
			buf = append(buf, '\r', '\n')
		}
	}

	buf = append(buf, "Content-Length: "...)
	buf = appendUint(buf, int64(resp.BodyLen()))
	buf = append(buf, '\r', '\n')

	for i := range resp.Headers {
		buf = append(buf, resp.Headers[i][0]...)
		buf = append(buf, ':', ' ')
		buf = append(buf, resp.Headers[i][1]...)
		buf = append(buf, '\r', '\n')
	}

	buf = append(buf, connKeepAlive...)
	buf = append(buf, '\r', '\n')
	buf = append(buf, resp.GetBody()...)

	*bp = buf
	return buf, bp
}

func WriteH1Response(conn net.Conn, writer *TrafficAEAD, resp *Response) error {
	const maxInner = MaxRecordPayload - 1
	body := resp.GetBody()
	bodyLen := len(body)
	if bodyLen+256 > maxInner {
		respData, respBP := BuildH1Response(resp)
		err := WriteAppData(conn, writer, respData)
		*respBP = (*respBP)[:0]
		LargeBufPool.Put(respBP)
		return err
	}
	ibp := WriteBufPool.Get().(*[]byte)
	inner := (*ibp)[:0]
	inner = appendStatusLine(inner, resp.StatusCode)
	if resp.ContentType != "" {
		if pre, ok := ctPrefixMap[resp.ContentType]; ok {
			inner = append(inner, pre...)
		} else {
			inner = append(inner, "Content-Type: "...)
			inner = append(inner, resp.ContentType...)
			inner = append(inner, '\r', '\n')
		}
	}
	inner = append(inner, "Content-Length: "...)
	inner = appendUint(inner, int64(bodyLen))
	inner = append(inner, '\r', '\n')
	for i := range resp.Headers {
		inner = append(inner, resp.Headers[i][0]...)
		inner = append(inner, ':', ' ')
		inner = append(inner, resp.Headers[i][1]...)
		inner = append(inner, '\r', '\n')
	}
	inner = append(inner, connKeepAlive...)
	inner = append(inner, '\r', '\n')
	inner = append(inner, body...)
	if len(inner) > maxInner {
		*ibp = (*ibp)[:0]
		WriteBufPool.Put(ibp)
		respData, respBP := BuildH1Response(resp)
		err := WriteAppData(conn, writer, respData)
		*respBP = (*respBP)[:0]
		LargeBufPool.Put(respBP)
		return err
	}
	inner = append(inner, 0x17)
	overhead := writer.Overhead()
	ciphertextLen := len(inner) + overhead
	obp := LargeBufPool.Get().(*[]byte)
	var out []byte
	if cap(*obp) >= 5+ciphertextLen {
		out = (*obp)[:0]
	} else {
		out = make([]byte, 0, 5+ciphertextLen)
	}
	out = append(out, 0x17, 0x03, 0x03, byte(ciphertextLen>>8), byte(ciphertextLen))
	out = writer.EncryptAppend(out, inner)
	_, err := conn.Write(out)
	*ibp = (*ibp)[:0]
	WriteBufPool.Put(ibp)
	*obp = out[:0]
	LargeBufPool.Put(obp)
	return err
}
