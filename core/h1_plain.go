package core

import (
	"bytes"
	"io"
	"log"
	"net"
	"sync"

	"github.com/guno1928/alosmap"
)

func appendPlainResponseMode(resp *Response, dst []byte, keepAlive bool, includeBody bool) []byte {
	dst = appendStatusLine(dst, resp.StatusCode)

	if resp.ContentType != "" {
		switch resp.ContentType {
		case "application/json; charset=utf-8":
			dst = append(dst, ctPrefixJSON...)
		case "text/plain; charset=utf-8":
			dst = append(dst, ctPrefixTextPlain...)
		case "text/html; charset=utf-8":
			dst = append(dst, ctPrefixTextHTML...)
		case "application/octet-stream":
			dst = append(dst, ctPrefixOctet...)
		default:
			dst = append(dst, "Content-Type: "...)
			dst = append(dst, resp.ContentType...)
			dst = append(dst, '\r', '\n')
		}
	}

	method := ""
	if resp.lazyReq != nil {
		method = resp.lazyReq.Method
	}
	suppressBody, omitContentLength := responseBodyDisposition(method, resp.StatusCode)
	if !omitContentLength {
		bodyLen := resp.BodyLen()
		if bodyLen < 256 {
			dst = append(dst, smallCL[bodyLen]...)
		} else {
			dst = append(dst, "Content-Length: "...)
			dst = appendUint(dst, int64(bodyLen))
			dst = append(dst, '\r', '\n')
		}
	}

	for i := range resp.Headers {
		dst = append(dst, resp.Headers[i][0]...)
		dst = append(dst, ':', ' ')
		dst = append(dst, resp.Headers[i][1]...)
		dst = append(dst, '\r', '\n')
	}

	if keepAlive {
		dst = append(dst, connKeepAlive...)
	} else {
		dst = append(dst, connClose...)
	}
	dst = append(dst, '\r', '\n')
	if includeBody && !suppressBody {
		dst = resp.appendBody(dst)
	}
	return dst
}

func growPlainReadBuffer(buf []byte, minFree, maxRead int) ([]byte, bool) {
	if cap(buf)-len(buf) >= minFree {
		return buf, true
	}
	unread := len(buf)
	newCap := cap(buf)*2 + minFree
	minCap := unread + minFree
	if newCap < minCap {
		newCap = minCap
	}
	if newCap < 4096 {
		newCap = 4096
	}
	if maxRead > 0 && newCap > maxRead {
		newCap = maxRead
	}
	if newCap < minCap {
		return nil, false
	}
	newBuf := make([]byte, unread, newCap)
	copy(newBuf, buf)
	return newBuf, true
}

var rootPrefixBytes = []byte("GET / HTTP/1.1\r\n")

func (s *Server) matchPlainRootFastRequest(data []byte) ([]byte, int, bool, bool) {
	if !s.plainRootFast.enabled {
		return nil, 0, false, false
	}
	if len(data) < len(rootPrefixBytes)+4 || !bytes.Equal(data[:len(rootPrefixBytes)], rootPrefixBytes) {
		return nil, 0, false, false
	}
	maxHeaderBytes := s.config.MaxHeaderSize
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = 8192
	}
	consumed, keepAlive, ok, needRead := parsePlainFastRootRequest(data, len(rootPrefixBytes), maxHeaderBytes)
	if needRead {
		return nil, 0, false, false
	}
	if !ok {
		return nil, 0, false, false
	}
	if !keepAlive {
		return s.plainRootFast.getClose, consumed, true, true
	}
	return s.plainRootFast.getKeepAlive, consumed, false, true
}

func parsePlainFastRootRequest(buf []byte, lineLen int, maxHeaderBytes int) (consumed int, keepAlive bool, ok bool, needRead bool) {
	headerEnd := findHeaderTerminatorBytes(buf, lineLen)
	if headerEnd < 0 {
		if len(buf) > maxHeaderBytes {
			return 0, false, false, false
		}
		return 0, false, false, true
	}
	keepAlive = true
	for offset := lineLen; offset < headerEnd-4; {
		lineEnd := findCRLFBytes(buf, offset)
		if lineEnd < 0 || lineEnd > headerEnd-2 {
			return 0, false, false, false
		}
		if lineEnd == offset {
			break
		}
		line := buf[offset:lineEnd]
		if asciiHasPrefixFoldBytes(line, "connection:") {
			value := trimASCIISpaceBytes(line[len("connection:"):])
			if asciiEqualFoldBytes(value, "close") {
				keepAlive = false
			} else if asciiEqualFoldBytes(value, "keep-alive") {
				keepAlive = true
			}
		} else if asciiHasPrefixFoldBytes(line, "content-length:") || asciiHasPrefixFoldBytes(line, "transfer-encoding:") {
			return 0, false, false, false
		}
		offset = lineEnd + 2
	}
	return headerEnd, keepAlive, true, false
}

func asciiHasPrefixFoldBytes(line []byte, prefix string) bool {
	if len(line) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if line[i]|0x20 != prefix[i]|0x20 {
			return false
		}
	}
	return true
}

func asciiEqualFoldBytes(line []byte, value string) bool {
	if len(line) != len(value) {
		return false
	}
	for i := 0; i < len(value); i++ {
		if asciiLower[line[i]] != asciiLower[value[i]] {
			return false
		}
	}
	return true
}

var crlfcrlfSlice = []byte{'\r', '\n', '\r', '\n'}

func findHeaderTerminatorBytes(buf []byte, start int) int {
	if start >= len(buf) {
		return -1
	}
	idx := bytes.Index(buf[start:], crlfcrlfSlice)
	if idx < 0 {
		return -1
	}
	return start + idx + 4
}

var crlfSlice = []byte{'\r', '\n'}

func findCRLFBytes(buf []byte, start int) int {
	if start >= len(buf) {
		return -1
	}
	idx := bytes.Index(buf[start:], crlfSlice)
	if idx < 0 {
		return -1
	}
	return start + idx
}

func ParseH1RequestHead(data []byte, req *Request) (headerEnd int, contentLength int, hasContentLength bool, closeConn bool, badTransferEncoding bool, chunkedEncoding bool, ok bool) {
	const maxHeaders = 128

	idx := bytes.Index(data, crlfSlice)
	if idx < 0 {
		return 0, 0, false, false, false, false, false
	}

	rl := data[:idx]
	sp1 := bytes.IndexByte(rl, ' ')
	if sp1 < 0 {
		return 0, 0, false, false, false, false, false
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

	var rawURI string
	if sp2 < 0 {
		rawURI = UnsafeString(rl[sp1+1:])
	} else {
		rawURI = UnsafeString(rl[sp1+1 : sp2])
	}
	req.Path = sanitizeRequestPath(rawURI)
	_, req.Query = splitPathQuery(rawURI)
	req.RawPath = rawURI

	for pos := idx + 2; pos < len(data); {
		remaining := data[pos:]
		lineEndOff := bytes.Index(remaining, crlfSlice)
		if lineEndOff < 0 {
			return 0, 0, false, false, false, false, false
		}
		nl := pos + lineEndOff
		if nl == pos {
			return nl + 2, contentLength, hasContentLength, closeConn, badTransferEncoding, chunkedEncoding, true
		}

		line := data[pos:nl]
		colon := bytes.IndexByte(line, ':')
		if colon > 0 {
			name := UnsafeString(line[:colon])
			val := line[colon+1:]
			if len(val) > 0 && val[0] == ' ' {
				val = val[1:]
			}
			valStr := UnsafeString(val)
			req.Headers = append(req.Headers, [2]string{name, valStr})
			if len(req.Headers) > maxHeaders {
				return nl + 2, contentLength, hasContentLength, closeConn, badTransferEncoding, chunkedEncoding, true
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
					closeConn = len(val) == 5 && asciiLower[val[0]] == 'c' && asciiLower[val[1]] == 'l' && asciiLower[val[2]] == 'o' && asciiLower[val[3]] == 's' && asciiLower[val[4]] == 'e'
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
					parsedCL, parsedOK := parseUint(valStr)
					if hasContentLength {
						if !parsedOK || contentLength < 0 || parsedCL != contentLength {
							contentLength = -1
						}
					} else {
						hasContentLength = true
						if parsedOK {
							contentLength = parsedCL
						} else {
							contentLength = -1
						}
					}
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
					if EqualFoldASCII(valStr, "chunked") {
						chunkedEncoding = true
					} else if valStr != "" {
						badTransferEncoding = true
					}
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
		}

		pos = nl + 2
	}

	return 0, 0, false, false, false, false, false
}

func appendPlainResponse(resp *Response, dst []byte) []byte {
	return appendPlainResponseMode(resp, dst, true, true)
}

var crlfcrlf = [4]byte{13, 10, 13, 10}

func findRequestEnd(data []byte) int {
	if len(data) < 4 {
		return -1
	}
	off := 0
	for {
		idx := bytes.IndexByte(data[off:], '\r')
		if idx < 0 {
			return -1
		}
		pos := off + idx
		if pos+3 >= len(data) {
			return -1
		}
		if data[pos+1] == '\n' && data[pos+2] == '\r' && data[pos+3] == '\n' {
			return pos + 4
		}
		off = pos + 1
	}
}

func findRequestEndFrom(data []byte, start int) int {
	if len(data)-start < 4 {
		return -1
	}
	idx := bytes.Index(data[start:], crlfcrlf[:])
	if idx < 0 {
		return -1
	}
	return start + idx + 4
}

func (s *Server) ServeH2Plain(conn net.Conn) {
	hc := &H2Conn{
		remoteAddr:        conn.RemoteAddr().String(),
		conn:              conn,
		plain:             true,
		hdrBuf:            make([]byte, 5),
		server:            s,
		decoder:           NewHpackDecoder(),
		initialWindowSize: H2DefaultWindowSize,
		streams:           alosmap.NewTypedSized[int64, *H2Stream](256, 0).Prealloc(256),
		writeCh:           make(chan WriteRequest, 512),
		done:              make(chan struct{}),
		decryptBuf:        make([]byte, 0, MaxRecordSize),
		appBuf:            make([]byte, 0, MaxRecordSize*2),
		headerAccum:       make([]byte, 0, 4096),
	}
	hc.connWindow.Store(int64(H2DefaultWindowSize))
	hc.maxFrameSize.Store(H2DefaultMaxFrameSize)
	hc.recvConnWindow.Store(int64(H2ConnectionWindowSize))
	hc.flowCond = sync.NewCond(&hc.flowMu)

	go hc.writerLoop()

	defer func() {
		close(hc.done)
		hc.flowCond.Broadcast()
		hc.dispatchWg.Wait()
		close(hc.writeCh)
	}()

	if !hc.readAndValidatePreface() {
		return
	}

	hc.sendInitialSettingsAndWindowUpdate()
	hc.serveLoop()
}

func (hc *H2Conn) readAppDataPlain() error {
	bp := RecordBufPool.Get().(*[]byte)
	buf := (*bp)[:cap(*bp)]
	n, err := hc.conn.Read(buf)
	if n > 0 {
		hc.appBuf = append(hc.appBuf, buf[:n]...)
		hc.appBufValid = len(hc.appBuf)
	}
	*bp = buf[:0]
	RecordBufPool.Put(bp)
	if err != nil {
		return err
	}
	return nil
}

func (hc *H2Conn) readAndValidatePrefacePlain() bool {
	var preface [H2PrefaceLen]byte
	if _, err := io.ReadFull(hc.conn, preface[:]); err != nil {
		return false
	}
	for i := 0; i < H2PrefaceLen; i++ {
		if preface[i] != H2ClientPreface[i] {
			return false
		}
	}
	Dbg("[H2-plain] client preface validated")
	return true
}

func (hc *H2Conn) writerLoopPlain() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[H2] writer panic: %v", r)
			hc.conn.Close()
		}
	}()
	var batch [writeRequestBatchSize]WriteRequest
	batchBuf := make([]byte, 0, 16384)
	for req := range hc.writeCh {
		batch[0] = req
		n := 1

	drain:
		for n < len(batch) {
			select {
			case next, ok := <-hc.writeCh:
				if !ok {
					break drain
				}
				batch[n] = next
				n++
			default:
				break drain
			}
		}

		if n == 1 {
			err := writeFull(hc.conn, req.Data)
			if req.Done != nil {
				req.Done <- err
			}
		} else {
			batchBuf = appendWriteBatch(batchBuf, batch, n)
			err := writeFull(hc.conn, batchBuf)
			for i := 0; i < n; i++ {
				if batch[i].Done != nil {
					batch[i].Done <- err
				}
			}
		}
	}
}
