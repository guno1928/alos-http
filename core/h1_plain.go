//go:build linux && amd64

package core

import (
	"bytes"
	"math/bits"
	"net/http"
)

func plainOKHead(resp *Response) []byte {
	if preset := plainContentTypePreset(resp.ContentType); preset >= 0 && (len(resp.Headers) == 0 || !headersHaveFold(resp.Headers, "Date")) {
		return currentHTTPDate().ok200[preset]
	}
	return nil
}

func appendPlainResponseMode(resp *Response, dst []byte, keepAlive bool, includeBody bool) []byte {
	var head []byte
	if resp.StatusCode == http.StatusOK {
		head = plainOKHead(resp)
	}
	if head != nil {
		dst = append(dst, head...)
	} else {
		dst = appendStatusLine(dst, resp.StatusCode)
		dst = appendDateUnlessSet(dst, resp.Headers)
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
				dst = appendHeaderValueStripped(dst, resp.ContentType)
				dst = append(dst, '\r', '\n')
			}
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

	dst = appendH1HeaderFields(dst, resp.Headers)
	dst = append(dst, serverConnHeadTail(resp, keepAlive)...)
	if includeBody && !suppressBody {
		dst = resp.appendBody(growIOBuf(dst, resp.BodyLen()))
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

var rootPrefix16 = [16]byte{'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1', '\r', '\n'}
var rootPrefixBytes = rootPrefix16[:]

func (s *Server) matchPlainRootFastRequest(data []byte, tls bool) ([]byte, int, bool, bool) {
	fast := s.plainRootFast.Load()
	if fast == nil {
		return nil, 0, false, false
	}
	if len(data) < len(rootPrefixBytes)+4 || !equalPrefix16(data, &rootPrefix16) {
		return nil, 0, false, false
	}
	maxHeaderBytes := s.limits.Load().MaxHeaderSize
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = 8192
	}
	consumed, keepAlive, ok, needRead := parsePlainFastRootRequest(data, len(rootPrefixBytes), maxHeaderBytes, fast.maxHeaderCount)
	if needRead {
		return nil, 0, false, false
	}
	if !ok {
		return nil, 0, false, false
	}
	if consumed-2 > maxHeaderBytes || consumed > fast.uncountedHeadLen && scalarRootFieldsExceed(data, consumed, fast.maxHeaderCount) {
		return nil, 0, false, false
	}
	return fast.bytesFor(keepAlive, tls), consumed, !keepAlive, true
}

const (
	defaultMaxHeaderCount     = 128
	minH1FieldLineBytes       = len("x:\r\n")
	maxH1FieldStartsPerChunk  = 64 / minH1FieldLineBytes
	rootScalarScanMaxBytes    = 96
	rootFastHeadTerminatorLen = len("\r\n")
)

var newlineBytes = []byte{'\n'}

func rootFastUncountedHeadLen(maxHeaderCount int) int {
	return len(rootPrefixBytes) + maxHeaderCount*minH1FieldLineBytes + rootFastHeadTerminatorLen
}

func scalarRootFieldsExceed(data []byte, consumed, maxHeaderCount int) bool {
	return consumed <= rootScalarScanMaxBytes && bytes.Count(data[len(rootPrefixBytes):consumed-rootFastHeadTerminatorLen], newlineBytes) > maxHeaderCount
}

func parsePlainFastRootRequest(buf []byte, lineLen int, maxHeaderBytes, maxHeaderCount int) (consumed int, keepAlive bool, ok bool, needRead bool) {
	if len(buf) <= rootScalarScanMaxBytes {
		st := rootFastState{keepAlive: true}
		if headerEnd, ok := st.scanFields(buf, lineLen); ok && st.hosts == 1 {
			return headerEnd, st.keepAlive, true, false
		}
	} else if endsWithHeaderTerminator(buf, lineLen) {
		if keepAlive, ok := rootFastHeaders(buf[lineLen:len(buf)-2], maxHeaderCount); ok {
			return len(buf), keepAlive, true, false
		}
	}
	headerEnd := findHeaderTerminatorBytes(buf, lineLen)
	if headerEnd < 0 {
		if len(buf) > maxHeaderBytes {
			return 0, false, false, false
		}
		return 0, false, false, true
	}
	keepAlive, ok = rootFastHeaders(buf[lineLen:headerEnd-2], maxHeaderCount)
	if !ok {
		return 0, false, false, false
	}
	return headerEnd, keepAlive, true, false
}

func endsWithHeaderTerminator(buf []byte, lineLen int) bool {
	n := len(buf)
	return n-2 >= lineLen && n >= 4 && string(buf[n-4:]) == "\r\n\r\n"
}

func rootFastHeaders(block []byte, maxHeaderCount int) (keepAlive, ok bool) {
	st := rootFastState{keepAlive: true, maxCount: maxHeaderCount}
	if !st.fields(block) || st.hosts != 1 {
		return false, false
	}
	return st.keepAlive, true
}

type rootFastState struct {
	hosts     int
	maxCount  int
	keepAlive bool
}

func (st *rootFastState) scanFields(buf []byte, i int) (headerEnd int, ok bool) {
	for i+1 < len(buf) {
		if buf[i] == '\r' {
			return i + 2, buf[i+1] == '\n'
		}
		name, value, next, hostSafe, ok := rootFieldScalar(buf, i)
		if !ok || !st.field(name, value, hostSafe) {
			return 0, false
		}
		i = next
	}
	return 0, false
}

func (st *rootFastState) fields(block []byte) bool {
	if len(block) >= h1BlockMinBytes {
		if ok, indexed := st.indexedFields(block); indexed {
			return ok
		}
	}
	return st.lineFields(block)
}

func (st *rootFastState) indexedFields(block []byte) (ok, indexed bool) {
	var idx h1BlockIndexOut
	if !h1BlockIndex(block, &idx) {
		return false, false
	}
	chunks := (len(block) + 63) >> 6
	for ci := 0; ci < chunks; ci++ {
		for c := idx.cands[ci]; c != 0; c &= c - 1 {
			start := ci<<6 | bits.TrailingZeros64(c)
			colon := h1NextBit(&idx.ends, start, chunks)
			end := len(block) - 2
			if next := h1NextBit(&idx.starts, colon, chunks); next >= 0 {
				end = next - 2
			}
			if !st.field(block[start:colon], block[colon+1:end], false) {
				return false, true
			}
		}
	}
	return len(block) <= st.maxCount*minH1FieldLineBytes || h1BlockStartsWithin(&idx, chunks, st.maxCount), true
}

func h1BlockStartsWithin(idx *h1BlockIndexOut, chunks, maxCount int) bool {
	count := 0
	for ci := 0; ci < chunks; ci++ {
		count += bits.OnesCount64(idx.starts[ci])
		if count+(chunks-1-ci)*maxH1FieldStartsPerChunk <= maxCount {
			return true
		}
	}
	return count <= maxCount
}

func (st *rootFastState) lineFields(block []byte) bool {
	count := 0
	for i := 0; i < len(block); {
		var name, value []byte
		var hostSafe, ok bool
		if len(block)-i >= h1ScalarScanMax {
			name, value, i, ok = rootFieldVector(block, i)
		} else {
			name, value, i, hostSafe, ok = rootFieldScalar(block, i)
		}
		if !ok || !st.field(name, value, hostSafe) {
			return false
		}
		count++
	}
	return count <= st.maxCount
}

func (st *rootFastState) field(name, value []byte, hostSafe bool) bool {
	switch len(name) {
	case len("host"):
		if asciiEqualFoldBytes(name, "host") {
			st.hosts++
			return hostSafe || ValidateHost(UnsafeString(trimOWS(value)))
		}
	case len("connection"):
		if asciiEqualFoldBytes(name, "connection") {
			if value = trimOWS(value); !asciiEqualFoldBytes(value, "keep-alive") {
				if closeRequested, _ := connectionOptionList(UnsafeString(value)); closeRequested {
					st.keepAlive = false
				}
			}
		}
	case len("expect"), len("content-length"), len("transfer-encoding"):
		return !asciiEqualFoldBytes(name, "expect") && !asciiEqualFoldBytes(name, "content-length") && !asciiEqualFoldBytes(name, "transfer-encoding")
	}
	return true
}

func rootFieldVector(fields []byte, i int) (name, value []byte, next int, ok bool) {
	rest := fields[i:]
	special, nameEnd := h1HeaderLineSpecials(rest)
	end, bad := classifyFirstSpecial(rest, special)
	if bad || end <= 0 || !validH1Colon(rest[:end], nameEnd) {
		return nil, nil, 0, false
	}
	return rest[:nameEnd], trimOWS(rest[nameEnd+1 : end]), i + end + 2, true
}

func rootFieldScalar(fields []byte, i int) (name, value []byte, next int, hostSafe, ok bool) {
	start := i
	for i < len(fields) && h1FieldClass[fields[i]]&h1ClassToken != 0 {
		i++
	}
	if i == start || i == len(fields) || fields[i] != ':' {
		return nil, nil, 0, false, false
	}
	name = fields[start:i]
	i++
	for i < len(fields) && (fields[i] == ' ' || fields[i] == '\t') {
		i++
	}
	valueStart := i
	var seen uint8
	common := ^uint8(0)
	for i < len(fields) && fields[i] != '\r' {
		class := h1FieldClass[fields[i]]
		seen |= class
		common &= class
		i++
	}
	if i+1 >= len(fields) || seen&h1ClassSpecial != 0 || fields[i+1] != '\n' {
		return nil, nil, 0, false, false
	}
	return name, fields[valueStart:i], i + 2, common&h1ClassHost != 0, true
}

func connectionOptions(value []byte) (closeRequested, keepAliveRequested bool) {
	switch {
	case asciiEqualFoldBytes(value, "keep-alive"):
		return false, true
	case asciiEqualFoldBytes(value, "close"):
		return true, false
	}
	return connectionOptionList(UnsafeString(value))
}

func connectionOptionList(options string) (closeRequested, keepAliveRequested bool) {
	return containsTokenFold(options, "close"), containsTokenFold(options, "keep-alive")
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

func findHeaderTerminatorBytes(buf []byte, start int) int {
	if start >= len(buf) {
		return -1
	}
	idx := indexCRLFCRLF(buf[start:])
	if idx < 0 {
		return -1
	}
	return start + idx + 4
}

// ParseH1RequestHead parses the HTTP/1.x request line and header block in
// data into req. It returns the length of the parsed header block, the
// Content-Length value (if any consistent value was present), whether the
// connection should close, whether Transfer-Encoding was malformed or
// chunked, whether the header block exceeded maxHeaderBytes or
// maxHeaderCount, and whether a complete head was found.
var h1TokenChar = func() [256]bool {
	var t [256]bool
	for c := 'a'; c <= 'z'; c++ {
		t[c] = true
	}
	for c := 'A'; c <= 'Z'; c++ {
		t[c] = true
	}
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	for _, c := range []byte("!#$%&'*+-.^_`|~") {
		t[c] = true
	}
	return t
}()

func isH1Token(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !h1TokenChar[c] {
			return false
		}
	}
	return true
}

func validH1Version(v []byte) bool {
	return len(v) == 8 && v[0] == 'H' && v[1] == 'T' && v[2] == 'T' && v[3] == 'P' &&
		v[4] == '/' && v[5] == '1' && v[6] == '.' && (v[7] == '0' || v[7] == '1')
}

func ParseH1RequestHead(data []byte, req *Request, maxHeaderBytes, maxHeaderCount int) (headerEnd int, contentLength int, hasContentLength bool, closeConn bool, badTransferEncoding bool, chunkedEncoding bool, tooLarge bool, ok bool) {
	headerEnd, contentLength, hasContentLength, closeConn, reject, chunkedEncoding, tooLarge, ok := parseH1RequestHead(data, req, maxHeaderBytes, maxHeaderCount)
	return headerEnd, contentLength, hasContentLength, closeConn, reject != h1RejectNone, chunkedEncoding, tooLarge, ok
}

func parseH1RequestHead(data []byte, req *Request, maxHeaderBytes, maxHeaderCount int) (headerEnd int, contentLength int, hasContentLength bool, closeConn bool, reject h1RejectReason, chunkedEncoding bool, tooLarge bool, ok bool) {
	maxBytes := maxHeaderBytes
	if maxBytes <= 0 {
		maxBytes = 8192
	}
	maxCount := maxHeaderCount
	if maxCount <= 0 {
		maxCount = defaultMaxHeaderCount
	}

	idx, bad := classifyFirstSpecial(data, firstH1Special(data))
	if bad {
		return 0, 0, false, false, h1RejectRequestLine, false, false, true
	}
	if idx < 0 {
		if len(data) > maxBytes {
			return 0, 0, false, false, h1RejectNone, false, true, false
		}
		return 0, 0, false, false, h1RejectNone, false, false, false
	}

	rl := data[:idx]
	sp1 := bytes.IndexByte(rl, ' ')
	if sp1 < 0 {
		return 0, 0, false, false, h1RejectRequestLine, false, false, true
	}
	sp2 := bytes.IndexByte(rl[sp1+1:], ' ')
	if sp2 <= 0 {
		return 0, 0, false, false, h1RejectRequestLine, false, false, true
	}
	sp2 += sp1 + 1

	if !validH1Version(rl[sp2+1:]) {
		return 0, 0, false, false, h1RejectRequestLine, false, false, true
	}
	http10 := rl[sp2+8] == '0'
	if http10 {
		req.Proto = internedHTTP10
	} else {
		req.Proto = internedHTTP11
	}
	keepAliveRequested := false

	methodBytes := rl[:sp1]
	if !isH1Token(methodBytes) {
		return 0, 0, false, false, h1RejectRequestLine, false, false, true
	}
	switch string(methodBytes) {
	case internedGET:
		req.Method = internedGET
	case internedPOST:
		req.Method = internedPOST
	case internedPUT:
		req.Method = internedPUT
	case internedDELETE:
		req.Method = internedDELETE
	case internedPATCH:
		req.Method = internedPATCH
	case internedHEAD:
		req.Method = internedHEAD
	case internedOPTIONS:
		req.Method = internedOPTIONS
	default:
		req.Method = string(methodBytes)
	}

	rawURI := UnsafeString(rl[sp1+1 : sp2])
	var absoluteHost, target string
	absoluteForm := false
	if len(rawURI) > 0 && rawURI[0] != '/' {
		absoluteHost, target, absoluteForm = splitAbsoluteForm(rawURI)
	}
	if absoluteForm {
		if absoluteHost == "" || !ValidateHost(absoluteHost) {
			return 0, 0, false, false, h1RejectHost, false, false, true
		}
		rawURI = target
	}
	pathPart, query := splitPathQuery(rawURI)
	req.Path = sanitizeSplitPath(pathPart)
	req.Query = query
	req.RawPath = rawURI

	badTransferEncoding := false
	hostCount := 0
	for pos := idx + 2; pos < len(data); {
		if pos > maxBytes {
			return 0, 0, false, false, h1RejectNone, false, true, false
		}
		remaining := data[pos:]
		var special, nameEnd int
		hostSafe := false
		if len(remaining) < h1ScalarScanMax {
			special, nameEnd, hostSafe = h1HeaderLineScalar(remaining)
		} else {
			special, nameEnd = h1HeaderLineSpecials(remaining)
		}
		lineEndOff, bad := classifyFirstSpecial(remaining, special)
		if bad {
			return 0, 0, false, false, h1RejectCTL, false, false, true
		}
		if lineEndOff < 0 {
			if len(data) > maxBytes {
				return 0, 0, false, false, h1RejectNone, false, true, false
			}
			return 0, 0, false, false, h1RejectNone, false, false, false
		}
		nl := pos + lineEndOff
		if nl == pos {
			if badTransferEncoding || chunkedEncoding && (hasContentLength || http10) {
				return 0, 0, false, false, h1RejectTransferEncoding, false, false, true
			}
			if hostCount > 1 || hostCount == 0 && !http10 {
				return 0, 0, false, false, h1RejectHost, false, false, true
			}
			if http10 {
				req.expect = h1ExpectNone
			}
			if absoluteForm {
				req.Host = absoluteHost
				req.cachedHost = absoluteHost
				req.headerCacheMask |= headerCacheHost
			}
			if http10 && !keepAliveRequested {
				closeConn = true
			}
			req.aliasesReadBuf = true
			return nl + 2, contentLength, hasContentLength, closeConn, h1RejectNone, chunkedEncoding, false, true
		}

		line := data[pos:nl]
		if !validH1Colon(line, nameEnd) {
			return 0, 0, false, false, h1HeaderLineReject(line), false, false, true
		}
		colon := nameEnd
		name := UnsafeString(line[:colon])
		val := trimOWS(line[colon+1:])
		valStr := UnsafeString(val)
		req.Headers = append(req.Headers, [2]string{name, valStr})
		if len(req.Headers) > maxCount {
			return nl + 2, contentLength, hasContentLength, closeConn, h1RejectNone, chunkedEncoding, true, false
		}

		switch colon {
		case 4:
			if (name[0] == 'H' || name[0] == 'h') && EqualFoldASCII(name, "Host") {
				hostCount++
				if !hostSafe && !ValidateHost(valStr) {
					return 0, 0, false, false, h1RejectHost, false, false, true
				}
				req.Host = valStr
				req.cachedHost = valStr
				req.headerCacheMask |= headerCacheHost
			}
		case 6:
			if (name[0] == 'O' || name[0] == 'o') && EqualFoldASCII(name, "Origin") {
				req.cachedOrigin = valStr
				req.headerCacheMask |= headerCacheOrigin
			} else if (name[0] == 'E' || name[0] == 'e') && EqualFoldASCII(name, "Expect") {
				req.expect = classifyExpect(req.expect, val)
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
				closeRequested, keepAliveListed := connectionOptions(val)
				closeConn = closeConn || closeRequested
				keepAliveRequested = keepAliveRequested || keepAliveListed
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
				} else {
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

		pos = nl + 2
	}

	return 0, 0, false, false, h1RejectNone, false, false, false
}

func appendPlainResponse(resp *Response, dst []byte) []byte {
	return appendPlainResponseMode(resp, dst, true, true)
}

func appendPlainResponseClose(resp *Response, dst []byte) []byte {
	return appendPlainResponseMode(resp, dst, false, true)
}

func appendPlainResponseHeaders(resp *Response, dst []byte) []byte {
	return appendPlainResponseMode(resp, dst, true, false)
}
