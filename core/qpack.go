package core

import "sync"

var qpackStaticTable = [99][2]string{
	{":authority", ""},
	{":path", "/"},
	{"age", "0"},
	{"content-disposition", ""},
	{"content-length", "0"},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"referer", ""},
	{"set-cookie", ""},
	{":method", "CONNECT"},
	{":method", "DELETE"},
	{":method", "GET"},
	{":method", "HEAD"},
	{":method", "OPTIONS"},
	{":method", "POST"},
	{":method", "PUT"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "103"},
	{":status", "200"},
	{":status", "304"},
	{":status", "404"},
	{":status", "503"},
	{"accept", "*/*"},
	{"accept", "application/dns-message"},
	{"accept-encoding", "gzip, deflate, br"},
	{"accept-ranges", "bytes"},
	{"access-control-allow-headers", "cache-control"},
	{"access-control-allow-headers", "content-type"},
	{"access-control-allow-origin", "*"},
	{"cache-control", "max-age=0"},
	{"cache-control", "max-age=2592000"},
	{"cache-control", "max-age=604800"},
	{"cache-control", "no-cache"},
	{"cache-control", "no-store"},
	{"cache-control", "public, max-age=31536000"},
	{"content-encoding", "br"},
	{"content-encoding", "gzip"},
	{"content-type", "application/dns-message"},
	{"content-type", "application/javascript"},
	{"content-type", "application/json"},
	{"content-type", "application/x-www-form-urlencoded"},
	{"content-type", "image/gif"},
	{"content-type", "image/jpeg"},
	{"content-type", "image/png"},
	{"content-type", "text/css"},
	{"content-type", "text/html; charset=utf-8"},
	{"content-type", "text/plain"},
	{"content-type", "text/plain;charset=utf-8"},
	{"range", "bytes=0-"},
	{"strict-transport-security", "max-age=31536000"},
	{"strict-transport-security", "max-age=31536000; includesubdomains"},
	{"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
	{"vary", "accept-encoding"},
	{"vary", "origin"},
	{"x-content-type-options", "nosniff"},
	{"x-xss-protection", "1; mode=block"},
	{":status", "100"},
	{":status", "204"},
	{":status", "206"},
	{":status", "302"},
	{":status", "400"},
	{":status", "403"},
	{":status", "421"},
	{":status", "425"},
	{":status", "500"},
	{"accept-language", ""},
	{"access-control-allow-credentials", "FALSE"},
	{"access-control-allow-credentials", "TRUE"},
	{"access-control-allow-headers", "*"},
	{"access-control-allow-methods", "get"},
	{"access-control-allow-methods", "get, post, options"},
	{"access-control-allow-methods", "options"},
	{"access-control-expose-headers", "content-length"},
	{"access-control-request-headers", "content-type"},
	{"access-control-request-method", "get"},
	{"access-control-request-method", "post"},
	{"alt-svc", "clear"},
	{"authorization", ""},
	{"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{"early-data", "1"},
	{"expect-ct", ""},
	{"forwarded", ""},
	{"if-range", ""},
	{"origin", ""},
	{"purpose", "prefetch"},
	{"server", ""},
	{"timing-allow-origin", "*"},
	{"upgrade-insecure-requests", "1"},
	{"user-agent", ""},
	{"x-forwarded-for", ""},
	{"x-frame-options", "deny"},
	{"x-frame-options", "sameorigin"},
}

type QPACKEncoder struct {
	buf []byte
}

func (e *QPACKEncoder) Reset(dst []byte) {
	e.buf = dst
}

func (e *QPACKEncoder) Bytes() []byte {
	return e.buf
}

func (e *QPACKEncoder) encodeRequiredInsertCount() {
	e.buf = append(e.buf, 0x00, 0x00)
}

func (e *QPACKEncoder) encodeIndexed(idx int) {
	e.buf = append(e.buf, 0xc0|byte(idx))
}

func (e *QPACKEncoder) encodeIndexedLarge(idx int) {
	e.encodeQPACKInt(0xc0, 6, uint64(idx))
}

func (e *QPACKEncoder) encodeLiteralWithNameRef(idx int, value string) {
	e.encodeQPACKInt(0x50, 4, uint64(idx))
	e.encodeQPACKString(value)
}

func (e *QPACKEncoder) encodeLiteral(name, value string) {
	huffNameLen := hpackHuffmanEncodedLen(name)
	if huffNameLen < len(name) {
		e.encodeQPACKInt(0x28, 3, uint64(huffNameLen))
		e.buf = hpackHuffmanAppend(e.buf, name)
	} else {
		e.encodeQPACKInt(0x20, 3, uint64(len(name)))
		e.buf = append(e.buf, name...)
	}
	e.encodeQPACKString(value)
}

func (e *QPACKEncoder) encodeQPACKInt(prefix byte, prefixBits uint8, val uint64) {
	maxFirst := uint64((1 << prefixBits) - 1)
	if val < maxFirst {
		e.buf = append(e.buf, prefix|byte(val))
		return
	}
	e.buf = append(e.buf, prefix|byte(maxFirst))
	val -= maxFirst
	for val >= 128 {
		e.buf = append(e.buf, byte(val&0x7f)|0x80)
		val >>= 7
	}
	e.buf = append(e.buf, byte(val))
}

func (e *QPACKEncoder) encodeQPACKString(s string) {
	huffLen := hpackHuffmanEncodedLen(s)
	if huffLen < len(s) {
		e.encodeQPACKInt(0x80, 7, uint64(huffLen))
		e.buf = hpackHuffmanAppend(e.buf, s)
	} else {
		e.encodeQPACKInt(0x00, 7, uint64(len(s)))
		e.buf = append(e.buf, s...)
	}
}

type qpackStaticKey struct {
	name, value string
}

var qpackStaticFullMap map[qpackStaticKey]int
var qpackStaticNameMap map[string]int

func init() {
	qpackStaticFullMap = make(map[qpackStaticKey]int, len(qpackStaticTable))
	qpackStaticNameMap = make(map[string]int, 50)
	for i := 0; i < len(qpackStaticTable); i++ {
		k := qpackStaticKey{qpackStaticTable[i][0], qpackStaticTable[i][1]}
		if _, exists := qpackStaticFullMap[k]; !exists {
			qpackStaticFullMap[k] = i
		}
		if _, exists := qpackStaticNameMap[qpackStaticTable[i][0]]; !exists {
			qpackStaticNameMap[qpackStaticTable[i][0]] = i
		}
	}
}

func qpackFindStaticIndex(name, value string) int {
	if idx, ok := qpackStaticFullMap[qpackStaticKey{name, value}]; ok {
		return idx
	}
	return -1
}

func qpackFindStaticNameIndex(name string) int {
	if idx, ok := qpackStaticNameMap[name]; ok {
		return idx
	}
	return -1
}

var qpackStatusIndex [600]int16

func init() {
	for i := range qpackStatusIndex {
		qpackStatusIndex[i] = -1
	}
	for i := 0; i < len(qpackStaticTable); i++ {
		if qpackStaticTable[i][0] == ":status" {
			code, ok := parseUint(qpackStaticTable[i][1])
			if ok && code < 600 {
				qpackStatusIndex[code] = int16(i)
			}
		}
	}
}

func (e *QPACKEncoder) EncodeStatus(code int) {
	if code > 0 && code < 600 {
		idx := qpackStatusIndex[code]
		if idx >= 0 {
			e.encodeIndexedLarge(int(idx))
			return
		}
	}
	var buf [4]byte
	s := appendUint(buf[:0], int64(code))
	nameIdx := qpackFindStaticNameIndex(":status")
	if nameIdx >= 0 {
		e.encodeLiteralWithNameRef(nameIdx, UnsafeString(s))
	} else {
		e.encodeLiteral(":status", UnsafeString(s))
	}
}

func (e *QPACKEncoder) EncodeHeader(name, value string) {
	idx := qpackFindStaticIndex(name, value)
	if idx >= 0 {
		e.encodeIndexedLarge(idx)
		return
	}
	nameIdx := qpackFindStaticNameIndex(name)
	if nameIdx >= 0 {
		e.encodeLiteralWithNameRef(nameIdx, value)
		return
	}
	e.encodeLiteral(name, value)
}

type QPACKDecoder struct{}

func (d *QPACKDecoder) Decode(data []byte) ([][2]string, error) {
	if len(data) < 2 {
		return nil, ErrTruncated
	}
	pos := 0
	ric, n := qpackDecodeInt(data[pos:], 8)
	if n == 0 {
		return nil, ErrTruncated
	}
	pos += n
	// We advertise zero dynamic-table capacity, so a nonzero Required Insert
	// Count refers to dynamic entries that cannot exist: reject as a
	// decompression failure rather than silently decoding against a phantom table.
	if ric != 0 {
		return nil, ErrQPACKDecompressionFailed
	}
	_, sn := qpackDecodeInt(data[pos:], 7)
	if sn == 0 {
		return nil, ErrTruncated
	}
	pos += sn

	var headers [][2]string
	for pos < len(data) {
		b := data[pos]
		if b&0x80 != 0 {
			static := b&0x40 != 0
			idx, n := qpackDecodeInt(data[pos:], 6)
			if n == 0 {
				return nil, ErrTruncated
			}
			pos += n
			// Only static-table references are valid: dynamic capacity is zero,
			// and an out-of-range static index has no entry to resolve.
			if !static || int(idx) >= len(qpackStaticTable) {
				return nil, ErrQPACKDecompressionFailed
			}
			headers = append(headers, qpackStaticTable[idx])
		} else if b&0x40 != 0 {
			nameIsStatic := b&0x10 != 0
			nameIdx, n := qpackDecodeInt(data[pos:], 4)
			if n == 0 {
				return nil, ErrTruncated
			}
			pos += n
			value, vn := qpackDecodeString(data[pos:])
			if vn == 0 {
				return nil, ErrTruncated
			}
			pos += vn
			// The name must resolve to a static-table entry; a dynamic name
			// reference or out-of-range static index cannot yield a header name.
			if !nameIsStatic || int(nameIdx) >= len(qpackStaticTable) {
				return nil, ErrQPACKDecompressionFailed
			}
			name := qpackStaticTable[nameIdx][0]
			headers = append(headers, [2]string{name, value})
		} else if b&0x20 != 0 {
			huffName := b&0x08 != 0
			nameLen, n := qpackDecodeInt(data[pos:], 3)
			if n == 0 {
				return nil, ErrTruncated
			}
			pos += n
			if pos+int(nameLen) > len(data) {
				return nil, ErrTruncated
			}
			nameRaw := data[pos : pos+int(nameLen)]
			pos += int(nameLen)
			var name string
			if huffName {
				name = hpackHuffmanDecode(nameRaw)
			} else {
				name = string(nameRaw)
			}
			value, vn := qpackDecodeString(data[pos:])
			if vn == 0 {
				return nil, ErrTruncated
			}
			pos += vn
			headers = append(headers, [2]string{name, value})
		} else {
			pos++
		}
		if len(headers) > 128 {
			return nil, ErrTooManyHeaders
		}
	}
	return headers, nil
}

func qpackDecodeInt(data []byte, prefixBits uint8) (uint64, int) {
	return HpackDecodeInt(data, prefixBits)
}

func qpackDecodeString(data []byte) (string, int) {
	if len(data) == 0 {
		return "", 0
	}
	huffman := data[0]&0x80 != 0
	sLen, n := qpackDecodeInt(data, 7)
	if n == 0 || n+int(sLen) > len(data) {
		return "", 0
	}
	raw := data[n : n+int(sLen)]
	if huffman {
		return hpackHuffmanDecode(raw), n + int(sLen)
	}
	return string(raw), n + int(sLen)
}

var qpackEncodeBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 256); return &b },
}

func qpackEncodeResponseHeaders(status int, contentType string, contentLength int64, headers [][2]string) []byte {
	bp := qpackEncodeBufPool.Get().(*[]byte)
	enc := QPACKEncoder{}
	enc.Reset((*bp)[:0])
	enc.encodeRequiredInsertCount()
	enc.EncodeStatus(status)
	if contentType != "" {
		enc.EncodeHeader("content-type", contentType)
	}
	if contentLength >= 0 {
		var clBuf [20]byte
		clStr := appendUint(clBuf[:0], contentLength)
		nameIdx := qpackFindStaticNameIndex("content-length")
		if nameIdx >= 0 {
			enc.encodeLiteralWithNameRef(nameIdx, UnsafeString(clStr))
		} else {
			enc.encodeLiteral("content-length", UnsafeString(clStr))
		}
	}
	enc.EncodeHeader("server", "ALOS")
	for i := range headers {
		name := headers[i][0]
		if name != "" && name[0] != ':' {
			if low, ok := commonLowerHeader(name); ok {
				enc.EncodeHeader(low, headers[i][1])
			} else {
				enc.EncodeHeader(ToLowerASCII(name), headers[i][1])
			}
		}
	}
	result := make([]byte, len(enc.buf))
	copy(result, enc.buf)
	*bp = enc.buf[:0]
	qpackEncodeBufPool.Put(bp)
	return result
}
