package core

import (
	"strings"
	"sync"
)

const (
	qpackBlockCacheMaxEntries = 1024
	qpackBlockCacheMaxBytes   = 1 << 20
	qpackPrefixCacheMaxEntries = 512
)

type qpackBlockCache struct {
	mu    sync.RWMutex
	m     map[string][][2]string
	bytes int
}

var qpackDecodedBlocks = qpackBlockCache{m: make(map[string][][2]string)}

func (c *qpackBlockCache) get(block []byte) ([][2]string, bool) {
	c.mu.RLock()
	h, ok := c.m[string(block)]
	c.mu.RUnlock()
	return h, ok
}

func (c *qpackBlockCache) put(block []byte, headers [][2]string) {
	cp := make([][2]string, len(headers))
	total := len(block)
	for i, h := range headers {
		n := strings.Clone(h[0])
		v := strings.Clone(h[1])
		cp[i] = [2]string{n, v}
		total += len(n) + len(v)
	}
	c.mu.Lock()
	if len(c.m) < qpackBlockCacheMaxEntries && c.bytes+total <= qpackBlockCacheMaxBytes {
		if _, exists := c.m[string(block)]; !exists {
			c.m[strings.Clone(UnsafeString(block))] = cp
			c.bytes += total
		}
	}
	c.mu.Unlock()
}

type qpackRespPrefixKey struct {
	status int
	ct     string
	server string
}

var (
	qpackRespPrefixMu    sync.RWMutex
	qpackRespPrefixCache = make(map[qpackRespPrefixKey]string)
)

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

// QPACKEncoder encodes HTTP/3 header fields into a QPACK-encoded header
// block (RFC 9204) using the static table only; it does not maintain a
// dynamic table.
type QPACKEncoder struct {
	buf []byte
}

// Reset sets dst as the encoder's output buffer; subsequent Encode calls
// append to it.
func (e *QPACKEncoder) Reset(dst []byte) {
	e.buf = dst
}

// Bytes returns the encoder's current output buffer.
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

// EncodeStatus appends a QPACK-encoded ":status" header field for code. It
// uses the static table's indexed representation when code has a matching
// static-table entry, and otherwise falls back to a literal value with a
// static name reference.
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

// EncodeHeader appends a QPACK-encoded header field for name and value. It
// prefers a full static-table match, then a literal value with a static name
// reference, and falls back to a fully literal representation.
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

// QPACKDecoder decodes QPACK-encoded HTTP/3 header blocks (RFC 9204) using
// the static table only; it does not maintain a dynamic table.
type QPACKDecoder struct{}

var qpackArenaPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 4096); return &b },
}

// Decode decodes a QPACK-encoded header block and returns the resulting
// name/value pairs.
func (d *QPACKDecoder) Decode(data []byte) ([][2]string, error) {
	h, _, err := d.DecodeAppend(data, nil)
	return h, err
}

// DecodeAppend decodes a QPACK-encoded header block and appends the
// resulting name/value pairs to headers. It returns the updated headers
// slice and a pooled buffer holding the decoded string data; the caller must
// return the buffer to qpackArenaPool once done with the decoded strings.
func (d *QPACKDecoder) DecodeAppend(data []byte, headers [][2]string) ([][2]string, *[]byte, error) {
	ap := qpackArenaPool.Get().(*[]byte)
	need := len(data)*8/5 + 16
	if cap(*ap) < need {
		*ap = make([]byte, 0, need)
	}
	arena := (*ap)[:0]

	if len(data) < 2 {
		return headers, ap, ErrTruncated
	}
	pos := 0
	_, n := qpackDecodeInt(data[pos:], 8)
	if n == 0 {
		return headers, ap, ErrTruncated
	}
	pos += n
	_, sn := qpackDecodeInt(data[pos:], 7)
	if sn == 0 {
		return headers, ap, ErrTruncated
	}
	pos += sn

	for pos < len(data) {
		b := data[pos]
		if b&0x80 != 0 {
			static := b&0x40 != 0
			idx, n := qpackDecodeInt(data[pos:], 6)
			if n == 0 {
				return nil, ap, ErrTruncated
			}
			pos += n
			if static {
				if idx >= uint64(len(qpackStaticTable)) {
					return nil, ap, ErrTruncated
				}
				headers = append(headers, qpackStaticTable[idx])
			}
		} else if b&0x40 != 0 {
			nameIsStatic := b&0x10 != 0
			nameIdx, n := qpackDecodeInt(data[pos:], 4)
			if n == 0 {
				return nil, ap, ErrTruncated
			}
			pos += n
			var value string
			var vn int
			value, vn, arena = qpackDecodeStringArena(data[pos:], arena)
			if vn == 0 {
				return nil, ap, ErrTruncated
			}
			pos += vn
			var name string
			if nameIsStatic {
				if nameIdx >= uint64(len(qpackStaticTable)) {
					return nil, ap, ErrTruncated
				}
				name = qpackStaticTable[nameIdx][0]
			}
			headers = append(headers, [2]string{name, value})
		} else if b&0x20 != 0 {
			huffName := b&0x08 != 0
			nameLen, n := qpackDecodeInt(data[pos:], 3)
			if n == 0 {
				return nil, ap, ErrTruncated
			}
			pos += n
			if nameLen > uint64(len(data)) || pos+int(nameLen) > len(data) {
				return nil, ap, ErrTruncated
			}
			nameRaw := data[pos : pos+int(nameLen)]
			pos += int(nameLen)
			var name string
			start := len(arena)
			if huffName {
				arena = hpackHuffmanDecodeInto(arena, nameRaw)
			} else {
				arena = append(arena, nameRaw...)
			}
			name = UnsafeString(arena[start:])
			var value string
			var vn int
			value, vn, arena = qpackDecodeStringArena(data[pos:], arena)
			if vn == 0 {
				return nil, ap, ErrTruncated
			}
			pos += vn
			headers = append(headers, [2]string{name, value})
		} else {
			pos++
		}
		if len(headers) > 128 {
			return nil, ap, ErrTooManyHeaders
		}
	}
	*ap = arena
	return headers, ap, nil
}

func qpackDecodeStringArena(data, arena []byte) (string, int, []byte) {
	if len(data) == 0 {
		return "", 0, arena
	}
	huffman := data[0]&0x80 != 0
	sLen, n := qpackDecodeInt(data, 7)
	if n == 0 || sLen > uint64(len(data)) || n+int(sLen) > len(data) {
		return "", 0, arena
	}
	raw := data[n : n+int(sLen)]
	start := len(arena)
	if huffman {
		arena = hpackHuffmanDecodeInto(arena, raw)
	} else {
		arena = append(arena, raw...)
	}
	return UnsafeString(arena[start:]), n + int(sLen), arena
}

func qpackDecodeInt(data []byte, prefixBits uint8) (uint64, int) {
	return HpackDecodeInt(data, prefixBits)
}


var qpackEncodeBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 256); return &b },
}

func qpackEncodeResponseHeaders(status int, contentType string, contentLength int64, headers [][2]string, serverName string) *[]byte {
	bp := qpackEncodeBufPool.Get().(*[]byte)
	enc := QPACKEncoder{}
	enc.Reset((*bp)[:0])
	key := qpackRespPrefixKey{status: status, ct: contentType, server: serverName}
	qpackRespPrefixMu.RLock()
	prefix, ok := qpackRespPrefixCache[key]
	qpackRespPrefixMu.RUnlock()
	if ok {
		enc.buf = append(enc.buf, prefix...)
	} else {
		enc.encodeRequiredInsertCount()
		enc.EncodeStatus(status)
		if contentType != "" {
			enc.EncodeHeader("content-type", contentType)
		}
		enc.EncodeHeader("server", serverName)
		p := string(enc.buf)
		qpackRespPrefixMu.Lock()
		if len(qpackRespPrefixCache) < qpackPrefixCacheMaxEntries {
			ck := qpackRespPrefixKey{status: status, ct: strings.Clone(contentType), server: strings.Clone(serverName)}
			qpackRespPrefixCache[ck] = p
		}
		qpackRespPrefixMu.Unlock()
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
	*bp = enc.buf
	return bp
}
