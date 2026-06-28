package core

import "github.com/zeebo/xxh3"

var HpackStaticTable = [62][2]string{
	{},
	{":authority", ""},
	{":method", "GET"},
	{":method", "POST"},
	{":path", "/"},
	{":path", "/index.html"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "200"},
	{":status", "204"},
	{":status", "206"},
	{":status", "304"},
	{":status", "400"},
	{":status", "404"},
	{":status", "500"},
	{"accept-charset", ""},
	{"accept-encoding", "gzip, deflate"},
	{"accept-language", ""},
	{"accept-ranges", ""},
	{"accept", ""},
	{"access-control-allow-origin", ""},
	{"age", ""},
	{"allow", ""},
	{"authorization", ""},
	{"cache-control", ""},
	{"content-disposition", ""},
	{"content-encoding", ""},
	{"content-language", ""},
	{"content-length", ""},
	{"content-location", ""},
	{"content-range", ""},
	{"content-type", ""},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"expect", ""},
	{"expires", ""},
	{"from", ""},
	{"host", ""},
	{"if-match", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"if-range", ""},
	{"if-unmodified-since", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"max-forwards", ""},
	{"proxy-authenticate", ""},
	{"proxy-authorization", ""},
	{"range", ""},
	{"referer", ""},
	{"refresh", ""},
	{"retry-after", ""},
	{"server", ""},
	{"set-cookie", ""},
	{"strict-transport-security", ""},
	{"transfer-encoding", ""},
	{"user-agent", ""},
	{"vary", ""},
	{"via", ""},
	{"www-authenticate", ""},
}

type HpackEncoder struct {
	Buf []byte
}

func (e *HpackEncoder) Reset(dst []byte) {
	e.Buf = dst
}

func (e *HpackEncoder) EncodeInt(prefix byte, prefixBits uint8, val uint64) {
	maxFirst := uint64((1 << prefixBits) - 1)
	if val < maxFirst {
		e.Buf = append(e.Buf, prefix|byte(val))
		return
	}
	e.Buf = append(e.Buf, prefix|byte(maxFirst))
	val -= maxFirst
	for val >= 128 {
		e.Buf = append(e.Buf, byte(val&0x7f)|0x80)
		val >>= 7
	}
	e.Buf = append(e.Buf, byte(val))
}

var huffBitLen [256]uint16

func init() {
	for i := 0; i < 256; i++ {
		huffBitLen[i] = uint16(huffmanCodes[i].bits)
	}
}

func hpackHuffmanEncodedLen(s string) int {
	var bits int
	l := len(s)
	i := 0
	for ; i+3 < l; i += 4 {
		bits += int(huffBitLen[s[i]]) + int(huffBitLen[s[i+1]]) + int(huffBitLen[s[i+2]]) + int(huffBitLen[s[i+3]])
	}
	for ; i < l; i++ {
		bits += int(huffBitLen[s[i]])
	}
	return (bits + 7) / 8
}

func hpackHuffmanAppend(dst []byte, s string) []byte {
	var cur uint64
	var nbits uint8
	for i := 0; i < len(s); i++ {
		entry := huffmanCodes[s[i]]
		cur = cur<<entry.bits | uint64(entry.code)
		nbits += entry.bits
		for nbits >= 8 {
			nbits -= 8
			dst = append(dst, byte(cur>>nbits))
		}
	}
	if nbits > 0 {
		dst = append(dst, byte(cur<<(8-nbits)|uint64(0xff>>(nbits))))
	}
	return dst
}

func (e *HpackEncoder) EncodeString(s string) {
	huffLen := hpackHuffmanEncodedLen(s)
	if huffLen < len(s) {
		e.EncodeInt(0x80, 7, uint64(huffLen))
		e.Buf = hpackHuffmanAppend(e.Buf, s)
	} else {
		e.EncodeInt(0x00, 7, uint64(len(s)))
		e.Buf = append(e.Buf, s...)
	}
}

func (e *HpackEncoder) EncodeHeader(name, value string) {
	name = ToLowerASCII(name)
	idx := hpackFindStaticName(name)
	if idx > 0 {
		e.EncodeInt(0x00, 4, uint64(idx))
		e.EncodeString(value)
	} else {
		e.Buf = append(e.Buf, 0x00)
		e.EncodeString(name)
		e.EncodeString(value)
	}
}

func (e *HpackEncoder) EncodeHeaderFold(name, value string) {
	idx := hpackFindStaticNameFold(name)
	if idx > 0 {
		e.EncodeInt(0x00, 4, uint64(idx))
		e.EncodeString(value)
	} else {
		e.Buf = append(e.Buf, 0x00)
		e.encodeStringLower(name)
		e.EncodeString(value)
	}
}

func hpackFindStaticNameFold(name string) int {
	switch len(name) {
	case 3:
		if EqualFoldASCII(name, "age") {
			return 21
		}
		if EqualFoldASCII(name, "via") {
			return 60
		}
	case 4:
		if EqualFoldASCII(name, "date") {
			return 33
		}
		if EqualFoldASCII(name, "etag") {
			return 34
		}
		if EqualFoldASCII(name, "from") {
			return 37
		}
		if EqualFoldASCII(name, "host") {
			return 38
		}
		if EqualFoldASCII(name, "link") {
			return 45
		}
		if EqualFoldASCII(name, "vary") {
			return 59
		}
	case 5:
		if name[0] == ':' {
			if EqualFoldASCII(name, ":path") {
				return 4
			}
		} else {
			if EqualFoldASCII(name, "allow") {
				return 22
			}
			if EqualFoldASCII(name, "range") {
				return 50
			}
		}
	case 6:
		if EqualFoldASCII(name, "accept") {
			return 19
		}
		if EqualFoldASCII(name, "cookie") {
			return 32
		}
		if EqualFoldASCII(name, "expect") {
			return 35
		}
		if EqualFoldASCII(name, "server") {
			return 54
		}
	case 7:
		if name[0] == ':' {
			if EqualFoldASCII(name, ":method") {
				return 2
			}
			if EqualFoldASCII(name, ":scheme") {
				return 6
			}
			if EqualFoldASCII(name, ":status") {
				return 8
			}
		} else {
			if EqualFoldASCII(name, "expires") {
				return 36
			}
			if EqualFoldASCII(name, "referer") {
				return 51
			}
			if EqualFoldASCII(name, "refresh") {
				return 52
			}
		}
	case 8:
		if EqualFoldASCII(name, "if-match") {
			return 39
		}
		if EqualFoldASCII(name, "if-range") {
			return 42
		}
		if EqualFoldASCII(name, "location") {
			return 46
		}
	case 10:
		if name[0] == ':' {
			if EqualFoldASCII(name, ":authority") {
				return 1
			}
		} else {
			if EqualFoldASCII(name, "set-cookie") {
				return 55
			}
			if EqualFoldASCII(name, "user-agent") {
				return 58
			}
		}
	case 11:
		if EqualFoldASCII(name, "retry-after") {
			return 53
		}
	case 12:
		if EqualFoldASCII(name, "content-type") {
			return 31
		}
		if EqualFoldASCII(name, "max-forwards") {
			return 47
		}
	case 13:
		if EqualFoldASCII(name, "accept-ranges") {
			return 18
		}
		if EqualFoldASCII(name, "authorization") {
			return 23
		}
		if EqualFoldASCII(name, "cache-control") {
			return 24
		}
		if EqualFoldASCII(name, "content-range") {
			return 30
		}
		if EqualFoldASCII(name, "if-none-match") {
			return 41
		}
		if EqualFoldASCII(name, "last-modified") {
			return 44
		}
	case 14:
		if EqualFoldASCII(name, "accept-charset") {
			return 15
		}
		if EqualFoldASCII(name, "content-length") {
			return 28
		}
	case 15:
		if EqualFoldASCII(name, "accept-encoding") {
			return 16
		}
		if EqualFoldASCII(name, "accept-language") {
			return 17
		}
	case 16:
		if EqualFoldASCII(name, "content-encoding") {
			return 26
		}
		if EqualFoldASCII(name, "content-language") {
			return 27
		}
		if EqualFoldASCII(name, "content-location") {
			return 29
		}
		if EqualFoldASCII(name, "www-authenticate") {
			return 61
		}
	case 17:
		if EqualFoldASCII(name, "if-modified-since") {
			return 40
		}
		if EqualFoldASCII(name, "transfer-encoding") {
			return 57
		}
	case 18:
		if EqualFoldASCII(name, "proxy-authenticate") {
			return 48
		}
	case 19:
		if EqualFoldASCII(name, "content-disposition") {
			return 25
		}
		if EqualFoldASCII(name, "if-unmodified-since") {
			return 43
		}
		if EqualFoldASCII(name, "proxy-authorization") {
			return 49
		}
	case 25:
		if EqualFoldASCII(name, "strict-transport-security") {
			return 56
		}
	case 27:
		if EqualFoldASCII(name, "access-control-allow-origin") {
			return 20
		}
	}
	return 0
}

func (e *HpackEncoder) encodeStringLower(s string) {
	n := len(s)
	var bits int
	for i := 0; i < n; i++ {
		bits += int(huffBitLen[asciiLower[s[i]]])
	}
	huffLen := (bits + 7) / 8

	if huffLen < n {
		e.EncodeInt(0x80, 7, uint64(huffLen))
		var cur uint64
		var nbits uint8
		for i := 0; i < n; i++ {
			entry := huffmanCodes[asciiLower[s[i]]]
			cur = cur<<entry.bits | uint64(entry.code)
			nbits += entry.bits
			for nbits >= 8 {
				nbits -= 8
				e.Buf = append(e.Buf, byte(cur>>nbits))
			}
		}
		if nbits > 0 {
			e.Buf = append(e.Buf, byte(cur<<(8-nbits)|uint64(0xff>>(nbits))))
		}
	} else {
		e.EncodeInt(0x00, 7, uint64(n))
		for i := 0; i < n; i++ {
			e.Buf = append(e.Buf, asciiLower[s[i]])
		}
	}
}

func (e *HpackEncoder) EncodeIndexed(idx uint64) {
	e.EncodeInt(0x80, 7, idx)
}

func (e *HpackEncoder) EncodeStatus(code int) {
	switch code {
	case 200:
		e.EncodeIndexed(8)
	case 204:
		e.EncodeIndexed(9)
	case 206:
		e.EncodeIndexed(10)
	case 304:
		e.EncodeIndexed(11)
	case 400:
		e.EncodeIndexed(12)
	case 404:
		e.EncodeIndexed(13)
	case 500:
		e.EncodeIndexed(14)
	default:
		e.EncodeInt(0x00, 4, 8)
		var tmp [4]byte
		s := appendUint(tmp[:0], int64(code))
		e.EncodeInt(0x00, 7, uint64(len(s)))
		e.Buf = append(e.Buf, s...)
	}
}

func init() {
	buildHuffmanDecodeTable()
}

var hpackStaticNameMap map[string]int

func init() {
	hpackStaticNameMap = make(map[string]int, 48)
	for i := 1; i < len(HpackStaticTable); i++ {
		name := HpackStaticTable[i][0]
		if _, exists := hpackStaticNameMap[name]; !exists {
			hpackStaticNameMap[name] = i
		}
	}
}

func hpackFindStaticName(name string) int {
	switch name {
	case ":authority":
		return 1
	case ":method":
		return 2
	case ":path":
		return 4
	case ":scheme":
		return 6
	case "content-length":
		return 28
	case "content-type":
		return 31
	case "server":
		return 54
	}
	if idx, ok := hpackStaticNameMap[name]; ok {
		return idx
	}
	return 0
}

type hpackDynEntry struct {
	name  string
	value string
	size  int
}

type hpackDecoderSnapshot struct {
	maxTableSize    int
	protocolMaxSize int
	dynSize         int
	entries         []hpackDynEntry
}

const (
	hpackHuffmanDecodeCacheSize = 64
	hpackHuffmanDecodeInlineMax = 64
)

type hpackHuffmanDecodeCacheEntry struct {
	used   bool
	hash   uint64
	size   uint32
	value  string
	heap   []byte
	inline [hpackHuffmanDecodeInlineMax]byte
}

func hpackHashBytes(data []byte) uint64 {
	return xxh3.Hash(data)
}

func (e *hpackHuffmanDecodeCacheEntry) match(hash uint64, data []byte) bool {
	if !e.used || e.hash != hash || int(e.size) != len(data) {
		return false
	}
	if len(data) <= len(e.inline) {
		for i := range data {
			if e.inline[i] != data[i] {
				return false
			}
		}
		return true
	}
	if len(e.heap) < len(data) {
		return false
	}
	for i := range data {
		if e.heap[i] != data[i] {
			return false
		}
	}
	return true
}

func (e *hpackHuffmanDecodeCacheEntry) store(hash uint64, data []byte, value string) {
	e.used = true
	e.hash = hash
	e.size = uint32(len(data))
	e.value = value
	if len(data) <= len(e.inline) {
		copy(e.inline[:], data)
		e.heap = nil
		return
	}
	if cap(e.heap) < len(data) {
		e.heap = make([]byte, len(data))
	} else {
		e.heap = e.heap[:len(data)]
	}
	copy(e.heap, data)
}

type HpackDecoder struct {
	maxTableSize     int
	protocolMaxSize  int
	dynRing          [128]hpackDynEntry
	dynHead          int
	dynLen           int
	dynSize          int
	huffmanCache     [hpackHuffmanDecodeCacheSize]hpackHuffmanDecodeCacheEntry
	huffmanCacheNext uint8
}

func NewHpackDecoder() *HpackDecoder {
	return &HpackDecoder{
		maxTableSize:    H2HeaderTableSize,
		protocolMaxSize: H2HeaderTableSize,
	}
}

func (d *HpackDecoder) snapshot() hpackDecoderSnapshot {
	snap := hpackDecoderSnapshot{
		maxTableSize:    d.maxTableSize,
		protocolMaxSize: d.protocolMaxSize,
		dynSize:         d.dynSize,
	}
	if d.dynLen > 0 {
		snap.entries = make([]hpackDynEntry, d.dynLen)
		for i := 0; i < d.dynLen; i++ {
			snap.entries[i] = *d.dynGet(i)
		}
	}
	return snap
}

func (d *HpackDecoder) restore(snap hpackDecoderSnapshot) {
	cache := d.huffmanCache
	cacheNext := d.huffmanCacheNext
	*d = HpackDecoder{
		maxTableSize:    snap.maxTableSize,
		protocolMaxSize: snap.protocolMaxSize,
		dynSize:         snap.dynSize,
		dynLen:          len(snap.entries),
	}
	d.huffmanCache = cache
	d.huffmanCacheNext = cacheNext
	for i := range snap.entries {
		d.dynRing[i] = snap.entries[i]
	}
}

func (d *HpackDecoder) decodeString(data []byte) (string, int) {
	if len(data) == 0 {
		return "", 0
	}
	huffman := data[0]&0x80 != 0
	sLen, n := HpackDecodeInt(data, 7)
	if sLen > uint64(len(data)) || n+int(sLen) > len(data) {
		return "", 0
	}
	raw := data[n : n+int(sLen)]
	if !huffman {
		return string(raw), n + int(sLen)
	}
	hash := hpackHashBytes(raw)
	for i := range d.huffmanCache {
		if d.huffmanCache[i].match(hash, raw) {
			return d.huffmanCache[i].value, n + int(sLen)
		}
	}
	decoded := hpackHuffmanDecode(raw)
	slot := int(d.huffmanCacheNext) % len(d.huffmanCache)
	d.huffmanCacheNext++
	d.huffmanCache[slot].store(hash, raw, decoded)
	return decoded, n + int(sLen)
}

func (d *HpackDecoder) dynGet(i int) *hpackDynEntry {
	return &d.dynRing[(d.dynHead+i)%len(d.dynRing)]
}

func (d *HpackDecoder) lookupIndex(idx uint64) (string, string, bool) {
	if idx == 0 {
		return "", "", false
	}
	if idx < uint64(len(HpackStaticTable)) {
		return HpackStaticTable[idx][0], HpackStaticTable[idx][1], true
	}
	dynIdx := int(idx) - len(HpackStaticTable)
	if dynIdx >= 0 && dynIdx < d.dynLen {
		e := d.dynGet(dynIdx)
		return e.name, e.value, true
	}
	return "", "", false
}

func (d *HpackDecoder) lookupName(idx uint64) (string, bool) {
	if idx == 0 {
		return "", false
	}
	if idx < uint64(len(HpackStaticTable)) {
		return HpackStaticTable[idx][0], true
	}
	dynIdx := int(idx) - len(HpackStaticTable)
	if dynIdx >= 0 && dynIdx < d.dynLen {
		return d.dynGet(dynIdx).name, true
	}
	return "", false
}

func (d *HpackDecoder) addEntry(name, value string) {
	entrySize := 32 + len(name) + len(value)
	for d.dynSize+entrySize > d.maxTableSize && d.dynLen > 0 {
		tail := d.dynGet(d.dynLen - 1)
		d.dynSize -= tail.size
		*tail = hpackDynEntry{}
		d.dynLen--
	}
	if entrySize <= d.maxTableSize && d.dynLen < len(d.dynRing) {
		d.dynHead = (d.dynHead - 1 + len(d.dynRing)) % len(d.dynRing)
		d.dynRing[d.dynHead] = hpackDynEntry{name: name, value: value, size: entrySize}
		d.dynLen++
		d.dynSize += entrySize
	}
}

func (d *HpackDecoder) setMaxSize(maxSize int) {
	d.maxTableSize = maxSize
	for d.dynSize > d.maxTableSize && d.dynLen > 0 {
		tail := d.dynGet(d.dynLen - 1)
		d.dynSize -= tail.size
		*tail = hpackDynEntry{}
		d.dynLen--
	}
}

func (d *HpackDecoder) Decode(data []byte) ([][2]string, error) {
	return d.DecodeInto(nil, data)
}

func (d *HpackDecoder) DecodeInto(headers [][2]string, data []byte) ([][2]string, error) {
	const maxHeaders = 128
	if headers == nil {
		headers = make([][2]string, 0, 16)
	}
	headers = headers[:0]
	pos := 0
	for pos < len(data) {
		b := data[pos]
		if b&0x80 != 0 {
			idx, n := HpackDecodeInt(data[pos:], 7)
			if n <= 0 {
				return nil, ErrH2BadHeader
			}
			pos += n
			name, value, ok := d.lookupIndex(idx)
			if !ok {
				return nil, ErrH2BadHeader
			}
			headers = append(headers, [2]string{name, value})
			if len(headers) > maxHeaders {
				return nil, ErrTooManyHeaders
			}
		} else if b&0x40 != 0 {
			idx, n := HpackDecodeInt(data[pos:], 6)
			if n <= 0 {
				return nil, ErrH2BadHeader
			}
			pos += n
			var name string
			if idx > 0 {
				var ok bool
				name, ok = d.lookupName(idx)
				if !ok {
					return nil, ErrH2BadHeader
				}
			} else {
				name, n = d.decodeString(data[pos:])
				if n <= 0 {
					return nil, ErrH2BadHeader
				}
				pos += n
			}
			val, n := d.decodeString(data[pos:])
			if n <= 0 {
				return nil, ErrH2BadHeader
			}
			pos += n
			headers = append(headers, [2]string{name, val})
			if len(headers) > maxHeaders {
				return nil, ErrTooManyHeaders
			}
			d.addEntry(name, val)
		} else if b&0x20 != 0 {
			maxSize, n := HpackDecodeInt(data[pos:], 5)
			if n <= 0 {
				return nil, ErrH2BadHeader
			}
			pos += n
			if int(maxSize) > d.protocolMaxSize {
				return nil, ErrHpackTableSizeExceeded
			}
			d.setMaxSize(int(maxSize))
		} else {
			idx, n := HpackDecodeInt(data[pos:], 4)
			if n <= 0 {
				return nil, ErrH2BadHeader
			}
			pos += n
			var name string
			if idx > 0 {
				var ok bool
				name, ok = d.lookupName(idx)
				if !ok {
					return nil, ErrH2BadHeader
				}
			} else {
				name, n = d.decodeString(data[pos:])
				if n <= 0 {
					return nil, ErrH2BadHeader
				}
				pos += n
			}
			val, n := d.decodeString(data[pos:])
			if n <= 0 {
				return nil, ErrH2BadHeader
			}
			pos += n
			headers = append(headers, [2]string{name, val})
			if len(headers) > maxHeaders {
				return nil, ErrTooManyHeaders
			}
		}
	}
	return headers, nil
}

func (d *HpackDecoder) DecodeIntoRequest(headers [][2]string, data []byte) ([][2]string, hpackRequestMeta, error) {
	const maxHeaders = 128
	var meta hpackRequestMeta
	if headers, meta, ok, err := decodeSimpleGetPathHTTPSRequest(d, headers, data); ok {
		return headers, meta, err
	}
	if headers == nil {
		headers = make([][2]string, 0, 16)
	}
	headers = headers[:0]
	pos := 0
	for pos < len(data) {
		b := data[pos]
		if b&0x80 != 0 {
			idx, n := HpackDecodeInt(data[pos:], 7)
			if n <= 0 {
				return nil, meta, ErrH2BadHeader
			}
			pos += n
			name, value, ok := d.lookupIndex(idx)
			if !ok {
				return nil, meta, ErrH2BadHeader
			}
			if err := meta.observeHeader(name, value); err != nil {
				return nil, meta, err
			}
			headers = append(headers, [2]string{name, value})
			meta.headerCount++
		} else if b&0x40 != 0 {
			idx, n := HpackDecodeInt(data[pos:], 6)
			if n <= 0 {
				return nil, meta, ErrH2BadHeader
			}
			pos += n
			var (
				name string
				ok   bool
			)
			if idx > 0 {
				name, ok = d.lookupName(idx)
				if !ok {
					return nil, meta, ErrH2BadHeader
				}
			} else {
				name, n = d.decodeString(data[pos:])
				if n <= 0 {
					return nil, meta, ErrH2BadHeader
				}
				pos += n
			}
			value, n := d.decodeString(data[pos:])
			if n <= 0 {
				return nil, meta, ErrH2BadHeader
			}
			pos += n
			if err := meta.observeHeader(name, value); err != nil {
				return nil, meta, err
			}
			headers = append(headers, [2]string{name, value})
			meta.headerCount++
			d.addEntry(name, value)
		} else if b&0x20 != 0 {
			maxSize, n := HpackDecodeInt(data[pos:], 5)
			if n <= 0 {
				return nil, meta, ErrH2BadHeader
			}
			pos += n
			if int(maxSize) > d.protocolMaxSize {
				return nil, meta, ErrHpackTableSizeExceeded
			}
			d.setMaxSize(int(maxSize))
		} else {
			idx, n := HpackDecodeInt(data[pos:], 4)
			if n <= 0 {
				return nil, meta, ErrH2BadHeader
			}
			pos += n
			var (
				name string
				ok   bool
			)
			if idx > 0 {
				name, ok = d.lookupName(idx)
				if !ok {
					return nil, meta, ErrH2BadHeader
				}
			} else {
				name, n = d.decodeString(data[pos:])
				if n <= 0 {
					return nil, meta, ErrH2BadHeader
				}
				pos += n
			}
			value, n := d.decodeString(data[pos:])
			if n <= 0 {
				return nil, meta, ErrH2BadHeader
			}
			pos += n
			if err := meta.observeHeader(name, value); err != nil {
				return nil, meta, err
			}
			headers = append(headers, [2]string{name, value})
			meta.headerCount++
		}
		if len(headers) > maxHeaders {
			return nil, meta, ErrTooManyHeaders
		}
	}
	if err := meta.validate(); err != nil {
		return nil, meta, err
	}
	return headers, meta, nil
}

func decodeSimpleGetPathHTTPSRequest(d *HpackDecoder, headers [][2]string, data []byte) ([][2]string, hpackRequestMeta, bool, error) {
	var meta hpackRequestMeta
	if len(data) < 4 || data[0] != 0x82 || data[1] != 0x04 || data[len(data)-1] != 0x87 {
		return headers, meta, false, nil
	}
	path, n := d.decodeString(data[2:])
	if n <= 0 || 2+n+1 != len(data) {
		return nil, meta, true, ErrH2BadHeader
	}
	if headers == nil {
		headers = make([][2]string, 0, 3)
	}
	headers = headers[:0]
	rawPath := path
	path = sanitizeRequestPath(path)
	_, query := splitPathQuery(rawPath)
	headers = append(headers,
		[2]string{":method", "GET"},
		[2]string{":path", path},
		[2]string{":scheme", "https"},
	)
	meta.method = "GET"
	meta.path = path
	meta.rawPath = rawPath
	meta.query = query
	meta.scheme = "https"
	meta.headerCount = 3
	return headers, meta, true, nil
}

type hpackRequestMeta struct {
	method      string
	path        string
	rawPath     string
	query       string
	scheme      string
	authority   string
	headerCount int
	pseudoMask  uint8
	sawRegular  bool
}

const (
	hpackPseudoMethod uint8 = 1 << iota
	hpackPseudoScheme
	hpackPseudoPath
	hpackPseudoAuthority
)

var h2FieldNameValid [256]bool

func init() {
	for i := 0x21; i < 0x7f; i++ {
		if i != ':' && !(i >= 'A' && i <= 'Z') {
			h2FieldNameValid[i] = true
		}
	}
}

func isValidH2FieldName(name string) bool {
	if name == "" {
		return false
	}
	start := 0
	if name[0] == ':' {
		if len(name) == 1 {
			return false
		}
		start = 1
	}
	for i := start; i < len(name); i++ {
		if !h2FieldNameValid[name[i]] {
			return false
		}
	}
	return true
}

var h2FieldValueInvalid [256]bool

func init() {
	h2FieldValueInvalid[0] = true
	h2FieldValueInvalid['\r'] = true
	h2FieldValueInvalid['\n'] = true
}

func isValidH2FieldValue(value string) bool {
	if len(value) > 0 {
		if value[0] == ' ' || value[0] == '\t' || value[len(value)-1] == ' ' || value[len(value)-1] == '\t' {
			return false
		}
	}
	for i := 0; i < len(value); i++ {
		if h2FieldValueInvalid[value[i]] {
			return false
		}
	}
	return true
}

func isH2ConnectionSpecificField(name, value string) bool {
	switch name {
	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
		return true
	case "te":
		return !EqualFoldASCII(value, "trailers")
	default:
		return false
	}
}

func (meta *hpackRequestMeta) observeHeader(name, value string) error {
	if !isValidH2FieldName(name) || !isValidH2FieldValue(value) {
		return ErrH2BadHeader
	}
	if name[0] == ':' {
		if meta.sawRegular {
			return ErrH2BadHeader
		}
		switch name {
		case ":method":
			if meta.pseudoMask&hpackPseudoMethod != 0 {
				return ErrH2BadHeader
			}
			meta.pseudoMask |= hpackPseudoMethod
			meta.method = value
		case ":scheme":
			if meta.pseudoMask&hpackPseudoScheme != 0 {
				return ErrH2BadHeader
			}
			meta.pseudoMask |= hpackPseudoScheme
			meta.scheme = value
		case ":path":
			if meta.pseudoMask&hpackPseudoPath != 0 {
				return ErrH2BadHeader
			}
			meta.pseudoMask |= hpackPseudoPath
			meta.rawPath = value
			_, meta.query = splitPathQuery(value)
			if value == "/" {
				meta.path = "/"
			} else {
				meta.path = sanitizeRequestPath(value)
			}
		case ":authority":
			if meta.pseudoMask&hpackPseudoAuthority != 0 {
				return ErrH2BadHeader
			}
			if !ValidateHost(value) {
				return ErrH2BadHeader
			}
			meta.pseudoMask |= hpackPseudoAuthority
			meta.authority = value
		default:
			return ErrH2BadHeader
		}
		return nil
	}
	meta.sawRegular = true
	if isH2ConnectionSpecificField(name, value) {
		return ErrH2BadHeader
	}
	return nil
}

func (meta hpackRequestMeta) validate() error {
	if meta.method == "CONNECT" {
		if meta.authority == "" || meta.scheme != "" || meta.path != "" {
			return ErrH2BadHeader
		}
		return nil
	}
	if meta.method == "" || meta.scheme == "" || meta.path == "" {
		return ErrH2BadHeader
	}
	return nil
}

func hpackSkipString(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, ErrH2BadHeader
	}
	sLen, n := HpackDecodeInt(data, 7)
	if n <= 0 || sLen > uint64(len(data)) || n+int(sLen) > len(data) {
		return 0, ErrH2BadHeader
	}
	return n + int(sLen), nil
}

func (d *HpackDecoder) decodeStringSelective(data []byte, want bool) (string, int, error) {
	if len(data) == 0 {
		return "", 0, ErrH2BadHeader
	}
	if !want {
		n, err := hpackSkipString(data)
		return "", n, err
	}
	str, n := d.decodeString(data)
	if n <= 0 || n > len(data) {
		return "", 0, ErrH2BadHeader
	}
	return str, n, nil
}

func (d *HpackDecoder) DecodeRequestMeta(data []byte) (hpackRequestMeta, error) {
	const maxHeaders = 128
	var meta hpackRequestMeta
	pos := 0
	for pos < len(data) {
		b := data[pos]
		if b&0x80 != 0 {
			idx, n := HpackDecodeInt(data[pos:], 7)
			if n <= 0 {
				return meta, ErrH2BadHeader
			}
			pos += n
			name, value, ok := d.lookupIndex(idx)
			if !ok {
				return meta, ErrH2BadHeader
			}
			if err := meta.observeHeader(name, value); err != nil {
				return meta, err
			}
			meta.headerCount++
		} else if b&0x40 != 0 {
			idx, n := HpackDecodeInt(data[pos:], 6)
			if n <= 0 {
				return meta, ErrH2BadHeader
			}
			pos += n
			var name string
			var ok bool
			if idx > 0 {
				name, ok = d.lookupName(idx)
				if !ok {
					return meta, ErrH2BadHeader
				}
			} else {
				var err error
				name, n, err = d.decodeStringSelective(data[pos:], true)
				if err != nil {
					return meta, err
				}
				pos += n
			}
			value, n, err := d.decodeStringSelective(data[pos:], true)
			if err != nil {
				return meta, err
			}
			pos += n
			if err := meta.observeHeader(name, value); err != nil {
				return meta, err
			}
			meta.headerCount++
			d.addEntry(name, value)
		} else if b&0x20 != 0 {
			maxSize, n := HpackDecodeInt(data[pos:], 5)
			if n <= 0 {
				return meta, ErrH2BadHeader
			}
			pos += n
			if int(maxSize) > d.protocolMaxSize {
				return meta, ErrHpackTableSizeExceeded
			}
			d.setMaxSize(int(maxSize))
		} else {
			idx, n := HpackDecodeInt(data[pos:], 4)
			if n <= 0 {
				return meta, ErrH2BadHeader
			}
			pos += n
			var (
				name string
				ok   bool
			)
			if idx > 0 {
				name, ok = d.lookupName(idx)
				if !ok {
					return meta, ErrH2BadHeader
				}
			} else {
				var err error
				name, n, err = d.decodeStringSelective(data[pos:], true)
				if err != nil {
					return meta, err
				}
				pos += n
			}
			wantValue := name == ":method" || name == ":path" || name == ":scheme" || name == ":authority"
			value, n, err := d.decodeStringSelective(data[pos:], wantValue)
			if err != nil {
				return meta, err
			}
			pos += n
			if err := meta.observeHeader(name, value); err != nil {
				return meta, err
			}
			meta.headerCount++
		}
		if meta.headerCount > maxHeaders {
			return meta, ErrTooManyHeaders
		}
	}
	if err := meta.validate(); err != nil {
		return meta, err
	}
	return meta, nil
}

func (d *HpackDecoder) DecodeFastRootRequest(data []byte) (hpackRequestMeta, bool, error) {
	if len(data) >= 4 && data[0] == 0x82 && data[1] == 0x04 && data[len(data)-1] == 0x87 {
		meta, err := d.DecodeRequestMeta(data)
		if err == nil && meta.method == "GET" && meta.path == "/" {
			return meta, true, nil
		}
		return meta, false, err
	}
	snap := d.snapshot()
	meta, err := d.DecodeRequestMeta(data)
	if err != nil {
		d.restore(snap)
		return meta, false, err
	}
	if meta.method == "GET" && meta.path == "/" {
		return meta, true, nil
	}
	d.restore(snap)
	return meta, false, nil
}

func HpackDecodeInt(data []byte, prefixBits uint8) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	mask := byte((1 << prefixBits) - 1)
	val := uint64(data[0] & mask)
	if val < uint64(mask) {
		return val, 1
	}
	m := uint64(0)
	i := 1
	for i < len(data) {
		b := data[i]
		i++
		if m > 63 {
			return 0, 0
		}
		val += uint64(b&0x7f) << m
		m += 7
		if b&0x80 == 0 {
			return val, i
		}
	}
	return 0, 0
}

func HpackDecodeString(data []byte) (string, int) {
	if len(data) == 0 {
		return "", 0
	}
	huffman := data[0]&0x80 != 0
	sLen, n := HpackDecodeInt(data, 7)
	if sLen > uint64(len(data)) || n+int(sLen) > len(data) {
		return "", 0
	}
	raw := data[n : n+int(sLen)]
	if huffman {
		decoded := hpackHuffmanDecode(raw)
		return decoded, n + int(sLen)
	}
	return string(raw), n + int(sLen)
}

func hpackHuffmanDecode(src []byte) string {
	var stackBuf [256]byte
	var dst []byte
	if len(src)*2 <= len(stackBuf) {
		dst = stackBuf[:0]
	} else {
		bp := MediumBufPool.Get().(*[]byte)
		dst = (*bp)[:0]
		defer func() {
			*bp = dst[:0]
			MediumBufPool.Put(bp)
		}()
	}
	var bits uint64
	var nbits uint8

	for _, b := range src {
		bits = bits<<8 | uint64(b)
		nbits += 8
		for nbits >= 5 {
			decoded, codeLen := huffmanLookup(bits, nbits)
			if codeLen == 0 {
				break
			}
			dst = append(dst, decoded)
			nbits -= codeLen
			bits &= (1 << nbits) - 1
		}
	}

	return string(dst)
}

var huffmanCodes = [257]struct {
	code uint32
	bits uint8
}{
	{0x1ff8, 13}, {0x7fffd8, 23}, {0xfffffe2, 28}, {0xfffffe3, 28},
	{0xfffffe4, 28}, {0xfffffe5, 28}, {0xfffffe6, 28}, {0xfffffe7, 28},
	{0xfffffe8, 28}, {0xffffea, 24}, {0x3ffffffc, 30}, {0xfffffe9, 28},
	{0xfffffea, 28}, {0x3ffffffd, 30}, {0xfffffeb, 28}, {0xfffffec, 28},
	{0xfffffed, 28}, {0xfffffee, 28}, {0xfffffef, 28}, {0xffffff0, 28},
	{0xffffff1, 28}, {0xffffff2, 28}, {0x3ffffffe, 30}, {0xffffff3, 28},
	{0xffffff4, 28}, {0xffffff5, 28}, {0xffffff6, 28}, {0xffffff7, 28},
	{0xffffff8, 28}, {0xffffff9, 28}, {0xffffffa, 28}, {0xffffffb, 28},
	{0x14, 6}, {0x3f8, 10}, {0x3f9, 10}, {0xffa, 12},
	{0x1ff9, 13}, {0x15, 6}, {0xf8, 8}, {0x7fa, 11},
	{0x3fa, 10}, {0x3fb, 10}, {0xf9, 8}, {0x7fb, 11},
	{0xfa, 8}, {0x16, 6}, {0x17, 6}, {0x18, 6},
	{0x0, 5}, {0x1, 5}, {0x2, 5}, {0x19, 6},
	{0x1a, 6}, {0x1b, 6}, {0x1c, 6}, {0x1d, 6},
	{0x1e, 6}, {0x1f, 6}, {0x5c, 7}, {0xfb, 8},
	{0x7ffc, 15}, {0x20, 6}, {0xffb, 12}, {0x3fc, 10},
	{0x1ffa, 13}, {0x21, 6}, {0x5d, 7}, {0x5e, 7},
	{0x5f, 7}, {0x60, 7}, {0x61, 7}, {0x62, 7},
	{0x63, 7}, {0x64, 7}, {0x65, 7}, {0x66, 7},
	{0x67, 7}, {0x68, 7}, {0x69, 7}, {0x6a, 7},
	{0x6b, 7}, {0x6c, 7}, {0x6d, 7}, {0x6e, 7},
	{0x6f, 7}, {0x70, 7}, {0x71, 7}, {0x72, 7},
	{0xfc, 8}, {0x73, 7}, {0xfd, 8}, {0x1ffb, 13},
	{0x7fff0, 19}, {0x1ffc, 13}, {0x3ffc, 14}, {0x22, 6},
	{0x7ffd, 15}, {0x3, 5}, {0x23, 6}, {0x4, 5},
	{0x24, 6}, {0x5, 5}, {0x25, 6}, {0x26, 6},
	{0x27, 6}, {0x6, 5}, {0x74, 7}, {0x75, 7},
	{0x28, 6}, {0x29, 6}, {0x2a, 6}, {0x7, 5},
	{0x2b, 6}, {0x76, 7}, {0x2c, 6}, {0x8, 5},
	{0x9, 5}, {0x2d, 6}, {0x77, 7}, {0x78, 7},
	{0x79, 7}, {0x7a, 7}, {0x7b, 7}, {0x7ffe, 15},
	{0x7fc, 11}, {0x3ffd, 14}, {0x1ffd, 13}, {0xffffffc, 28},
	{0xfffe6, 20}, {0x3fffd2, 22}, {0xfffe7, 20}, {0xfffe8, 20},
	{0x3fffd3, 22}, {0x3fffd4, 22}, {0x3fffd5, 22}, {0x7fffd9, 23},
	{0x3fffd6, 22}, {0x7fffda, 23}, {0x7fffdb, 23}, {0x7fffdc, 23},
	{0x7fffdd, 23}, {0x7fffde, 23}, {0xffffeb, 24}, {0x7fffdf, 23},
	{0xffffec, 24}, {0xffffed, 24}, {0x3fffd7, 22}, {0x7fffe0, 23},
	{0xffffee, 24}, {0x7fffe1, 23}, {0x7fffe2, 23}, {0x7fffe3, 23},
	{0x7fffe4, 23}, {0x1fffdc, 21}, {0x3fffd8, 22}, {0x7fffe5, 23},
	{0x3fffd9, 22}, {0x7fffe6, 23}, {0x7fffe7, 23}, {0xffffef, 24},
	{0x3fffda, 22}, {0x1fffdd, 21}, {0xfffe9, 20}, {0x3fffdb, 22},
	{0x3fffdc, 22}, {0x7fffe8, 23}, {0x7fffe9, 23}, {0x1fffde, 21},
	{0x7fffea, 23}, {0x3fffdd, 22}, {0x3fffde, 22}, {0xfffff0, 24},
	{0x1fffdf, 21}, {0x3fffdf, 22}, {0x7fffeb, 23}, {0x7fffec, 23},
	{0x1fffe0, 21}, {0x1fffe1, 21}, {0x3fffe0, 22}, {0x1fffe2, 21},
	{0x7fffed, 23}, {0x3fffe1, 22}, {0x7fffee, 23}, {0x7fffef, 23},
	{0xfffea, 20}, {0x3fffe2, 22}, {0x3fffe3, 22}, {0x3fffe4, 22},
	{0x7ffff0, 23}, {0x3fffe5, 22}, {0x3fffe6, 22}, {0x7ffff1, 23},
	{0x3ffffe0, 26}, {0x3ffffe1, 26}, {0xfffeb, 20}, {0x7fff1, 19},
	{0x3fffe7, 22}, {0x7ffff2, 23}, {0x3fffe8, 22}, {0x1ffffec, 25},
	{0x3ffffe2, 26}, {0x3ffffe3, 26}, {0x3ffffe4, 26}, {0x7ffffde, 27},
	{0x7ffffdf, 27}, {0x3ffffe5, 26}, {0xfffff1, 24}, {0x1ffffed, 25},
	{0x7fff2, 19}, {0x1fffe3, 21}, {0x3ffffe6, 26}, {0x7ffffe0, 27},
	{0x7ffffe1, 27}, {0x3ffffe7, 26}, {0x7ffffe2, 27}, {0xfffff2, 24},
	{0x1fffe4, 21}, {0x1fffe5, 21}, {0x3ffffe8, 26}, {0x3ffffe9, 26},
	{0xffffffd, 28}, {0x7ffffe3, 27}, {0x7ffffe4, 27}, {0x7ffffe5, 27},
	{0xfffec, 20}, {0xfffff3, 24}, {0xfffed, 20}, {0x1fffe6, 21},
	{0x3fffe9, 22}, {0x1fffe7, 21}, {0x1fffe8, 21}, {0x7ffff3, 23},
	{0x3fffea, 22}, {0x3fffeb, 22}, {0x1ffffee, 25}, {0x1ffffef, 25},
	{0xfffff4, 24}, {0xfffff5, 24}, {0x3ffffea, 26}, {0x7ffff4, 23},
	{0x3ffffeb, 26}, {0x7ffffe6, 27}, {0x3ffffec, 26}, {0x3ffffed, 26},
	{0x7ffffe7, 27}, {0x7ffffe8, 27}, {0x7ffffe9, 27}, {0x7ffffea, 27},
	{0x7ffffeb, 27}, {0xffffffe, 28}, {0x7ffffec, 27}, {0x7ffffed, 27},
	{0x7ffffee, 27}, {0x7ffffef, 27}, {0x7fffff0, 27}, {0x3ffffee, 26},
	{0x3fffffff, 30},
}

type huffPrimEntry struct {
	sym  byte
	bits uint8
}

type huffLongEntry struct {
	code uint32
	sym  byte
}

var huffPrimary [256]huffPrimEntry
var huffLong [31][]huffLongEntry

func buildHuffmanDecodeTable() {
	for sym := 0; sym < 256; sym++ {
		entry := huffmanCodes[sym]
		if entry.bits <= 8 {
			shift := 8 - entry.bits
			base := int(entry.code) << shift
			count := 1 << shift
			for j := 0; j < count; j++ {
				idx := base + j
				if idx < 256 && (huffPrimary[idx].bits == 0 || entry.bits < huffPrimary[idx].bits) {
					huffPrimary[idx] = huffPrimEntry{sym: byte(sym), bits: entry.bits}
				}
			}
		} else {
			huffLong[entry.bits] = append(huffLong[entry.bits], huffLongEntry{code: entry.code, sym: byte(sym)})
		}
	}
}

func huffmanLookup(bits uint64, nbits uint8) (byte, uint8) {
	if nbits >= 8 {
		e := huffPrimary[byte(bits>>(nbits-8))]
		if e.bits > 0 {
			return e.sym, e.bits
		}
		for b := uint8(9); b <= nbits && b <= 30; b++ {
			group := huffLong[b]
			target := uint32(bits >> (nbits - b))
			for _, g := range group {
				if g.code == target {
					return g.sym, b
				}
			}
		}
		return 0, 0
	}
	e := huffPrimary[byte(bits<<(8-nbits))]
	if e.bits > 0 && e.bits <= nbits {
		return e.sym, e.bits
	}
	return 0, 0
}
