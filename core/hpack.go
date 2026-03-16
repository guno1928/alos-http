package core

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
	for i := 0; i < len(s); i++ {
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

type HpackDecoder struct {
	maxTableSize    int
	protocolMaxSize int
	dynRing         [128]hpackDynEntry
	dynHead         int
	dynLen          int
	dynSize         int
}

func NewHpackDecoder() *HpackDecoder {
	return &HpackDecoder{
		maxTableSize:    H2HeaderTableSize,
		protocolMaxSize: H2HeaderTableSize,
	}
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
			pos += n
			name, value, ok := d.lookupIndex(idx)
			if ok {
				headers = append(headers, [2]string{name, value})
				if len(headers) > maxHeaders {
					return nil, ErrTooManyHeaders
				}
			}
		} else if b&0x40 != 0 {
			idx, n := HpackDecodeInt(data[pos:], 6)
			pos += n
			var name string
			if idx > 0 {
				name, _ = d.lookupName(idx)
			} else {
				name, n = HpackDecodeString(data[pos:])
				pos += n
			}
			val, n := HpackDecodeString(data[pos:])
			pos += n
			headers = append(headers, [2]string{name, val})
			if len(headers) > maxHeaders {
				return nil, ErrTooManyHeaders
			}
			d.addEntry(name, val)
		} else if b&0x20 != 0 {
			maxSize, n := HpackDecodeInt(data[pos:], 5)
			pos += n
			if int(maxSize) > d.protocolMaxSize {
				return nil, ErrHpackTableSizeExceeded
			}
			d.setMaxSize(int(maxSize))
		} else {
			idx, n := HpackDecodeInt(data[pos:], 4)
			pos += n
			var name string
			if idx > 0 {
				name, _ = d.lookupName(idx)
			} else {
				name, n = HpackDecodeString(data[pos:])
				pos += n
			}
			val, n := HpackDecodeString(data[pos:])
			pos += n
			headers = append(headers, [2]string{name, val})
			if len(headers) > maxHeaders {
				return nil, ErrTooManyHeaders
			}
		}
	}
	return headers, nil
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
			return val, i
		}
		val += uint64(b&0x7f) << m
		m += 7
		if b&0x80 == 0 {
			break
		}
	}
	return val, i
}

func HpackDecodeString(data []byte) (string, int) {
	if len(data) == 0 {
		return "", 0
	}
	huffman := data[0]&0x80 != 0
	sLen, n := HpackDecodeInt(data, 7)
	if sLen > uint64(len(data)) || n+int(sLen) > len(data) {
		return "", n
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
