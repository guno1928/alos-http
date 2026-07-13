//go:build linux

package core

var hpackStatic = [62][2]string{
	{},
	{":authority", ""}, {":method", "GET"}, {":method", "POST"}, {":path", "/"},
	{":path", "/index.html"}, {":scheme", "http"}, {":scheme", "https"}, {":status", "200"},
	{":status", "204"}, {":status", "206"}, {":status", "304"}, {":status", "400"},
	{":status", "404"}, {":status", "500"}, {"accept-charset", ""}, {"accept-encoding", "gzip, deflate"},
	{"accept-language", ""}, {"accept-ranges", ""}, {"accept", ""}, {"access-control-allow-origin", ""},
	{"age", ""}, {"allow", ""}, {"authorization", ""}, {"cache-control", ""},
	{"content-disposition", ""}, {"content-encoding", ""}, {"content-language", ""}, {"content-length", ""},
	{"content-location", ""}, {"content-range", ""}, {"content-type", ""}, {"cookie", ""},
	{"date", ""}, {"etag", ""}, {"expect", ""}, {"expires", ""},
	{"from", ""}, {"host", ""}, {"if-match", ""}, {"if-modified-since", ""},
	{"if-none-match", ""}, {"if-range", ""}, {"if-unmodified-since", ""}, {"last-modified", ""},
	{"link", ""}, {"location", ""}, {"max-forwards", ""}, {"proxy-authenticate", ""},
	{"proxy-authorization", ""}, {"range", ""}, {"referer", ""}, {"refresh", ""},
	{"retry-after", ""}, {"server", ""}, {"set-cookie", ""}, {"strict-transport-security", ""},
	{"transfer-encoding", ""}, {"user-agent", ""}, {"vary", ""}, {"via", ""},
	{"www-authenticate", ""},
}

var hpackStaticNameIndex = func() map[string]int {
	m := make(map[string]int, 61)
	for i := 1; i <= 61; i++ {
		if _, ok := m[hpackStatic[i][0]]; !ok {
			m[hpackStatic[i][0]] = i
		}
	}
	return m
}()

type hpackEncoder struct {
	buf []byte
}

func (e *hpackEncoder) reset(dst []byte) {
	e.buf = dst
}

func (e *hpackEncoder) encodeInt(prefix byte, prefixBits uint8, val int) {
	maxFirst := (1 << prefixBits) - 1
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

func (e *hpackEncoder) appendString(s string) {
	e.encodeInt(0, 7, len(s))
	e.buf = append(e.buf, s...)
}

func (e *hpackEncoder) field(name, value string) {
	if idx, ok := hpackStaticNameIndex[name]; ok {
		e.encodeInt(0x00, 4, idx)
	} else {
		e.buf = append(e.buf, 0x00)
		e.appendString(name)
	}
	e.appendString(value)
}

type fpHpackDynEntry struct {
	name  string
	value string
}

type hpackDecoder struct {
	dyn     []fpHpackDynEntry
	size    int
	maxSize int
}

func (d *hpackDecoder) init(maxSize int) {
	d.maxSize = maxSize
	d.dyn = d.dyn[:0]
	d.size = 0
}

func (d *hpackDecoder) setMaxSize(n int) {
	d.maxSize = n
	d.evict()
}

func (d *hpackDecoder) evict() {
	for d.size > d.maxSize && len(d.dyn) > 0 {
		last := d.dyn[len(d.dyn)-1]
		d.size -= len(last.name) + len(last.value) + 32
		d.dyn = d.dyn[:len(d.dyn)-1]
	}
}

func (d *hpackDecoder) add(name, value string) {
	entrySize := len(name) + len(value) + 32
	d.size += entrySize
	d.dyn = append(d.dyn, fpHpackDynEntry{})
	copy(d.dyn[1:], d.dyn[:len(d.dyn)-1])
	d.dyn[0] = fpHpackDynEntry{name: name, value: value}
	d.evict()
}

func (d *hpackDecoder) lookup(idx int) (string, string, bool) {
	if idx >= 1 && idx <= 61 {
		return hpackStatic[idx][0], hpackStatic[idx][1], true
	}
	di := idx - 62
	if di >= 0 && di < len(d.dyn) {
		return d.dyn[di].name, d.dyn[di].value, true
	}
	return "", "", false
}

func (d *hpackDecoder) decode(block []byte, out [][2]string) ([][2]string, error) {
	pos := 0
	for pos < len(block) {
		b := block[pos]
		switch {
		case b&0x80 != 0:
			idx, n, err := hpackReadInt(block[pos:], 7)
			if err != nil {
				return out, err
			}
			pos += n
			name, value, ok := d.lookup(idx)
			if !ok {
				return out, fpErrBadResponse
			}
			out = append(out, [2]string{name, value})
		case b&0x40 != 0:
			name, value, np, err := d.readNameValue(block[pos:], 6)
			if err != nil {
				return out, err
			}
			pos += np
			d.add(name, value)
			out = append(out, [2]string{name, value})
		case b&0x20 != 0:
			newMax, n, err := hpackReadInt(block[pos:], 5)
			if err != nil {
				return out, err
			}
			pos += n
			if newMax > d.maxSize {
				return out, fpErrBadResponse
			}
			d.setMaxSize(newMax)
		default:
			name, value, np, err := d.readNameValue(block[pos:], 4)
			if err != nil {
				return out, err
			}
			pos += np
			out = append(out, [2]string{name, value})
		}
	}
	return out, nil
}

func (d *hpackDecoder) readNameValue(block []byte, prefixBits uint8) (string, string, int, error) {
	idx, n, err := hpackReadInt(block, prefixBits)
	if err != nil {
		return "", "", 0, err
	}
	pos := n
	var name string
	if idx == 0 {
		s, ns, err := hpackReadString(block[pos:])
		if err != nil {
			return "", "", 0, err
		}
		name = s
		pos += ns
	} else {
		nm, _, ok := d.lookup(idx)
		if !ok {
			return "", "", 0, fpErrBadResponse
		}
		name = nm
	}
	value, vs, err := hpackReadString(block[pos:])
	if err != nil {
		return "", "", 0, err
	}
	pos += vs
	return name, value, pos, nil
}

func hpackReadInt(b []byte, prefixBits uint8) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, fpErrBadResponse
	}
	maxFirst := (1 << prefixBits) - 1
	val := int(b[0]) & maxFirst
	if val < maxFirst {
		return val, 1, nil
	}
	pos := 1
	m := 0
	for {
		if pos >= len(b) {
			return 0, 0, fpErrBadResponse
		}
		c := b[pos]
		pos++
		val += int(c&0x7f) << m
		if c&0x80 == 0 {
			break
		}
		m += 7
		if m > 28 {
			return 0, 0, fpErrBadResponse
		}
	}
	return val, pos, nil
}

func hpackReadString(b []byte) (string, int, error) {
	if len(b) == 0 {
		return "", 0, fpErrBadResponse
	}
	huffman := b[0]&0x80 != 0
	length, n, err := hpackReadInt(b, 7)
	if err != nil {
		return "", 0, err
	}
	if n+length > len(b) {
		return "", 0, fpErrBadResponse
	}
	raw := b[n : n+length]
	if !huffman {
		return string(raw), n + length, nil
	}
	s, err := fpHpackHuffmanDecode(raw)
	if err != nil {
		return "", 0, err
	}
	return s, n + length, nil
}

func fpHpackHuffmanDecode(data []byte) (string, error) {
	out := make([]byte, 0, len(data)*8/5)
	var acc uint64
	var nbits uint8
	for _, bb := range data {
		acc = acc<<8 | uint64(bb)
		nbits += 8
		for nbits >= 5 {
			sym, used := huffLookup(acc, nbits)
			if used == 0 || used > nbits {
				break
			}
			out = append(out, sym)
			nbits -= used
			acc &= (1 << nbits) - 1
		}
	}
	if nbits > 7 {
		return "", fpErrBadResponse
	}
	if nbits > 0 {
		mask := uint64((1 << nbits) - 1)
		if acc&mask != mask {
			return "", fpErrBadResponse
		}
	}
	return string(out), nil
}
