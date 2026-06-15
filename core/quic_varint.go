package core

import "encoding/binary"

func quicVarintLen(v uint64) int {
	if v < 64 {
		return 1
	}
	if v < 16384 {
		return 2
	}
	if v < 1073741824 {
		return 4
	}
	return 8
}

func quicAppendVarint(dst []byte, v uint64) []byte {
	if v < 64 {
		return append(dst, byte(v))
	}
	if v < 16384 {
		return append(dst, byte(0x40|v>>8), byte(v))
	}
	if v < 1073741824 {
		return append(dst, byte(0x80|v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], 0xc000000000000000|v)
	return append(dst, buf[:]...)
}

func quicPutVarint(dst []byte, v uint64) int {
	if v < 64 {
		dst[0] = byte(v)
		return 1
	}
	if v < 16384 {
		binary.BigEndian.PutUint16(dst, uint16(0x4000|v))
		return 2
	}
	if v < 1073741824 {
		binary.BigEndian.PutUint32(dst, uint32(0x80000000|v))
		return 4
	}
	binary.BigEndian.PutUint64(dst, 0xc000000000000000|v)
	return 8
}

func quicParseVarint(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	prefix := data[0] >> 6
	switch prefix {
	case 0:
		return uint64(data[0] & 0x3f), 1
	case 1:
		if len(data) < 2 {
			return 0, 0
		}
		return uint64(data[0]&0x3f)<<8 | uint64(data[1]), 2
	case 2:
		if len(data) < 4 {
			return 0, 0
		}
		return uint64(data[0]&0x3f)<<24 | uint64(data[1])<<16 | uint64(data[2])<<8 | uint64(data[3]), 4
	default:
		if len(data) < 8 {
			return 0, 0
		}
		v := binary.BigEndian.Uint64(data) & 0x3fffffffffffffff
		return v, 8
	}
}
