package core

import "sync"

const (
	h3FrameData     uint64 = 0x00
	h3FrameHeaders  uint64 = 0x01
	h3FrameSettings uint64 = 0x04
	h3FrameGoaway   uint64 = 0x07

	h3StreamControl    uint64 = 0x00
	h3StreamQPACKEnc   uint64 = 0x02
	h3StreamQPACKDec   uint64 = 0x03

	h3SettingMaxHeaderListSize uint64 = 0x06
	h3SettingQPACKMaxTableCap  uint64 = 0x01
	h3SettingQPACKBlockedStr   uint64 = 0x07
)

var h3FrameBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 512); return &b },
}

func h3AppendFrame(dst []byte, frameType uint64, payload []byte) []byte {
	dst = quicAppendVarint(dst, frameType)
	dst = quicAppendVarint(dst, uint64(len(payload)))
	dst = append(dst, payload...)
	return dst
}

func h3AppendSettingsFrame(dst []byte) []byte {
	var payload []byte
	payload = quicAppendVarint(payload, h3SettingMaxHeaderListSize)
	payload = quicAppendVarint(payload, 16384)
	payload = quicAppendVarint(payload, h3SettingQPACKMaxTableCap)
	payload = quicAppendVarint(payload, 0)
	payload = quicAppendVarint(payload, h3SettingQPACKBlockedStr)
	payload = quicAppendVarint(payload, 0)
	return h3AppendFrame(dst, h3FrameSettings, payload)
}

func h3AppendHeadersFrame(dst []byte, encodedHeaders []byte) []byte {
	return h3AppendFrame(dst, h3FrameHeaders, encodedHeaders)
}

func h3AppendDataFrame(dst []byte, data []byte) []byte {
	return h3AppendFrame(dst, h3FrameData, data)
}

func h3AppendGoawayFrame(dst []byte, streamID uint64) []byte {
	var payload []byte
	payload = quicAppendVarint(payload, streamID)
	return h3AppendFrame(dst, h3FrameGoaway, payload)
}

type h3FrameReader struct {
	data []byte
	off  int
}

func (r *h3FrameReader) next() (frameType uint64, payload []byte, ok bool) {
	if r.off >= len(r.data) {
		return 0, nil, false
	}
	ft, n := quicParseVarint(r.data[r.off:])
	if n == 0 {
		return 0, nil, false
	}
	r.off += n
	fLen, n := quicParseVarint(r.data[r.off:])
	if n == 0 {
		return 0, nil, false
	}
	r.off += n
	if fLen > uint64(len(r.data)-r.off) {
		return 0, nil, false
	}
	payload = r.data[r.off : r.off+int(fLen)]
	r.off += int(fLen)
	return ft, payload, true
}

func h3AppendStreamType(dst []byte, streamType uint64) []byte {
	return quicAppendVarint(dst, streamType)
}
