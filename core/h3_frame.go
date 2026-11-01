//go:build linux && amd64

package core

import "sync"

const (
	h3FrameData        uint64 = 0x00
	h3FrameHeaders     uint64 = 0x01
	h3FrameCancelPush  uint64 = 0x03
	h3FrameSettings    uint64 = 0x04
	h3FramePushPromise uint64 = 0x05
	h3FrameGoaway      uint64 = 0x07
	h3FrameMaxPushID   uint64 = 0x0d

	h3StreamControl  uint64 = 0x00
	h3StreamPush     uint64 = 0x01
	h3StreamQPACKEnc uint64 = 0x02
	h3StreamQPACKDec uint64 = 0x03

	h3SettingMaxHeaderListSize uint64 = 0x06
	h3SettingQPACKMaxTableCap  uint64 = 0x01
	h3SettingQPACKBlockedStr   uint64 = 0x07
)

const (
	h3ErrNoError              uint64 = 0x0100
	h3ErrStreamCreation       uint64 = 0x0103
	h3ErrClosedCriticalStream uint64 = 0x0104
	h3ErrFrameUnexpected      uint64 = 0x0105
	h3ErrFrame                uint64 = 0x0106
	h3ErrExcessiveLoad        uint64 = 0x0107
	h3ErrSettings             uint64 = 0x0109
	h3ErrMissingSettings      uint64 = 0x010a
	h3ErrRequestRejected      uint64 = 0x010b
	h3ErrRequestIncomplete    uint64 = 0x010d
	qpackErrEncoderStream     uint64 = 0x0201
	qpackSetCapacityZero      byte   = 0x20
	h3MaxControlFramePayload         = 4096
	h3MaxPushIDFramePayload          = 8
)

func h3FrameTypeReservedFromHTTP2(frameType uint64) bool {
	switch frameType {
	case 0x02, 0x06, 0x08, 0x09:
		return true
	}
	return false
}

func h3SettingReservedFromHTTP2(id uint64) bool {
	return id >= 0x02 && id <= 0x05
}

const h3FrameBufPoolMaxCap = 64 << 10

var h3FrameBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 512); return &b },
}

func h3AppendFrame(dst []byte, frameType uint64, payload []byte) []byte {
	dst = quicAppendVarint(dst, frameType)
	dst = quicAppendVarint(dst, uint64(len(payload)))
	dst = append(dst, payload...)
	return dst
}

func h3AppendSettingsFrame(dst []byte, fieldSectionLimit int) []byte {
	var payload []byte
	payload = quicAppendVarint(payload, h3SettingMaxHeaderListSize)
	payload = quicAppendVarint(payload, uint64(fieldSectionLimit))
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

type h3FrameReader struct {
	data []byte
	off  int
}

func (r *h3FrameReader) next() (frameType uint64, payload []byte, ok bool) {
	if r.off >= len(r.data) {
		return 0, nil, false
	}
	pos := r.off
	ft, n := quicParseVarint(r.data[pos:])
	if n == 0 {
		return 0, nil, false
	}
	pos += n
	fLen, n := quicParseVarint(r.data[pos:])
	if n == 0 {
		return 0, nil, false
	}
	pos += n
	if fLen > uint64(len(r.data)-pos) {
		return 0, nil, false
	}
	payload = r.data[pos : pos+int(fLen)]
	r.off = pos + int(fLen)
	return ft, payload, true
}

func h3AppendStreamType(dst []byte, streamType uint64) []byte {
	return quicAppendVarint(dst, streamType)
}
