package core

// H2ClientPreface is the 24-byte connection preface an HTTP/2 client sends
// before the first frame.
var H2ClientPreface = [24]byte{'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0', '\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n'}

// H2Frame represents a parsed HTTP/2 frame header and payload.
type H2Frame struct {
	Length   uint32
	Type     byte
	Flags    byte
	StreamID uint32
	Payload  []byte
}

func releaseH2Frame(f *H2Frame) {
	f.Payload = f.Payload[:0]
	H2FramePool.Put(f)
}

// H2ReadFrame parses an HTTP/2 frame from the bytes returned by reader,
// returning a pooled *H2Frame, or an error if the data is too short or the
// declared frame length exceeds it.
func H2ReadFrame(reader func() ([]byte, error)) (*H2Frame, error) {
	data, err := reader()
	if err != nil {
		return nil, err
	}
	if len(data) < 9 {
		return nil, ErrH2FrameTooLarge
	}
	f := H2FramePool.Get().(*H2Frame)
	f.Length = uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	f.Type = data[3]
	f.Flags = data[4]
	f.StreamID = (uint32(data[5])<<24 | uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8])) & 0x7fffffff
	if 9+int(f.Length) > len(data) {
		releaseH2Frame(f)
		return nil, ErrH2FrameTooLarge
	}
	f.Payload = data[9 : 9+f.Length]
	return f, nil
}

// H2WriteFrame appends an HTTP/2 frame with the given type, flags, stream ID,
// and payload to dst, reusing dst's capacity when it is large enough, and
// returns the resulting slice.
func H2WriteFrame(dst []byte, typ, flags byte, streamID uint32, payload []byte) []byte {
	pLen := len(payload)
	needed := 9 + pLen
	if cap(dst) < needed {
		dst = make([]byte, needed)
	} else {
		dst = dst[:needed]
	}
	dst[0] = byte(pLen >> 16)
	dst[1] = byte(pLen >> 8)
	dst[2] = byte(pLen)
	dst[3] = typ
	dst[4] = flags
	dst[5] = byte(streamID >> 24)
	dst[6] = byte(streamID >> 16)
	dst[7] = byte(streamID >> 8)
	dst[8] = byte(streamID)
	if pLen > 0 {
		copy(dst[9:], payload)
	}
	return dst
}

// H2WriteSettings appends an HTTP/2 SETTINGS frame carrying the given
// identifier/value pairs to dst and returns the resulting slice.
func H2WriteSettings(dst []byte, settings [][2]uint32) []byte {
	payloadLen := len(settings) * 6
	needed := 9 + payloadLen
	if cap(dst) < needed {
		dst = make([]byte, needed)
	} else {
		dst = dst[:needed]
	}
	dst[0] = byte(payloadLen >> 16)
	dst[1] = byte(payloadLen >> 8)
	dst[2] = byte(payloadLen)
	dst[3] = H2FrameSettings
	dst[4] = 0
	dst[5] = 0
	dst[6] = 0
	dst[7] = 0
	dst[8] = 0
	off := 9
	for _, s := range settings {
		v16 := uint16(s[0])
		dst[off] = byte(v16 >> 8)
		dst[off+1] = byte(v16)
		v32 := s[1]
		dst[off+2] = byte(v32 >> 24)
		dst[off+3] = byte(v32 >> 16)
		dst[off+4] = byte(v32 >> 8)
		dst[off+5] = byte(v32)
		off += 6
	}
	return dst
}

// H2WriteSettingsAck appends an HTTP/2 SETTINGS frame with the ACK flag set
// to dst and returns the resulting slice.
func H2WriteSettingsAck(dst []byte) []byte {
	if cap(dst) < 9 {
		dst = make([]byte, 9)
	} else {
		dst = dst[:9]
	}
	dst[0] = 0
	dst[1] = 0
	dst[2] = 0
	dst[3] = H2FrameSettings
	dst[4] = H2FlagAck
	dst[5] = 0
	dst[6] = 0
	dst[7] = 0
	dst[8] = 0
	return dst
}

// H2WriteWindowUpdate appends an HTTP/2 WINDOW_UPDATE frame for streamID
// with the given increment to dst and returns the resulting slice.
func H2WriteWindowUpdate(dst []byte, streamID, increment uint32) []byte {
	if cap(dst) < 13 {
		dst = make([]byte, 13)
	} else {
		dst = dst[:13]
	}
	dst[0] = 0
	dst[1] = 0
	dst[2] = 4
	dst[3] = H2FrameWindowUpdate
	dst[4] = 0
	dst[5] = byte(streamID >> 24)
	dst[6] = byte(streamID >> 16)
	dst[7] = byte(streamID >> 8)
	dst[8] = byte(streamID)
	v := increment & 0x7fffffff
	dst[9] = byte(v >> 24)
	dst[10] = byte(v >> 16)
	dst[11] = byte(v >> 8)
	dst[12] = byte(v)
	return dst
}

// H2WriteGoAway appends an HTTP/2 GOAWAY frame reporting lastStream and
// errCode to dst and returns the resulting slice.
func H2WriteGoAway(dst []byte, lastStream, errCode uint32) []byte {
	if cap(dst) < 17 {
		dst = make([]byte, 17)
	} else {
		dst = dst[:17]
	}
	dst[0] = 0
	dst[1] = 0
	dst[2] = 8
	dst[3] = H2FrameGoAway
	dst[4] = 0
	dst[5] = 0
	dst[6] = 0
	dst[7] = 0
	dst[8] = 0
	dst[9] = byte(lastStream >> 24)
	dst[10] = byte(lastStream >> 16)
	dst[11] = byte(lastStream >> 8)
	dst[12] = byte(lastStream)
	dst[13] = byte(errCode >> 24)
	dst[14] = byte(errCode >> 16)
	dst[15] = byte(errCode >> 8)
	dst[16] = byte(errCode)
	return dst
}

// H2WritePing appends an HTTP/2 PING frame carrying data to dst, setting the
// ACK flag when ack is true, and returns the resulting slice.
func H2WritePing(dst []byte, ack bool, data [8]byte) []byte {
	if cap(dst) < 17 {
		dst = make([]byte, 17)
	} else {
		dst = dst[:17]
	}
	dst[0] = 0
	dst[1] = 0
	dst[2] = 8
	dst[3] = H2FramePing
	if ack {
		dst[4] = H2FlagAck
	} else {
		dst[4] = 0
	}
	dst[5] = 0
	dst[6] = 0
	dst[7] = 0
	dst[8] = 0
	copy(dst[9:17], data[:])
	return dst
}

// H2WriteRSTStream appends an HTTP/2 RST_STREAM frame for streamID with
// errCode to dst and returns the resulting slice.
func H2WriteRSTStream(dst []byte, streamID, errCode uint32) []byte {
	if cap(dst) < 13 {
		dst = make([]byte, 13)
	} else {
		dst = dst[:13]
	}
	dst[0] = 0
	dst[1] = 0
	dst[2] = 4
	dst[3] = H2FrameRSTStream
	dst[4] = 0
	dst[5] = byte(streamID >> 24)
	dst[6] = byte(streamID >> 16)
	dst[7] = byte(streamID >> 8)
	dst[8] = byte(streamID)
	dst[9] = byte(errCode >> 24)
	dst[10] = byte(errCode >> 16)
	dst[11] = byte(errCode >> 8)
	dst[12] = byte(errCode)
	return dst
}

// H2WriteContinuation appends an HTTP/2 CONTINUATION frame carrying
// headerBlock to dst and returns the resulting slice.
func H2WriteContinuation(dst []byte, flags byte, streamID uint32, headerBlock []byte) []byte {
	return H2WriteFrame(dst, H2FrameContinuation, flags, streamID, headerBlock)
}
