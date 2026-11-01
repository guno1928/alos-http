//go:build linux && amd64

package core

type h3PeerStreamKind uint8

const (
	h3PeerStreamUntyped h3PeerStreamKind = iota
	h3PeerStreamControl
	h3PeerStreamQPACKEncoder
	h3PeerStreamQPACKDecoder
	h3PeerStreamIgnored
)

type h3ConnError struct {
	code   uint64
	reason string
}

func (e *h3ConnError) Error() string { return e.reason }

func h3Fail(code uint64, reason string) *h3ConnError {
	return &h3ConnError{code: code, reason: reason}
}

type h3PeerStream struct {
	kind         h3PeerStreamKind
	pending      []byte
	skip         uint64
	settingsSeen bool
}

func (k h3PeerStreamKind) critical() bool {
	return k == h3PeerStreamControl || k == h3PeerStreamQPACKEncoder || k == h3PeerStreamQPACKDecoder
}

func (h3 *H3Conn) readPeerStream(s *QUICStream) {
	data, fin := s.takeReceived()
	st := h3.peerStreams[s.id]
	if st == nil {
		if h3.peerStreams == nil {
			h3.peerStreams = make(map[uint64]*h3PeerStream, 4)
		}
		st = &h3PeerStream{}
		h3.peerStreams[s.id] = st
	}
	if err := h3.consumePeerStream(s, st, data); err != nil {
		h3.qconn.closeWithAppError(err.code, err.reason)
		return
	}
	if fin {
		h3.peerStreamEnded(s, st)
	}
}

func (h3 *H3Conn) peerStreamEnded(s *QUICStream, st *h3PeerStream) {
	if st.kind.critical() {
		h3.qconn.closeWithAppError(h3ErrClosedCriticalStream, "critical stream closed")
		return
	}
	delete(h3.peerStreams, s.id)
	if s.dispatched.CompareAndSwap(false, true) {
		h3.qconn.retireStream(s)
	}
}

func (h3 *H3Conn) peerStreamReset(id uint64) {
	st := h3.peerStreams[id]
	if st != nil && st.kind.critical() {
		h3.qconn.closeWithAppError(h3ErrClosedCriticalStream, "critical stream reset")
		return
	}
	delete(h3.peerStreams, id)
}

func (h3 *H3Conn) consumePeerStream(s *QUICStream, st *h3PeerStream, data []byte) *h3ConnError {
	if st.kind == h3PeerStreamUntyped {
		st.pending = append(st.pending, data...)
		streamType, n := quicParseVarint(st.pending)
		if n == 0 {
			return nil
		}
		data = st.pending[n:]
		st.pending = nil
		if err := h3.assignPeerStreamType(s, st, streamType); err != nil {
			return err
		}
	}
	switch st.kind {
	case h3PeerStreamControl:
		return h3.consumeControlStream(st, data)
	case h3PeerStreamQPACKEncoder:
		for _, b := range data {
			if b != qpackSetCapacityZero {
				return h3Fail(qpackErrEncoderStream, "encoder instruction for a dynamic table of capacity 0")
			}
		}
	}
	return nil
}

func (h3 *H3Conn) assignPeerStreamType(s *QUICStream, st *h3PeerStream, streamType uint64) *h3ConnError {
	switch streamType {
	case h3StreamControl:
		if h3.peerControlSeen {
			return h3Fail(h3ErrStreamCreation, "second control stream")
		}
		h3.peerControlSeen = true
		st.kind = h3PeerStreamControl
	case h3StreamQPACKEnc:
		if h3.peerEncoderSeen {
			return h3Fail(h3ErrStreamCreation, "second QPACK encoder stream")
		}
		h3.peerEncoderSeen = true
		st.kind = h3PeerStreamQPACKEncoder
	case h3StreamQPACKDec:
		if h3.peerDecoderSeen {
			return h3Fail(h3ErrStreamCreation, "second QPACK decoder stream")
		}
		h3.peerDecoderSeen = true
		st.kind = h3PeerStreamQPACKDecoder
	case h3StreamPush:
		return h3Fail(h3ErrStreamCreation, "client-initiated push stream")
	default:
		st.kind = h3PeerStreamIgnored
		h3.qconn.stopSending(s.id, h3ErrStreamCreation)
	}
	return nil
}

func (h3 *H3Conn) consumeControlStream(st *h3PeerStream, data []byte) *h3ConnError {
	if st.skip > 0 {
		if uint64(len(data)) <= st.skip {
			st.skip -= uint64(len(data))
			return nil
		}
		data = data[st.skip:]
		st.skip = 0
	}
	buf := data
	if len(st.pending) > 0 {
		st.pending = append(st.pending, data...)
		buf = st.pending
	}
	for len(buf) > 0 {
		frameType, n1 := quicParseVarint(buf)
		if n1 == 0 {
			break
		}
		length, n2 := quicParseVarint(buf[n1:])
		if n2 == 0 {
			break
		}
		header := n1 + n2
		if !st.settingsSeen && frameType != h3FrameSettings {
			return h3Fail(h3ErrMissingSettings, "first control frame is not SETTINGS")
		}
		switch {
		case frameType == h3FrameSettings:
			if st.settingsSeen {
				return h3Fail(h3ErrFrameUnexpected, "second SETTINGS frame")
			}
			if length > h3MaxControlFramePayload {
				return h3Fail(h3ErrExcessiveLoad, "SETTINGS frame too large")
			}
		case frameType == h3FrameGoaway || frameType == h3FrameMaxPushID || frameType == h3FrameCancelPush:
			if length > h3MaxPushIDFramePayload {
				return h3Fail(h3ErrFrame, "control frame payload is not a single varint")
			}
		case frameType == h3FrameData || frameType == h3FrameHeaders || frameType == h3FramePushPromise || h3FrameTypeReservedFromHTTP2(frameType):
			return h3Fail(h3ErrFrameUnexpected, "frame not allowed on the control stream")
		default:
			available := uint64(len(buf) - header)
			if available < length {
				st.skip = length - available
				buf = nil
				continue
			}
			buf = buf[header+int(length):]
			continue
		}
		if uint64(len(buf)-header) < length {
			break
		}
		payload := buf[header : header+int(length)]
		if frameType == h3FrameSettings {
			if err := validatePeerSettings(payload); err != nil {
				return err
			}
			st.settingsSeen = true
		} else if _, n := quicParseVarint(payload); n == 0 || n != len(payload) {
			return h3Fail(h3ErrFrame, "malformed control frame")
		}
		buf = buf[header+int(length):]
	}
	st.pending = append(st.pending[:0], buf...)
	return nil
}

func validatePeerSettings(payload []byte) *h3ConnError {
	seen := make(map[uint64]struct{}, 8)
	for len(payload) > 0 {
		id, n1 := quicParseVarint(payload)
		if n1 == 0 {
			return h3Fail(h3ErrFrame, "truncated setting identifier")
		}
		_, n2 := quicParseVarint(payload[n1:])
		if n2 == 0 {
			return h3Fail(h3ErrFrame, "truncated setting value")
		}
		if h3SettingReservedFromHTTP2(id) {
			return h3Fail(h3ErrSettings, "HTTP/2 setting in HTTP/3 SETTINGS")
		}
		if _, dup := seen[id]; dup {
			return h3Fail(h3ErrSettings, "duplicate setting")
		}
		seen[id] = struct{}{}
		payload = payload[n1+n2:]
	}
	return nil
}
