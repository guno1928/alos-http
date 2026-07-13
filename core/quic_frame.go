package core

const (
	quicFramePadding          = 0x00
	quicFramePing             = 0x01
	quicFrameACK              = 0x02
	quicFrameACKECN           = 0x03
	quicFrameResetStream      = 0x04
	quicFrameStopSending      = 0x05
	quicFrameCrypto           = 0x06
	quicFrameNewToken         = 0x07
	quicFrameStream           = 0x08
	quicFrameStreamEnd        = 0x0f
	quicFrameMaxData          = 0x10
	quicFrameMaxStreamData    = 0x11
	quicFrameMaxStreamsBidi   = 0x12
	quicFrameMaxStreamsUni    = 0x13
	quicFrameDataBlocked      = 0x14
	quicFrameStreamDataBlock  = 0x15
	quicFrameStreamsBlockBidi = 0x16
	quicFrameStreamsBlockUni  = 0x17
	quicFrameNewConnID        = 0x18
	quicFrameRetireConnID     = 0x19
	quicFramePathChallenge    = 0x1a
	quicFramePathResponse     = 0x1b
	quicFrameConnClose        = 0x1c
	quicFrameAppClose         = 0x1d
	quicFrameHandshakeDone    = 0x1e
)

const (
	quicStreamFlagOff byte = 0x04
	quicStreamFlagLen byte = 0x02
	quicStreamFlagFin byte = 0x01
)

type quicCryptoFrame struct {
	offset uint64
	data   []byte
}

type quicStreamFrame struct {
	streamID uint64
	offset   uint64
	data     []byte
	fin      bool
}

type quicAckRange struct {
	gap   uint64
	count uint64
}

type quicAckFrame struct {
	largestAck uint64
	ackDelay   uint64
	firstRange uint64
	ranges     []quicAckRange
}

type quicConnCloseFrame struct {
	errorCode    uint64
	frameType    uint64
	reasonPhrase string
	isApp        bool
}

type quicMaxDataFrame struct {
	maxData uint64
}

type quicMaxStreamDataFrame struct {
	streamID      uint64
	maxStreamData uint64
}

type quicMaxStreamsFrame struct {
	maxStreams uint64
	bidi       bool
}

type quicNewConnIDFrame struct {
	seq        uint64
	retirePT   uint64
	connID     []byte
	resetToken [16]byte
}

func quicAppendCryptoFrame(dst []byte, offset uint64, data []byte) []byte {
	dst = quicAppendVarint(dst, quicFrameCrypto)
	dst = quicAppendVarint(dst, offset)
	dst = quicAppendVarint(dst, uint64(len(data)))
	dst = append(dst, data...)
	return dst
}

func quicAppendStreamFrame(dst []byte, streamID, offset uint64, data []byte, fin bool) []byte {
	flags := byte(quicFrameStream)
	if offset > 0 {
		flags |= quicStreamFlagOff
	}
	flags |= quicStreamFlagLen
	if fin {
		flags |= quicStreamFlagFin
	}
	dst = append(dst, flags)
	dst = quicAppendVarint(dst, streamID)
	if offset > 0 {
		dst = quicAppendVarint(dst, offset)
	}
	dst = quicAppendVarint(dst, uint64(len(data)))
	dst = append(dst, data...)
	return dst
}

func quicAppendACKFrame(dst []byte, largestAck, ackDelay, firstRange uint64) []byte {
	dst = quicAppendVarint(dst, quicFrameACK)
	dst = quicAppendVarint(dst, largestAck)
	dst = quicAppendVarint(dst, ackDelay)
	dst = quicAppendVarint(dst, 0)
	dst = quicAppendVarint(dst, firstRange)
	return dst
}

func quicAppendMaxDataFrame(dst []byte, maxData uint64) []byte {
	dst = quicAppendVarint(dst, quicFrameMaxData)
	dst = quicAppendVarint(dst, maxData)
	return dst
}

func quicAppendMaxStreamDataFrame(dst []byte, streamID, maxStreamData uint64) []byte {
	dst = quicAppendVarint(dst, quicFrameMaxStreamData)
	dst = quicAppendVarint(dst, streamID)
	dst = quicAppendVarint(dst, maxStreamData)
	return dst
}

func quicAppendStreamDataBlockedFrame(dst []byte, streamID, limit uint64) []byte {
	dst = quicAppendVarint(dst, quicFrameStreamDataBlock)
	dst = quicAppendVarint(dst, streamID)
	dst = quicAppendVarint(dst, limit)
	return dst
}

func quicAppendMaxStreamsFrame(dst []byte, maxStreams uint64, bidi bool) []byte {
	if bidi {
		dst = quicAppendVarint(dst, quicFrameMaxStreamsBidi)
	} else {
		dst = quicAppendVarint(dst, quicFrameMaxStreamsUni)
	}
	dst = quicAppendVarint(dst, maxStreams)
	return dst
}

func quicAppendHandshakeDoneFrame(dst []byte) []byte {
	return quicAppendVarint(dst, quicFrameHandshakeDone)
}

func quicAppendConnCloseFrame(dst []byte, errorCode, frameType uint64, reason string) []byte {
	dst = quicAppendVarint(dst, quicFrameConnClose)
	dst = quicAppendVarint(dst, errorCode)
	dst = quicAppendVarint(dst, frameType)
	dst = quicAppendVarint(dst, uint64(len(reason)))
	dst = append(dst, reason...)
	return dst
}

func quicAppendPingFrame(dst []byte) []byte {
	return quicAppendVarint(dst, quicFramePing)
}

func quicAppendPaddingFrame(dst []byte, count int) []byte {
	for i := 0; i < count; i++ {
		dst = append(dst, 0x00)
	}
	return dst
}

func quicAppendNewConnIDFrame(dst []byte, seq, retirePT uint64, connID []byte, resetToken [16]byte) []byte {
	dst = quicAppendVarint(dst, quicFrameNewConnID)
	dst = quicAppendVarint(dst, seq)
	dst = quicAppendVarint(dst, retirePT)
	dst = append(dst, byte(len(connID)))
	dst = append(dst, connID...)
	dst = append(dst, resetToken[:]...)
	return dst
}

type quicFrameParser struct {
	data []byte
	off  int
}

func (p *quicFrameParser) remaining() int {
	return len(p.data) - p.off
}

func (p *quicFrameParser) readVarint() (uint64, bool) {
	v, n := quicParseVarint(p.data[p.off:])
	if n == 0 {
		return 0, false
	}
	p.off += n
	return v, true
}

func (p *quicFrameParser) readBytes(n int) ([]byte, bool) {
	if p.off+n > len(p.data) {
		return nil, false
	}
	b := p.data[p.off : p.off+n]
	p.off += n
	return b, true
}

func (p *quicFrameParser) skip(n int) bool {
	if p.off+n > len(p.data) {
		return false
	}
	p.off += n
	return true
}

type quicFrameVisitor struct {
	onPadding       func()
	onPing          func()
	onACK           func(f quicAckFrame)
	onCrypto        func(f quicCryptoFrame)
	onStream        func(f quicStreamFrame)
	onMaxData       func(f quicMaxDataFrame)
	onMaxStreamData func(f quicMaxStreamDataFrame)
	onMaxStreams    func(f quicMaxStreamsFrame)
	onConnClose     func(f quicConnCloseFrame)
	onHandshakeDone func()
	onNewConnID     func(f quicNewConnIDFrame)
	onNewToken      func(token []byte)
}

func quicParseFrames(data []byte, v *quicFrameVisitor) error {
	p := quicFrameParser{data: data}

	for p.remaining() > 0 {
		if p.data[p.off] == 0x00 {
			p.off++
			if v.onPadding != nil {
				v.onPadding()
			}
			continue
		}

		frameType, ok := p.readVarint()
		if !ok {
			return ErrTruncated
		}

		switch {
		case frameType == quicFramePing:
			if v.onPing != nil {
				v.onPing()
			}

		case frameType == quicFrameACK || frameType == quicFrameACKECN:
			f, err := p.parseACK(frameType == quicFrameACKECN)
			if err != nil {
				return err
			}
			if v.onACK != nil {
				v.onACK(f)
			}

		case frameType == quicFrameCrypto:
			offset, ok := p.readVarint()
			if !ok {
				return ErrTruncated
			}
			length, ok := p.readVarint()
			if !ok {
				return ErrTruncated
			}
			data, ok := p.readBytes(int(length))
			if !ok {
				return ErrTruncated
			}
			if v.onCrypto != nil {
				v.onCrypto(quicCryptoFrame{offset: offset, data: data})
			}

		case frameType >= quicFrameStream && frameType <= quicFrameStreamEnd:
			f, err := p.parseStream(byte(frameType))
			if err != nil {
				return err
			}
			if v.onStream != nil {
				v.onStream(f)
			}

		case frameType == quicFrameMaxData:
			maxData, ok := p.readVarint()
			if !ok {
				return ErrTruncated
			}
			if v.onMaxData != nil {
				v.onMaxData(quicMaxDataFrame{maxData: maxData})
			}

		case frameType == quicFrameMaxStreamData:
			sid, ok := p.readVarint()
			if !ok {
				return ErrTruncated
			}
			max, ok := p.readVarint()
			if !ok {
				return ErrTruncated
			}
			if v.onMaxStreamData != nil {
				v.onMaxStreamData(quicMaxStreamDataFrame{streamID: sid, maxStreamData: max})
			}

		case frameType == quicFrameMaxStreamsBidi || frameType == quicFrameMaxStreamsUni:
			max, ok := p.readVarint()
			if !ok {
				return ErrTruncated
			}
			if v.onMaxStreams != nil {
				v.onMaxStreams(quicMaxStreamsFrame{maxStreams: max, bidi: frameType == quicFrameMaxStreamsBidi})
			}

		case frameType == quicFrameConnClose || frameType == quicFrameAppClose:
			f, err := p.parseConnClose(frameType == quicFrameAppClose)
			if err != nil {
				return err
			}
			if v.onConnClose != nil {
				v.onConnClose(f)
			}

		case frameType == quicFrameHandshakeDone:
			if v.onHandshakeDone != nil {
				v.onHandshakeDone()
			}

		case frameType == quicFrameNewConnID:
			f, err := p.parseNewConnID()
			if err != nil {
				return err
			}
			if v.onNewConnID != nil {
				v.onNewConnID(f)
			}

		case frameType == quicFrameNewToken:
			length, ok := p.readVarint()
			if !ok {
				return ErrTruncated
			}
			token, ok := p.readBytes(int(length))
			if !ok {
				return ErrTruncated
			}
			if v.onNewToken != nil {
				v.onNewToken(token)
			}

		case frameType == quicFrameResetStream:
			if _, ok := p.readVarint(); !ok {
				return ErrTruncated
			}
			if _, ok := p.readVarint(); !ok {
				return ErrTruncated
			}
			if _, ok := p.readVarint(); !ok {
				return ErrTruncated
			}

		case frameType == quicFrameStopSending:
			if _, ok := p.readVarint(); !ok {
				return ErrTruncated
			}
			if _, ok := p.readVarint(); !ok {
				return ErrTruncated
			}

		case frameType == quicFrameDataBlocked:
			if _, ok := p.readVarint(); !ok {
				return ErrTruncated
			}

		case frameType == quicFrameStreamDataBlock:
			if _, ok := p.readVarint(); !ok {
				return ErrTruncated
			}
			if _, ok := p.readVarint(); !ok {
				return ErrTruncated
			}

		case frameType == quicFrameStreamsBlockBidi || frameType == quicFrameStreamsBlockUni:
			if _, ok := p.readVarint(); !ok {
				return ErrTruncated
			}

		case frameType == quicFrameRetireConnID:
			if _, ok := p.readVarint(); !ok {
				return ErrTruncated
			}

		case frameType == quicFramePathChallenge:
			if !p.skip(8) {
				return ErrTruncated
			}

		case frameType == quicFramePathResponse:
			if !p.skip(8) {
				return ErrTruncated
			}

		default:
			return ErrH2BadHeader
		}
	}
	return nil
}

func (p *quicFrameParser) parseACK(ecn bool) (quicAckFrame, error) {
	var f quicAckFrame
	var ok bool
	f.largestAck, ok = p.readVarint()
	if !ok {
		return f, ErrTruncated
	}
	f.ackDelay, ok = p.readVarint()
	if !ok {
		return f, ErrTruncated
	}
	rangeCount, ok := p.readVarint()
	if !ok {
		return f, ErrTruncated
	}
	f.firstRange, ok = p.readVarint()
	if !ok {
		return f, ErrTruncated
	}
	if rangeCount > 0 {
		if rangeCount > 256 || rangeCount > uint64(p.remaining()) {
			return f, ErrTruncated
		}
		f.ranges = make([]quicAckRange, rangeCount)
		for i := uint64(0); i < rangeCount; i++ {
			gap, ok := p.readVarint()
			if !ok {
				return f, ErrTruncated
			}
			count, ok := p.readVarint()
			if !ok {
				return f, ErrTruncated
			}
			f.ranges[i] = quicAckRange{gap: gap, count: count}
		}
	}
	if ecn {
		if _, ok := p.readVarint(); !ok {
			return f, ErrTruncated
		}
		if _, ok := p.readVarint(); !ok {
			return f, ErrTruncated
		}
		if _, ok := p.readVarint(); !ok {
			return f, ErrTruncated
		}
	}
	return f, nil
}

func (p *quicFrameParser) parseStream(flags byte) (quicStreamFrame, error) {
	var f quicStreamFrame
	var ok bool
	f.streamID, ok = p.readVarint()
	if !ok {
		return f, ErrTruncated
	}
	if flags&quicStreamFlagOff != 0 {
		f.offset, ok = p.readVarint()
		if !ok {
			return f, ErrTruncated
		}
	}
	if flags&quicStreamFlagLen != 0 {
		length, ok := p.readVarint()
		if !ok {
			return f, ErrTruncated
		}
		f.data, ok = p.readBytes(int(length))
		if !ok {
			return f, ErrTruncated
		}
	} else {
		f.data = p.data[p.off:]
		p.off = len(p.data)
	}
	f.fin = flags&quicStreamFlagFin != 0
	return f, nil
}

func (p *quicFrameParser) parseConnClose(isApp bool) (quicConnCloseFrame, error) {
	var f quicConnCloseFrame
	f.isApp = isApp
	var ok bool
	f.errorCode, ok = p.readVarint()
	if !ok {
		return f, ErrTruncated
	}
	if !isApp {
		f.frameType, ok = p.readVarint()
		if !ok {
			return f, ErrTruncated
		}
	}
	reasonLen, ok := p.readVarint()
	if !ok {
		return f, ErrTruncated
	}
	reason, ok := p.readBytes(int(reasonLen))
	if !ok {
		return f, ErrTruncated
	}
	f.reasonPhrase = string(reason)
	return f, nil
}

func (p *quicFrameParser) parseNewConnID() (quicNewConnIDFrame, error) {
	var f quicNewConnIDFrame
	var ok bool
	f.seq, ok = p.readVarint()
	if !ok {
		return f, ErrTruncated
	}
	f.retirePT, ok = p.readVarint()
	if !ok {
		return f, ErrTruncated
	}
	cidLenByte, ok := p.readBytes(1)
	if !ok {
		return f, ErrTruncated
	}
	cidLen := int(cidLenByte[0])
	if cidLen > 20 {
		return f, ErrTruncated
	}
	f.connID, ok = p.readBytes(cidLen)
	if !ok {
		return f, ErrTruncated
	}
	token, ok := p.readBytes(16)
	if !ok {
		return f, ErrTruncated
	}
	copy(f.resetToken[:], token)
	return f, nil
}
