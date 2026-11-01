//go:build linux && amd64

package core

import (
	"math"
	"slices"
	"sync/atomic"

	"github.com/guno1928/turbo"
)

const (
	h2MaxResetsPerWindow = 200
	h2ResetWindowNanos   = 1_000_000_000
	h2MaxCtrlPerWindow   = 5000
	h2MaxWindowSize      = 1<<31 - 1
	h2GoAwayMinPayload   = 8
	h2MaxRequestFields   = 128

	h2ParkedBytesHardFactor = 8

	h2FrameHeaderLen    = 9
	h2SealedDataMax     = MaxRecordPayload - 1 - h2FrameHeaderLen
	h2DirectSealMinBody = H2DefaultMaxFrameSize

	h2StatusHeaderListTooLarge = 431
)

type tlsWorkerH2State struct {
	decoder           *HpackDecoder
	streams           map[uint32]*H2Stream
	initialWindowSize uint32
	maxFrameSize      uint32
	connWindow        int64
	recvConnWindow    int64
	pendingConnWindow uint32
	lastStreamID      uint32
	highestStreamID   uint32

	prefaceReceived    bool
	expectContinuation uint32
	headerEndStream    bool
	appBufOff          int
	headerAccum        []byte
	headersBuf         [][2]string

	sending map[uint32]*H2Stream
	busy    *H2Stream

	rstCount     int
	rstWindow    int64
	sendingBytes int64
	parkedBytes  int64
	ctrlCount    int
	ctrlWindow   int64

	peerGoingAway bool
	bodyReserved  atomic.Int64

	encTable hpackEncTable

	sealBatch     bool
	sealedOut     []byte
	sealedBacklog int
	directSent    uint64
	doneHead      *H2Stream
	doneTail      *H2Stream
	doneConnNext  *epollConn
}

func (st *tlsWorkerH2State) init(tableSize uint32, headerListLimit int) {
	if st.decoder == nil {
		st.decoder = HpackDecoderPool.Get().(*HpackDecoder)
	}
	*st.decoder = HpackDecoder{
		maxTableSize:         int(tableSize),
		protocolMaxSize:      int(tableSize),
		allowExtendedConnect: true,
		maxHeaderListSize:    headerListLimit,
	}
	if st.streams == nil {
		st.streams = make(map[uint32]*H2Stream, 4)
	} else {
		for id, stream := range st.streams {
			stream.Reset()
			StreamPool.Put(stream)
			delete(st.streams, id)
		}
	}
	if st.sending == nil {
		st.sending = make(map[uint32]*H2Stream, 4)
	} else {
		for id, stream := range st.sending {
			stream.Reset()
			StreamPool.Put(stream)
			delete(st.sending, id)
		}
	}
	st.initialWindowSize = H2DefaultWindowSize
	st.maxFrameSize = H2DefaultMaxFrameSize
	st.connWindow = int64(H2DefaultWindowSize)
	st.recvConnWindow = int64(H2ConnectionWindowSize)
	st.pendingConnWindow = 0
	st.lastStreamID = 0
	st.highestStreamID = 0
	st.prefaceReceived = false
	st.expectContinuation = 0
	st.headerEndStream = false
	st.appBufOff = 0
	st.headerAccum = shrinkBuffer(st.headerAccum, 4096)
	clear(st.headersBuf)
	if cap(st.headersBuf) > 128 {
		st.headersBuf = nil
	} else {
		st.headersBuf = st.headersBuf[:0]
	}
	st.rstCount = 0
	st.rstWindow = 0
	st.sendingBytes = 0
	st.parkedBytes = 0
	st.ctrlCount = 0
	st.ctrlWindow = 0
	st.peerGoingAway = false
	st.encTable.reset()
}

func (st *tlsWorkerH2State) countReset() bool {
	now := turbo.UnixNano()
	if now-st.rstWindow > h2ResetWindowNanos {
		st.rstWindow = now
		st.rstCount = 0
	}
	st.rstCount++
	return st.rstCount > h2MaxResetsPerWindow
}

func (st *tlsWorkerH2State) countCtrl() bool {
	now := turbo.UnixNano()
	if now-st.ctrlWindow > h2ResetWindowNanos {
		st.ctrlWindow = now
		st.ctrlCount = 0
	}
	st.ctrlCount++
	return st.ctrlCount > h2MaxCtrlPerWindow
}

func h2HeaderListLimitFor(maxHeaderSize int) int {
	const fieldOverheadAllowance = hpackEntryOverhead * h2MaxRequestFields
	return min(maxHeaderSize, math.MaxUint32-fieldOverheadAllowance) + fieldOverheadAllowance
}

func (s *Server) h2HeaderListLimit() int {
	return h2HeaderListLimitFor(s.limits.Load().MaxHeaderSize)
}

func appendH2ServerSettingsFlight(dst []byte, s *Server) []byte {
	settings := [...][2]uint32{
		{uint32(H2SettingHeaderTableSize), s.h2HeaderTableSize()},
		{uint32(H2SettingMaxConcurrentStreams), s.h2MaxStreams()},
		{uint32(H2SettingInitialWindowSize), s.h2InitialWindow()},
		{uint32(H2SettingMaxFrameSize), s.h2MaxFrameSize()},
		{uint32(H2SettingMaxHeaderListSize), uint32(s.h2HeaderListLimit())},
		{uint32(H2SettingEnableConnectProtocol), 1},
	}
	dst = H2WriteSettings(dst, settings[:])
	return appendH2WindowUpdateFrame(dst, 0, uint32(H2ConnectionWindowSize-H2DefaultWindowSize))
}

func appendFastH2RootResponse(dst []byte, fast *h2RootFastResponse, streamID uint32, maxFrame int) []byte {
	off := len(dst)
	headerEnd := off + 9 + len(fast.headerPayload)
	if len(fast.framed) > 0 {
		dst = append(dst, fast.framed...)
		dst[off+5] = byte(streamID >> 24)
		dst[off+6] = byte(streamID >> 16)
		dst[off+7] = byte(streamID >> 8)
		dst[off+8] = byte(streamID)
		if fast.dataFrameOff >= 0 {
			dataOff := off + fast.dataFrameOff
			dst[dataOff+5] = byte(streamID >> 24)
			dst[dataOff+6] = byte(streamID >> 16)
			dst[dataOff+7] = byte(streamID >> 8)
			dst[dataOff+8] = byte(streamID)
		}
		refreshH2DateField(dst[off+9 : headerEnd])
		return dst
	}
	if len(fast.body) == 0 {
		dst = appendH2Frame(dst, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, streamID, fast.headerPayload)
		refreshH2DateField(dst[off+9 : headerEnd])
		return finishH2HeadersFrame(dst, off, maxFrame)
	}
	dst = appendH2Frame(dst, H2FrameHeaders, H2FlagEndHeaders, streamID, fast.headerPayload)
	refreshH2DateField(dst[off+9 : headerEnd])
	dst = finishH2HeadersFrame(dst, off, maxFrame)
	remaining := fast.body
	for len(remaining) > 0 {
		chunk := remaining
		if len(chunk) > maxFrame {
			chunk = chunk[:maxFrame]
		}
		flags := byte(0)
		if len(chunk) == len(remaining) {
			flags = H2FlagEndStream
		}
		dst = appendH2Frame(dst, H2FrameData, flags, streamID, chunk)
		remaining = remaining[len(chunk):]
	}
	return dst
}

func appendH2StatusOnlyResponse(dst []byte, streamID uint32, status int, serverName string) []byte {
	return appendH2StatusOnlyResponseIndexed(dst, streamID, status, serverName, nil, H2DefaultMaxFrameSize)
}

func appendH2StatusOnlyResponseIndexed(dst []byte, streamID uint32, status int, serverName string, tbl *hpackEncTable, maxFrame int) []byte {
	off := len(dst)
	enc := HpackEncoder{Buf: appendH2Frame(dst, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, streamID, nil)}
	encodeH2ResponseHeadersIndexed(&enc, tbl, status, "", 0, nil, serverName)
	return finishH2HeadersFrame(enc.Buf, off, maxFrame)
}

func appendH2HeaderBlockFrame(dst []byte, streamID uint32, flags byte, tbl *hpackEncTable, block []byte, maxFrame int) []byte {
	off := len(dst)
	if !tbl.pendingUpdate {
		return finishH2HeadersFrame(appendH2Frame(dst, H2FrameHeaders, flags, streamID, block), off, maxFrame)
	}
	enc := HpackEncoder{Buf: appendH2Frame(dst, H2FrameHeaders, flags, streamID, nil)}
	tbl.beginBlock(&enc)
	enc.Buf = append(enc.Buf, block...)
	return finishH2HeadersFrame(enc.Buf, off, maxFrame)
}

func appendH2ResponseHeadersFrame(dst []byte, streamID uint32, resp *Response, endStream bool) []byte {
	return appendH2ResponseHeadersFrameIndexed(dst, streamID, resp, endStream, nil, respServerName(resp), H2DefaultMaxFrameSize)
}

func appendH2ResponseHeadersFrameIndexed(dst []byte, streamID uint32, resp *Response, endStream bool, tbl *hpackEncTable, serverName string, maxFrame int) []byte {
	flags := byte(H2FlagEndHeaders)
	if endStream {
		flags |= H2FlagEndStream
	}
	off := len(dst)
	enc := HpackEncoder{Buf: appendH2Frame(dst, H2FrameHeaders, flags, streamID, nil)}
	encodeH2ResponseHeadersIndexed(&enc, tbl, resp.StatusCode, resp.ContentType, int64(resp.headerContentLength()), resp.Headers, serverName)
	return finishH2HeadersFrame(enc.Buf, off, maxFrame)
}

func finishH2HeadersFrame(dst []byte, off, maxFrame int) []byte {
	n := len(dst) - off - h2FrameHeaderLen
	if n > maxFrame {
		return fragmentH2HeadersFrame(dst, off, maxFrame)
	}
	putH2FrameLength(dst[off:], n)
	return dst
}

func fragmentH2HeadersFrame(dst []byte, off, maxFrame int) []byte {
	blockStart := off + h2FrameHeaderLen
	blockLen := len(dst) - blockStart
	streamID := uint32(dst[off+5])<<24 | uint32(dst[off+6])<<16 | uint32(dst[off+7])<<8 | uint32(dst[off+8])
	flags := dst[off+4]
	frames := (blockLen + maxFrame - 1) / maxFrame
	end := len(dst)
	dst = slices.Grow(dst, (frames-1)*h2FrameHeaderLen)[:end+(frames-1)*h2FrameHeaderLen]
	for i := frames - 1; i > 0; i-- {
		chunkStart := blockStart + i*maxFrame
		chunkLen := min(maxFrame, end-chunkStart)
		frameOff := off + i*(h2FrameHeaderLen+maxFrame)
		copy(dst[frameOff+h2FrameHeaderLen:], dst[chunkStart:chunkStart+chunkLen])
		continuationFlags := byte(0)
		if i == frames-1 {
			continuationFlags = H2FlagEndHeaders
		}
		putH2FrameHeader(dst[frameOff:], H2FrameContinuation, continuationFlags, streamID, chunkLen)
	}
	putH2FrameHeader(dst[off:], H2FrameHeaders, flags&^H2FlagEndHeaders, streamID, maxFrame)
	return dst
}

func putH2FrameLength(frame []byte, n int) {
	frame[0] = byte(n >> 16)
	frame[1] = byte(n >> 8)
	frame[2] = byte(n)
}

func appendH2SettingsAckFrame(dst []byte) []byte {
	return appendH2Frame(dst, H2FrameSettings, H2FlagAck, 0, nil)
}

func appendH2WindowUpdateFrame(dst []byte, streamID, increment uint32) []byte {
	var payload [4]byte
	v := increment & 0x7fffffff
	payload[0] = byte(v >> 24)
	payload[1] = byte(v >> 16)
	payload[2] = byte(v >> 8)
	payload[3] = byte(v)
	return appendH2Frame(dst, H2FrameWindowUpdate, 0, streamID, payload[:])
}

func appendH2GoAwayFrame(dst []byte, lastStream, errCode uint32) []byte {
	var payload [8]byte
	payload[0] = byte(lastStream >> 24)
	payload[1] = byte(lastStream >> 16)
	payload[2] = byte(lastStream >> 8)
	payload[3] = byte(lastStream)
	payload[4] = byte(errCode >> 24)
	payload[5] = byte(errCode >> 16)
	payload[6] = byte(errCode >> 8)
	payload[7] = byte(errCode)
	return appendH2Frame(dst, H2FrameGoAway, 0, 0, payload[:])
}

func appendH2RSTStreamFrame(dst []byte, streamID, errCode uint32) []byte {
	var payload [4]byte
	payload[0] = byte(errCode >> 24)
	payload[1] = byte(errCode >> 16)
	payload[2] = byte(errCode >> 8)
	payload[3] = byte(errCode)
	return appendH2Frame(dst, H2FrameRSTStream, 0, streamID, payload[:])
}

func appendH2PingFrame(dst []byte, ack bool, data [8]byte) []byte {
	flags := byte(0)
	if ack {
		flags = H2FlagAck
	}
	return appendH2Frame(dst, H2FramePing, flags, 0, data[:])
}

func (st *tlsWorkerH2State) linkBusy(s *H2Stream) {
	s.busyPrev = nil
	s.busyNext = st.busy
	if st.busy != nil {
		st.busy.busyPrev = s
	}
	st.busy = s
}

func (st *tlsWorkerH2State) unlinkBusy(s *H2Stream) {
	if s.busyPrev != nil {
		s.busyPrev.busyNext = s.busyNext
	} else if st.busy == s {
		st.busy = s.busyNext
	}
	if s.busyNext != nil {
		s.busyNext.busyPrev = s.busyPrev
	}
	s.busyPrev = nil
	s.busyNext = nil
}

func (st *tlsWorkerH2State) cancelBusy(cause error) {
	for s := st.busy; s != nil; s = s.busyNext {
		s.cancel.cancel(cause)
	}
}

func (st *tlsWorkerH2State) findBusy(id uint32) *H2Stream {
	for s := st.busy; s != nil; s = s.busyNext {
		if s.ID == id {
			return s
		}
	}
	return nil
}

func (st *tlsWorkerH2State) cancelBusyStream(id uint32, cause error) *H2Stream {
	s := st.findBusy(id)
	if s == nil || s.abandoned {
		return nil
	}
	s.abandoned = true
	s.cancel.cancel(cause)
	return s
}

func (st *tlsWorkerH2State) releaseSending(id uint32, stream *H2Stream) {
	delete(st.sending, id)
	st.sendingBytes -= int64(stream.stallBytes)
	st.parkedBytes -= int64(stream.parkedBytes)
	stream.Reset()
	StreamPool.Put(stream)
}

func appendH2Frame(dst []byte, typ, flags byte, streamID uint32, payload []byte) []byte {
	pLen := len(payload)
	off := len(dst)
	needed := off + h2FrameHeaderLen + pLen
	if cap(dst) < needed {
		dst = slices.Grow(dst, h2FrameHeaderLen+pLen)
	}
	dst = dst[:needed]
	putH2FrameHeader(dst[off:], typ, flags, streamID, pLen)
	if pLen > 0 {
		copy(dst[off+h2FrameHeaderLen:], payload)
	}
	return dst
}

func appendH2FrameHeader(dst []byte, typ, flags byte, streamID uint32, pLen int) []byte {
	off := len(dst)
	dst = slices.Grow(dst, h2FrameHeaderLen)[:off+h2FrameHeaderLen]
	putH2FrameHeader(dst[off:], typ, flags, streamID, pLen)
	return dst
}

func putH2FrameHeader(frame []byte, typ, flags byte, streamID uint32, pLen int) {
	_ = frame[8]
	frame[0] = byte(pLen >> 16)
	frame[1] = byte(pLen >> 8)
	frame[2] = byte(pLen)
	frame[3] = typ
	frame[4] = flags
	frame[5] = byte(streamID >> 24)
	frame[6] = byte(streamID >> 16)
	frame[7] = byte(streamID >> 8)
	frame[8] = byte(streamID)
}
