package core

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type H2Conn struct {
	conn              net.Conn
	reader            *TrafficAEAD
	writer            *TrafficAEAD
	hdrBuf            []byte
	server            *Server
	remoteAddr        string
	decoder           *HpackDecoder
	connWindow        atomic.Int64
	maxFrameSize      atomic.Uint32
	lastStreamID      atomic.Uint32
	initialWindowSize uint32
	streams           *ShardedMap[uint32, *H2Stream]
	writeCh           chan WriteRequest
	done              chan struct{}
	dispatchWg        sync.WaitGroup
	decryptBuf        []byte
	appBuf            []byte
	appBufValid       int
	appBufOff         int
	plain             bool

	expectContinuation uint32
	headerAccum        []byte
	headerFlags        byte
	headerEndStream    bool
	headersBuf         [][2]string

	pendingConnWindow atomic.Uint32
	activeStreams     atomic.Int32
	flowMu            sync.Mutex
	flowCond          *sync.Cond

	recvConnWindow atomic.Int64
}

func appendWriteBatch(dst []byte, batch [64]WriteRequest, n int) []byte {
	totalLen := 0
	for i := 0; i < n; i++ {
		totalLen += len(batch[i].Data)
	}
	if cap(dst) < totalLen {
		dst = make([]byte, 0, totalLen)
	}
	dst = dst[:0]
	for i := 0; i < n; i++ {
		dst = append(dst, batch[i].Data...)
	}
	return dst
}

func (s *Server) ServeH2(conn net.Conn, reader, writer *TrafficAEAD, hdrBuf []byte) {
	bc := NewBufConn(conn)
	hc := &H2Conn{
		remoteAddr:        conn.RemoteAddr().String(),
		conn:              bc,
		reader:            reader,
		writer:            writer,
		hdrBuf:            hdrBuf,
		server:            s,
		decoder:           NewHpackDecoder(),
		initialWindowSize: H2DefaultWindowSize,
		streams:           NewShardedMap[uint32, *H2Stream](Uint32Hash),
		writeCh:           make(chan WriteRequest, 512),
		done:              make(chan struct{}),
		decryptBuf:        make([]byte, 0, MaxRecordSize),
		appBuf:            make([]byte, 0, MaxRecordSize*2),
		headerAccum:       make([]byte, 0, 4096),
	}
	hc.connWindow.Store(int64(H2DefaultWindowSize))
	hc.maxFrameSize.Store(H2DefaultMaxFrameSize)
	hc.recvConnWindow.Store(int64(H2ConnectionWindowSize))
	hc.flowCond = sync.NewCond(&hc.flowMu)

	Dbg("[H2] %s starting HTTP/2 connection", hc.remoteAddr)

	go hc.writerLoop()

	defer func() {
		bc.Release()
		Dbg("[H2] %s connection closing (streams=%d)", hc.remoteAddr, hc.activeStreams.Load())
		close(hc.done)
		hc.flowCond.Broadcast()
		hc.dispatchWg.Wait()
		close(hc.writeCh)
	}()

	if !hc.readAndValidatePreface() {
		Dbg("[H2] %s preface validation failed — client may blacklist h2", hc.remoteAddr)
		return
	}

	hc.sendInitialSettingsAndWindowUpdate()

	hc.serveLoop()
}

func (hc *H2Conn) writerLoop() {
	if hc.plain {
		hc.writerLoopPlain()
		return
	}
	var batch [64]WriteRequest
	batchBuf := make([]byte, 0, 16384)
	for req := range hc.writeCh {
		batch[0] = req
		n := 1

	drain:
		for n < len(batch) {
			select {
			case next, ok := <-hc.writeCh:
				if !ok {
					break drain
				}
				batch[n] = next
				n++
			default:
				break drain
			}
		}

		if n == 1 {
			err := WriteAppData(hc.conn, hc.writer, req.Data)
			if req.Done != nil {
				req.Done <- err
			}
		} else {
			batchBuf = appendWriteBatch(batchBuf, batch, n)
			err := WriteAppData(hc.conn, hc.writer, batchBuf)
			for i := 0; i < n; i++ {
				if batch[i].Done != nil {
					batch[i].Done <- err
				}
			}
		}
	}
}

func (hc *H2Conn) enqueueWrite(frame []byte) {
	select {
	case hc.writeCh <- WriteRequest{Data: frame}:
	case <-hc.done:
	}
}

func (hc *H2Conn) enqueueWriteSync(frame []byte) error {
	done := ErrChanPool.Get().(chan error)
	select {
	case hc.writeCh <- WriteRequest{Data: frame, Done: done}:
		err := <-done
		ErrChanPool.Put(done)
		return err
	case <-hc.done:
		ErrChanPool.Put(done)
		return ErrStreamClosed
	}
}

func (hc *H2Conn) readAndValidatePreface() bool {
	if hc.plain {
		return hc.readAndValidatePrefacePlain()
	}
	_, rec, recBP, err := ReadRecordSkipCCS(hc.conn, hc.hdrBuf)
	if err != nil {
		log.Printf("[H2] read preface record: %v", err)
		return false
	}

	pt, err := hc.reader.Decrypt(rec)
	if err != nil {
		log.Printf("[H2] decrypt preface: %v", err)
		ReleaseRecordBuf(recBP)
		return false
	}

	content, ct, err := StripInnerPlaintext(pt)
	if err != nil || ct != 0x17 {
		log.Printf("[H2] preface inner type: 0x%02x err=%v", ct, err)
		ReleaseRecordBuf(recBP)
		return false
	}

	if len(content) < H2PrefaceLen {
		log.Printf("[H2] preface too short: %d bytes", len(content))
		ReleaseRecordBuf(recBP)
		return false
	}
	prefaceOk := true
	for i := 0; i < H2PrefaceLen; i++ {
		if content[i] != H2ClientPreface[i] {
			prefaceOk = false
			break
		}
	}
	if !prefaceOk {
		log.Printf("[H2] bad preface")
		ReleaseRecordBuf(recBP)
		return false
	}
	Dbg("[H2] client preface validated")

	remaining := content[H2PrefaceLen:]
	hc.appBuf = append(hc.appBuf[:0], remaining...)
	hc.appBufValid = len(hc.appBuf)
	ReleaseRecordBuf(recBP)
	return true
}

func (hc *H2Conn) sendInitialSettingsAndWindowUpdate() {
	settings := [4][2]uint32{
		{uint32(H2SettingMaxConcurrentStreams), H2MaxConcurrentStream},
		{uint32(H2SettingInitialWindowSize), H2StreamWindowSize},
		{uint32(H2SettingMaxFrameSize), H2DefaultMaxFrameSize},
		{uint32(H2SettingMaxHeaderListSize), H2MaxHeaderListSize},
	}
	settingsFrame := H2WriteSettings(nil, settings[:])
	windowFrame := H2WriteWindowUpdate(nil, 0, uint32(H2ConnectionWindowSize-H2DefaultWindowSize))
	hc.enqueueWrite(settingsFrame)
	hc.enqueueWrite(windowFrame)
}

func (hc *H2Conn) sendWindowUpdate(streamID, increment uint32) {
	frame := H2WriteWindowUpdate(nil, streamID, increment)
	hc.enqueueWrite(frame)
}

func (hc *H2Conn) sendGoAway(errCode uint32) {
	lastID := hc.lastStreamID.Load()
	Dbg("[H2] %s sending GOAWAY errCode=0x%x lastStream=%d", hc.remoteAddr, errCode, lastID)
	bp := SmallBufPool.Get().(*[]byte)
	frame := H2WriteGoAway((*bp)[:0], lastID, errCode)
	hc.enqueueWriteSync(frame)
	*bp = frame[:0]
	SmallBufPool.Put(bp)
}

func (hc *H2Conn) readAppData() error {
	if hc.plain {
		return hc.readAppDataPlain()
	}
	_, rec, recBP, err := ReadRecordSkipCCS(hc.conn, hc.hdrBuf)
	if err != nil {
		return err
	}
	pt, err := hc.reader.Decrypt(rec)
	if err != nil {
		ReleaseRecordBuf(recBP)
		return err
	}
	content, ct, err := StripInnerPlaintext(pt)
	if err != nil {
		ReleaseRecordBuf(recBP)
		return err
	}
	if ct == 0x15 {
		if len(content) >= 2 {
			log.Printf("[H2] TLS alert from peer: level=%d desc=%d", content[0], content[1])
		}
		ReleaseRecordBuf(recBP)
		return ErrH2GoAway
	}
	if ct != 0x17 {
		ReleaseRecordBuf(recBP)
		return nil
	}
	hc.appBuf = append(hc.appBuf, content...)
	hc.appBufValid = len(hc.appBuf)
	ReleaseRecordBuf(recBP)
	return nil
}

func (hc *H2Conn) consumeFrame() (*H2Frame, error) {
	for {
		avail := hc.appBufValid - hc.appBufOff
		if avail >= 9 {
			off := hc.appBufOff
			fLen := int(hc.appBuf[off])<<16 | int(hc.appBuf[off+1])<<8 | int(hc.appBuf[off+2])
			totalNeeded := 9 + fLen
			if avail >= totalNeeded {
				f := H2FramePool.Get().(*H2Frame)
				f.Length = uint32(fLen)
				if fLen > int(H2MaxFrameSize) {
					H2FramePool.Put(f)
					hc.sendGoAway(H2ErrFrameSize)
					return nil, ErrH2FrameTooLarge
				}
				f.Type = hc.appBuf[off+3]
				f.Flags = hc.appBuf[off+4]
				f.StreamID = (uint32(hc.appBuf[off+5])<<24 | uint32(hc.appBuf[off+6])<<16 | uint32(hc.appBuf[off+7])<<8 | uint32(hc.appBuf[off+8])) & 0x7fffffff
				if cap(f.Payload) >= fLen {
					f.Payload = f.Payload[:fLen]
				} else {
					f.Payload = make([]byte, fLen)
				}
				copy(f.Payload, hc.appBuf[off+9:off+totalNeeded])
				hc.appBufOff += totalNeeded
				if hc.appBufOff > cap(hc.appBuf)/2 {
					remaining := hc.appBufValid - hc.appBufOff
					copy(hc.appBuf, hc.appBuf[hc.appBufOff:hc.appBufValid])
					hc.appBufValid = remaining
					hc.appBufOff = 0
					hc.appBuf = hc.appBuf[:remaining]
				}
				return f, nil
			}
		}
		if hc.appBufOff > 0 {
			remaining := hc.appBufValid - hc.appBufOff
			copy(hc.appBuf, hc.appBuf[hc.appBufOff:hc.appBufValid])
			hc.appBufValid = remaining
			hc.appBufOff = 0
			hc.appBuf = hc.appBuf[:remaining]
		}
		if err := hc.readAppData(); err != nil {
			return nil, err
		}
	}
}

func (hc *H2Conn) serveLoop() {
	for {
		frame, err := hc.consumeFrame()
		if err != nil {
			Dbg("[H2] %s serve loop exit: %v (streams=%d)", hc.remoteAddr, err, hc.activeStreams.Load())
			return
		}
		if debugFlag.Load() {
			Dbg("[H2] frame type=0x%02x flags=0x%02x stream=%d len=%d", frame.Type, frame.Flags, frame.StreamID, frame.Length)
		}

		if hc.expectContinuation != 0 {
			if frame.Type != H2FrameContinuation || frame.StreamID != hc.expectContinuation {
				releaseH2Frame(frame)
				hc.sendGoAway(H2ErrProtocol)
				return
			}
			hc.handleContinuation(frame)
			releaseH2Frame(frame)
			continue
		}

		hc.handleFrame(frame)
		releaseH2Frame(frame)

		select {
		case <-hc.done:
			return
		default:
		}
	}
}

func (hc *H2Conn) handleFrame(f *H2Frame) {
	switch f.Type {
	case H2FrameSettings:
		if f.StreamID != 0 {
			hc.sendGoAway(H2ErrProtocol)
			return
		}
		if f.Flags&H2FlagAck != 0 {
			if len(f.Payload) > 0 {
				hc.sendGoAway(H2ErrFrameSize)
			}
			return
		}
		if len(f.Payload)%6 != 0 {
			hc.sendGoAway(H2ErrFrameSize)
			return
		}
		hc.processSettings(f.Payload)
		ack := H2WriteSettingsAck(nil)
		hc.enqueueWrite(ack)

	case H2FrameHeaders:
		hc.handleHeaders(f)

	case H2FrameData:
		hc.handleData(f)

	case H2FrameWindowUpdate:
		if len(f.Payload) != 4 {
			hc.sendGoAway(H2ErrFrameSize)
			return
		}
		inc := (uint32(f.Payload[0])<<24 | uint32(f.Payload[1])<<16 | uint32(f.Payload[2])<<8 | uint32(f.Payload[3])) & 0x7fffffff
		if inc == 0 {
			if f.StreamID == 0 {
				hc.sendGoAway(H2ErrProtocol)
			} else {
				hc.enqueueWrite(H2WriteRSTStream(nil, f.StreamID, H2ErrProtocol))
			}
			return
		}
		if f.StreamID == 0 {
			newWin := hc.connWindow.Add(int64(inc))
			if newWin > 2147483647 {
				hc.sendGoAway(H2ErrFlowControl)
				return
			}
			hc.flowCond.Broadcast()
		} else {
			if stream, ok := hc.streams.Load(f.StreamID); ok {
				newWin := stream.Window.Add(int64(inc))
				if newWin > 2147483647 {
					hc.enqueueWrite(H2WriteRSTStream(nil, f.StreamID, H2ErrFlowControl))
					return
				}
				hc.flowCond.Broadcast()
			}
		}

	case H2FramePing:
		if f.StreamID != 0 {
			hc.sendGoAway(H2ErrProtocol)
			return
		}
		if len(f.Payload) != 8 {
			hc.sendGoAway(H2ErrFrameSize)
			return
		}
		if f.Flags&H2FlagAck == 0 {
			var pingData [8]byte
			copy(pingData[:], f.Payload[:8])
			pong := H2WritePing(nil, true, pingData)
			hc.enqueueWrite(pong)
		}

	case H2FrameRSTStream:
		if f.StreamID == 0 {
			hc.sendGoAway(H2ErrProtocol)
			return
		}
		if len(f.Payload) != 4 {
			hc.sendGoAway(H2ErrFrameSize)
			return
		}
		if stream, ok := hc.streams.Load(f.StreamID); ok {
			stream.State.Store(StreamClosed)
			hc.streams.Delete(f.StreamID)
			hc.activeStreams.Add(-1)
			stream.Reset()
			StreamPool.Put(stream)
		}

	case H2FrameGoAway:
		return

	case H2FramePriority:
		if f.StreamID == 0 {
			hc.sendGoAway(H2ErrProtocol)
			return
		}
		if len(f.Payload) != 5 {
			hc.sendGoAway(H2ErrFrameSize)
			return
		}

	case H2FramePushPromise:
		hc.sendGoAway(H2ErrProtocol)
		return

	case H2FrameContinuation:
		hc.sendGoAway(H2ErrProtocol)

	default:
	}
}

func (hc *H2Conn) processSettings(payload []byte) {
	for i := 0; i+6 <= len(payload); i += 6 {
		id := uint16(payload[i])<<8 | uint16(payload[i+1])
		val := uint32(payload[i+2])<<24 | uint32(payload[i+3])<<16 | uint32(payload[i+4])<<8 | uint32(payload[i+5])
		switch id {
		case H2SettingMaxFrameSize:
			if val >= 16384 && val <= uint32(H2MaxFrameSize) {
				hc.maxFrameSize.Store(val)
			}
		case H2SettingInitialWindowSize:
			if val > 2147483647 {
				hc.sendGoAway(H2ErrFlowControl)
				return
			}
			oldSize := hc.initialWindowSize
			delta := int64(val) - int64(oldSize)
			hc.initialWindowSize = val
			hc.streams.Range(func(id uint32, stream *H2Stream) bool {
				newWindow := stream.Window.Load() + delta
				if newWindow > 2147483647 {
					hc.enqueueWrite(H2WriteRSTStream(nil, id, H2ErrFlowControl))
					return true
				}
				stream.Window.Store(newWindow)
				return true
			})
		case H2SettingHeaderTableSize:
			if val > 65536 {
				val = 65536
			}
			hc.decoder.protocolMaxSize = int(val)
			hc.decoder.setMaxSize(int(val))
		}
	}
}

func (hc *H2Conn) handleHeaders(f *H2Frame) {
	if f.StreamID == 0 {
		hc.sendGoAway(H2ErrProtocol)
		return
	}
	payload := f.Payload
	if f.Flags&H2FlagPadded != 0 && len(payload) > 0 {
		padLen := int(payload[0])
		payload = payload[1:]
		if padLen > len(payload) {
			hc.enqueueWrite(H2WriteRSTStream(nil, f.StreamID, H2ErrProtocol))
			return
		}
		payload = payload[:len(payload)-padLen]
	}
	if f.Flags&H2FlagPriority != 0 && len(payload) >= 5 {
		payload = payload[5:]
	}

	if f.Flags&H2FlagEndHeaders == 0 {
		hc.expectContinuation = f.StreamID
		hc.headerAccum = append(hc.headerAccum[:0], payload...)
		hc.headerFlags = f.Flags
		hc.headerEndStream = f.Flags&H2FlagEndStream != 0
		return
	}

	hc.processDecodedHeaders(f.StreamID, payload, f.Flags&H2FlagEndStream != 0)
}

func (hc *H2Conn) handleContinuation(f *H2Frame) {
	hc.headerAccum = append(hc.headerAccum, f.Payload...)
	if len(hc.headerAccum) > H2MaxHeaderListSize*4 {
		hc.expectContinuation = 0
		hc.sendGoAway(H2ErrEnhanceYourCalm)
		return
	}
	if f.Flags&H2FlagEndHeaders != 0 {
		streamID := hc.expectContinuation
		endStream := hc.headerEndStream
		hc.expectContinuation = 0
		hc.processDecodedHeaders(streamID, hc.headerAccum, endStream)
	}
}

func (hc *H2Conn) processDecodedHeaders(streamID uint32, headerBlock []byte, endStream bool) {
	headers, err := hc.decoder.DecodeInto(hc.headersBuf, headerBlock)
	hc.headersBuf = headers
	if err != nil {
		hc.enqueueWrite(H2WriteRSTStream(nil, streamID, H2ErrCompression))
		return
	}

	if len(headers) > 128 {
		hc.enqueueWrite(H2WriteRSTStream(nil, streamID, H2ErrEnhanceYourCalm))
		return
	}

	if int(hc.activeStreams.Load()) >= H2MaxConcurrentStream {
		hc.enqueueWrite(H2WriteRSTStream(nil, streamID, H2ErrRefusedStream))
		return
	}

	stream := StreamPool.Get().(*H2Stream)
	stream.Reset()
	stream.ID = streamID
	stream.Window.Store(int64(hc.initialWindowSize))

	for i := range headers {
		switch headers[i][0] {
		case ":method":
			stream.Method = headers[i][1]
		case ":path":
			stream.Path = sanitizeRequestPath(headers[i][1])
		case ":scheme":
			stream.Scheme = headers[i][1]
		case ":authority":
			if ValidateHost(headers[i][1]) {
				stream.Auth = headers[i][1]
			}
		default:
			stream.Headers = append(stream.Headers, headers[i])
		}
	}

	prevLastStream := hc.lastStreamID.Load()
	if streamID%2 == 0 || (prevLastStream > 0 && streamID <= prevLastStream) {
		hc.sendGoAway(H2ErrProtocol)
		stream.Reset()
		StreamPool.Put(stream)
		return
	}
	hc.lastStreamID.Store(streamID)

	if _, exists := hc.streams.Load(streamID); exists {
		hc.enqueueWrite(H2WriteRSTStream(nil, streamID, H2ErrProtocol))
		stream.Reset()
		StreamPool.Put(stream)
		return
	}

	hc.streams.Store(streamID, stream)
	hc.activeStreams.Add(1)

	if stream.Method == "" || stream.Path == "" {
		hc.enqueueWrite(H2WriteRSTStream(nil, streamID, H2ErrProtocol))
		hc.streams.Delete(streamID)
		hc.activeStreams.Add(-1)
		stream.Reset()
		StreamPool.Put(stream)
		return
	}

	if endStream {
		stream.State.Store(StreamHalfClosed)
		hc.dispatchWg.Add(1)
		go hc.dispatchRequest(stream)
	} else {
		stream.State.Store(StreamOpen)
	}
}

func (hc *H2Conn) handleData(f *H2Frame) {
	if f.StreamID == 0 {
		hc.sendGoAway(H2ErrProtocol)
		return
	}
	stream, ok := hc.streams.Load(f.StreamID)
	if !ok {
		return
	}

	if stream.State.Load() >= StreamHalfClosed {
		hc.enqueueWrite(H2WriteRSTStream(nil, f.StreamID, H2ErrStreamClosed))
		return
	}

	payload := f.Payload
	if f.Flags&H2FlagPadded != 0 && len(payload) > 0 {
		padLen := int(payload[0])
		payload = payload[1:]
		if padLen > len(payload) {
			hc.enqueueWrite(H2WriteRSTStream(nil, f.StreamID, H2ErrProtocol))
			return
		}
		payload = payload[:len(payload)-padLen]
	}

	consumed := int64(len(f.Payload))
	newRecvWin := hc.recvConnWindow.Add(-consumed)
	if newRecvWin < 0 {
		hc.sendGoAway(H2ErrFlowControl)
		return
	}

	stream.Body = append(stream.Body, payload...)

	maxBody := hc.server.config.MaxBodySize
	if maxBody > 0 && int64(len(stream.Body)) > maxBody {
		hc.enqueueWrite(H2WriteRSTStream(nil, f.StreamID, H2ErrCancel))
		hc.streams.Delete(f.StreamID)
		hc.activeStreams.Add(-1)
		stream.Reset()
		StreamPool.Put(stream)
		return
	}

	connConsumed := uint32(len(f.Payload))
	hc.pendingConnWindow.Add(connConsumed)

	if hc.pendingConnWindow.Load() > H2ConnectionWindowSize/2 {
		connUpdate := hc.pendingConnWindow.Swap(0)
		if connUpdate > 0 {
			hc.recvConnWindow.Add(int64(connUpdate))
			hc.sendWindowUpdate(0, connUpdate)
		}
	}
	hc.sendWindowUpdate(f.StreamID, connConsumed)

	if f.Flags&H2FlagEndStream != 0 {
		stream.State.Store(StreamHalfClosed)
		hc.dispatchWg.Add(1)
		go hc.dispatchRequest(stream)
	}
}

func (hc *H2Conn) dispatchRequest(stream *H2Stream) {
	defer hc.dispatchWg.Done()
	Stats.TotalReqs.Add(1)
	if hc.server.logRequests.Load() {
		log.Printf("[H2] stream %d: %s %s", stream.ID, stream.Method, stream.Path)
	}

	req := RequestPool.Get().(*Request)
	req.Reset()
	req.Method = stream.Method
	req.Path = stream.Path
	req.Proto = "HTTP/2"
	req.Headers = append(req.Headers[:0], stream.Headers...)
	req.Body = stream.Body
	req.StreamID = stream.ID
	req.IsH2 = true
	req.StreamWriter = hc.server.NewH2StreamWriter(stream.ID, hc, &stream.Window)
	req.Host = stream.Auth
	req.cachedHost = stream.Auth
	req.headerCacheMask = headerCacheHost
	req.RemoteAddr = hc.remoteAddr

	resp := ResponsePool.Get().(*Response)
	resp.Reset()
	resp.SetSW(req.StreamWriter)

	hc.server.dispatch(req, resp)

	if resp.IsStreamed() {
		stream.State.Store(StreamClosed)
		hc.streams.Delete(stream.ID)
		hc.activeStreams.Add(-1)
		stream.Reset()
		StreamPool.Put(stream)
		if sw, ok := req.StreamWriter.(*H2StreamWriter); ok {
			H2StreamWriterPool.Put(sw)
		}
		RequestPool.Put(req)
		ResponsePool.Put(resp)
		return
	}

	hc.writeH2Response(stream.ID, resp)

	stream.State.Store(StreamClosed)
	hc.streams.Delete(stream.ID)
	hc.activeStreams.Add(-1)
	stream.Reset()
	StreamPool.Put(stream)

	if sw, ok := req.StreamWriter.(*H2StreamWriter); ok {
		H2StreamWriterPool.Put(sw)
	}
	RequestPool.Put(req)
	ResponsePool.Put(resp)
}

func (hc *H2Conn) writeH2Response(streamID uint32, resp *Response) {
	bp := MediumBufPool.Get().(*[]byte)

	enc := HpackEncoder{}
	enc.Reset((*bp)[:0])
	enc.EncodeStatus(resp.StatusCode)

	if resp.ContentType != "" {
		enc.EncodeHeader("content-type", resp.ContentType)
	}
	var clBuf [20]byte
	clStr := appendUint(clBuf[:0], int64(resp.BodyLen()))
	enc.EncodeHeader("content-length", UnsafeString(clStr))
	for i := range resp.Headers {
		enc.EncodeHeader(resp.Headers[i][0], resp.Headers[i][1])
	}
	enc.EncodeHeader("server", "ALOS")

	headerPayload := enc.Buf

	body := resp.GetBody()

	if len(body) == 0 {
		headerFrame := H2WriteFrame(nil, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, streamID, headerPayload)
		hc.enqueueWrite(headerFrame)
	} else {
		maxFrame := int(hc.maxFrameSize.Load())

		if len(body) <= maxFrame {
			hdrFrameLen := 9 + len(headerPayload)
			dataFrameLen := 9 + len(body)
			combined := make([]byte, hdrFrameLen+dataFrameLen)
			combined[0] = byte(len(headerPayload) >> 16)
			combined[1] = byte(len(headerPayload) >> 8)
			combined[2] = byte(len(headerPayload))
			combined[3] = H2FrameHeaders
			combined[4] = H2FlagEndHeaders
			combined[5] = byte(streamID >> 24)
			combined[6] = byte(streamID >> 16)
			combined[7] = byte(streamID >> 8)
			combined[8] = byte(streamID)
			copy(combined[9:], headerPayload)
			off := hdrFrameLen
			combined[off] = byte(len(body) >> 16)
			combined[off+1] = byte(len(body) >> 8)
			combined[off+2] = byte(len(body))
			combined[off+3] = H2FrameData
			combined[off+4] = H2FlagEndStream
			combined[off+5] = byte(streamID >> 24)
			combined[off+6] = byte(streamID >> 16)
			combined[off+7] = byte(streamID >> 8)
			combined[off+8] = byte(streamID)
			copy(combined[off+9:], body)
			hc.enqueueWrite(combined)
		} else {
			headerFrame := H2WriteFrame(nil, H2FrameHeaders, H2FlagEndHeaders, streamID, headerPayload)
			hc.enqueueWrite(headerFrame)
			for len(body) > 0 {
				chunk := body
				if len(chunk) > maxFrame {
					chunk = chunk[:maxFrame]
				}

				waitStart := time.Now()
				hc.flowCond.L.Lock()
				for {
					connAvail := hc.connWindow.Load()
					if connAvail > 0 {
						if int64(len(chunk)) > connAvail {
							chunk = chunk[:int(connAvail)]
						}
						break
					}
					select {
					case <-hc.done:
						hc.flowCond.L.Unlock()
						goto writeEnd
					default:
					}
					if time.Since(waitStart) > 30*time.Second {
						hc.flowCond.L.Unlock()
						goto writeEnd
					}
					hc.flowCond.Wait()
				}
				hc.flowCond.L.Unlock()

				body = body[len(chunk):]

				if hc.server.connLimiter != nil {
					hc.server.connLimiter.ThrottleDownload(int64(len(chunk)))
				}
				if hc.server.globalLimiter != nil {
					if hc.server.globalLimiter.Download != nil {
						hc.server.globalLimiter.Download.Wait(int64(len(chunk)))
					}
				}

				hc.connWindow.Add(-int64(len(chunk)))

				flags := byte(0)
				if len(body) == 0 {
					flags = H2FlagEndStream
				}
				dataFrame := H2WriteFrame(nil, H2FrameData, flags, streamID, chunk)
				hc.enqueueWrite(dataFrame)
			}
		}
	}
writeEnd:
	*bp = enc.Buf[:0]
	MediumBufPool.Put(bp)
}
