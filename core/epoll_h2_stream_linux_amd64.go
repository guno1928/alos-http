//go:build linux && amd64

package core

import (
	"sync"
	"time"

	"github.com/guno1928/turbo"
)

const (
	h2StreamPendingCap     = 256 << 10
	h2StreamSocketHighMark = 256 << 10
	h2StreamPendingKeep    = 2 * h2StreamPendingCap
)

var h2StreamStallTimeout = 30 * time.Second

var errH2StreamStalled = &staticError{"stream stalled waiting for flow-control window"}

var epollH2StreamWriterPool sync.Pool

func init() { epollH2StreamWriterPool.New = newEpollH2StreamWriter }

func newEpollH2StreamWriter() any {
	sw := &epollH2StreamWriter{}
	sw.space = sync.NewCond(&sw.mu)
	sw.pumpFn = func(w *epollWorker) { sw.c.h2PumpTask(w, sw) }
	return sw
}

type epollH2StreamWriter struct {
	mu     sync.Mutex
	space  *sync.Cond
	pumpFn func(*epollWorker)

	c        *epollConn
	w        *epollWorker
	stream   *H2Stream
	gen      uint32
	streamID uint32

	method       string
	serverName   string
	altSvc       *altSvcHeader
	maxWrite     int64
	written      int64
	cors         streamCORSHead
	headerCalled bool
	suppressBody bool

	header      []byte
	pending     []byte
	pendingOff  int
	headerReady bool
	headersOut  bool
	ended       bool
	finished    bool
	handlerDone bool
	registered  bool
	endedEarly  bool
	pumpQueued  bool
	sendRST     bool
	err         error
	file        h2FileSend
}

func (c *epollConn) newH2StreamWriter(req *Request) StreamWriter {
	stream := req.h2Stream
	sw := epollH2StreamWriterPool.Get().(*epollH2StreamWriter)
	sw.c, sw.w, sw.stream = c, c.worker, stream
	sw.gen, sw.streamID = stream.dispatchGen, stream.ID
	sw.method = req.Method
	sw.serverName = c.worker.server.config.ServerName
	sw.altSvc = c.worker.server.altSvcFor(req.IsTLS)
	sw.maxWrite = c.worker.server.config.MaxWriteSize
	if req.h2WebSocket {
		sw.maxWrite = 0
	}
	sw.cors.bind(req)
	return sw
}

func (sw *epollH2StreamWriter) WriteHeader(statusCode int, headers [][2]string, contentType string) error {
	if sw.headerCalled {
		return nil
	}
	sw.headerCalled = true
	headers = sw.cors.withCORS(headers)
	sw.suppressBody, _ = responseBodyDisposition(sw.method, statusCode)

	bp := MediumBufPool.Get().(*[]byte)
	enc := HpackEncoder{}
	enc.Reset((*bp)[:0])
	encodeH2ResponseHeaders(&enc, statusCode, contentType, -1, headers, sw.serverName)
	enc.Buf = appendAltSvcHPACK(enc.Buf, sw.altSvc, headers)

	sw.mu.Lock()
	sw.header = append(sw.header[:0], enc.Buf...)
	sw.headerReady = true
	err := sw.err
	queue := sw.claimPumpLocked()
	sw.mu.Unlock()

	*bp = enc.Buf[:0]
	MediumBufPool.Put(bp)
	if queue {
		sw.w.postTask(sw.pumpFn)
	}
	return err
}

func (sw *epollH2StreamWriter) WriteChunk(data []byte) error {
	if !sw.headerCalled {
		return ErrStreamClosed
	}
	if sw.suppressBody {
		return nil
	}
	if sw.maxWrite > 0 {
		sw.written += int64(len(data))
		if sw.written > sw.maxWrite {
			return ErrBodyTooLarge
		}
	}
	for len(data) > 0 {
		sw.mu.Lock()
		if err := sw.waitSpaceLocked(); err != nil {
			queue := sw.claimPumpLocked()
			sw.mu.Unlock()
			if queue {
				sw.w.postTask(sw.pumpFn)
			}
			return err
		}
		n := min(len(data), h2StreamPendingCap-sw.bufferedLocked())
		sw.pending = append(sw.pending, data[:n]...)
		data = data[n:]
		queue := sw.claimPumpLocked()
		sw.mu.Unlock()
		if queue {
			sw.w.postTask(sw.pumpFn)
		}
	}
	return nil
}

func (sw *epollH2StreamWriter) Flush() error {
	sw.mu.Lock()
	err := sw.err
	queue := sw.claimPumpLocked()
	sw.mu.Unlock()
	if queue {
		sw.w.postTask(sw.pumpFn)
	}
	return err
}

func (sw *epollH2StreamWriter) Close() error {
	sw.mu.Lock()
	sw.ended = true
	err := sw.err
	queue := sw.claimPumpLocked()
	sw.mu.Unlock()
	if queue {
		sw.w.postTask(sw.pumpFn)
	}
	return err
}

func (sw *epollH2StreamWriter) bufferedLocked() int { return len(sw.pending) - sw.pendingOff }

func (sw *epollH2StreamWriter) claimPumpLocked() bool {
	if sw.pumpQueued || sw.finished {
		return false
	}
	sw.pumpQueued = true
	return true
}

func (sw *epollH2StreamWriter) waitSpaceLocked() error {
	if sw.ended {
		return ErrStreamClosed
	}
	if sw.err != nil || sw.bufferedLocked() < h2StreamPendingCap {
		return sw.err
	}
	stalled := false
	timer := turbo.AfterFunc(h2StreamStallTimeout, func() {
		sw.mu.Lock()
		stalled = true
		sw.space.Broadcast()
		sw.mu.Unlock()
	})
	defer timer.Stop()
	for sw.err == nil && sw.bufferedLocked() >= h2StreamPendingCap {
		if stalled {
			sw.err = errH2StreamStalled
			sw.sendRST = true
			break
		}
		sw.space.Wait()
	}
	return sw.err
}

func (sw *epollH2StreamWriter) fail(err error) {
	sw.mu.Lock()
	if sw.err == nil {
		sw.err = err
	}
	sw.finished = true
	sw.space.Broadcast()
	sw.mu.Unlock()
}

func (sw *epollH2StreamWriter) release() {
	sw.c, sw.w, sw.stream = nil, nil, nil
	sw.gen, sw.streamID = 0, 0
	sw.method, sw.serverName, sw.altSvc = "", "", nil
	sw.maxWrite, sw.written = 0, 0
	sw.cors.reset()
	sw.headerCalled, sw.suppressBody = false, false
	sw.header = sw.header[:0]
	if cap(sw.pending) > h2StreamPendingKeep {
		sw.pending = nil
	} else {
		sw.pending = sw.pending[:0]
	}
	sw.pendingOff = 0
	sw.headerReady, sw.headersOut, sw.ended, sw.finished = false, false, false, false
	sw.handlerDone, sw.registered, sw.pumpQueued, sw.sendRST = false, false, false, false
	sw.endedEarly = false
	sw.err = nil
	sw.file.clear()
	epollH2StreamWriterPool.Put(sw)
}

func (c *epollConn) h2PumpTask(w *epollWorker, sw *epollH2StreamWriter) {
	if c.generation != sw.gen || c.fd < 0 {
		sw.mu.Lock()
		sw.pumpQueued = false
		sw.mu.Unlock()
		sw.fail(ErrStreamClosed)
		return
	}
	if !sw.registered {
		sw.registered = true
		if c.h2Streaming == nil {
			c.h2Streaming = make(map[uint32]*epollH2StreamWriter)
		}
		c.h2Streaming[sw.streamID] = sw
	}
	c.h2PumpSealed(w, sw)
	w.markFlush(c)
}

func (c *epollConn) h2PumpSealed(w *epollWorker, sw *epollH2StreamWriter) {
	backlog := c.h2OutputBacklog()
	if c.sealsH2Output() {
		plain := c.h2PumpFrames(w.h2FinishScratch[:0], sw, backlog)
		w.h2FinishScratch = plain[:0]
		if len(plain) > 0 {
			c.writeBuf = c.sealTLSAppData(c.writeBuf, plain)
		}
	} else {
		c.writeBuf = c.h2PumpFrames(c.writeBuf, sw, backlog)
	}
	c.h2SettleStream(sw)
}

func (c *epollConn) h2PumpFrames(dst []byte, sw *epollH2StreamWriter, backlog int) []byte {
	st := &c.h2
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.pumpQueued = false
	if sw.finished {
		return dst
	}
	if sw.err != nil {
		if sw.sendRST {
			dst = appendH2RSTStreamFrame(dst, sw.streamID, H2ErrCancel)
		}
		sw.finished = true
		sw.space.Broadcast()
		return dst
	}
	if !sw.headersOut {
		if !sw.headerReady {
			return dst
		}
		end := sw.ended && sw.bufferedLocked() == 0
		flags := byte(H2FlagEndHeaders)
		if end {
			flags |= H2FlagEndStream
		}
		dst = appendH2HeaderBlockFrame(dst, sw.streamID, flags, &st.encTable, sw.header, st.dataFrameLimit())
		sw.headersOut = true
		if end {
			sw.finished = true
			return dst
		}
	}
	frameLimit := int(st.maxFrameSize)
	if frameLimit <= 0 {
		frameLimit = H2DefaultMaxFrameSize
	}
	start := len(dst)
	for sw.bufferedLocked() > 0 && backlog+len(dst)-start < h2StreamSocketHighMark {
		avail := sw.stream.Window.Load()
		if st.connWindow < avail {
			avail = st.connWindow
		}
		if avail <= 0 {
			break
		}
		n := min(int64(sw.bufferedLocked()), avail, int64(frameLimit))
		end := sw.ended && int(n) == sw.bufferedLocked()
		flags := byte(0)
		if end {
			flags = H2FlagEndStream
		}
		dst = appendH2Frame(dst, H2FrameData, flags, sw.streamID, sw.pending[sw.pendingOff:sw.pendingOff+int(n)])
		sw.pendingOff += int(n)
		st.connWindow -= n
		sw.stream.Window.Add(-n)
		if end {
			sw.finished = true
		}
	}
	if sw.file.left > 0 && sw.bufferedLocked() == 0 {
		dst = c.h2PumpFile(dst, sw, h2StreamSocketHighMark-backlog-(len(dst)-start), frameLimit)
	}
	switch {
	case sw.bufferedLocked() == 0:
		sw.pending, sw.pendingOff = sw.pending[:0], 0
	case sw.pendingOff > len(sw.pending)/2:
		rest := copy(sw.pending, sw.pending[sw.pendingOff:])
		sw.pending, sw.pendingOff = sw.pending[:rest], 0
	}
	if !sw.finished && sw.ended && sw.bufferedLocked() == 0 {
		dst = appendH2Frame(dst, H2FrameData, H2FlagEndStream, sw.streamID, nil)
		sw.finished = true
	}
	sw.space.Broadcast()
	return dst
}

func (c *epollConn) h2SettleStream(sw *epollH2StreamWriter) {
	sw.mu.Lock()
	finished, handlerDone := sw.finished, sw.handlerDone
	sw.mu.Unlock()
	switch {
	case finished && handlerDone:
		c.h2ReleaseStreaming(sw)
	case finished && !sw.endedEarly:
		sw.endedEarly = true
		c.h2EndedInFlight++
	}
}

func (c *epollConn) h2UncountEndedEarly(sw *epollH2StreamWriter) {
	if sw.endedEarly && c.h2EndedInFlight > 0 {
		c.h2EndedInFlight--
	}
	sw.endedEarly = false
}

func (c *epollConn) h2ReleaseStreaming(sw *epollH2StreamWriter) {
	if sw.registered && c.h2Streaming[sw.streamID] == sw {
		delete(c.h2Streaming, sw.streamID)
	}
	if c.h2Draining > 0 {
		c.h2Draining--
	}
	stream := sw.stream
	sw.release()
	stream.Reset()
	StreamPool.Put(stream)
}

func (c *epollConn) h2FinishStreamed(w *epollWorker, stream *H2Stream, sw *epollH2StreamWriter) {
	sw.mu.Lock()
	sw.handlerDone = true
	sw.ended = true
	finished := sw.finished
	sw.mu.Unlock()
	c.h2UncountEndedEarly(sw)
	if finished {
		if sw.registered && c.h2Streaming[sw.streamID] == sw {
			delete(c.h2Streaming, sw.streamID)
		}
		sw.release()
		stream.Reset()
		StreamPool.Put(stream)
		return
	}
	if !sw.registered {
		sw.registered = true
		if c.h2Streaming == nil {
			c.h2Streaming = make(map[uint32]*epollH2StreamWriter)
		}
		c.h2Streaming[sw.streamID] = sw
	}
	c.h2Draining++
	c.h2PumpSealed(w, sw)
	w.markFlush(c)
}

func (c *epollConn) h2DropUnusedWriter(sw *epollH2StreamWriter) {
	if sw.registered && c.h2Streaming[sw.streamID] == sw {
		delete(c.h2Streaming, sw.streamID)
	}
	sw.release()
}

func (c *epollConn) h2PumpAll(w *epollWorker) bool {
	if len(c.h2Streaming) == 0 {
		return (len(c.h2.sending) != 0 || c.h2.peerGoingAway) && c.h2PumpBuffered()
	}
	before, directBefore := len(c.writeBuf), c.h2.directSent
	for _, sw := range c.h2Streaming {
		c.h2PumpSealed(w, sw)
	}
	if len(c.h2.sending) != 0 {
		c.h2ResumeSending(0)
	}
	return len(c.writeBuf) > before || c.h2.directSent != directBefore
}

func (c *epollConn) h2WindowOpened(w *epollWorker) {
	if len(c.h2Streaming) == 0 {
		return
	}
	c.h2PumpDue = true
	w.markFlush(c)
}

func (c *epollConn) h2CancelStreaming(streamID uint32) bool {
	sw := c.h2Streaming[streamID]
	if sw == nil {
		return false
	}
	sw.fail(ErrStreamClosed)
	if sw.handlerDone {
		c.h2ReleaseStreaming(sw)
	} else {
		delete(c.h2Streaming, streamID)
		sw.registered = false
		if !sw.endedEarly {
			sw.endedEarly = true
			c.h2EndedInFlight++
		}
	}
	return true
}

func (c *epollConn) h2AbortAllStreaming() {
	for id, sw := range c.h2Streaming {
		sw.fail(ErrStreamClosed)
		if sw.handlerDone {
			c.h2ReleaseStreaming(sw)
			continue
		}
		delete(c.h2Streaming, id)
		sw.registered = false
	}
	c.h2Draining = 0
	c.h2EndedInFlight = 0
	c.h2PumpDue = false
}
