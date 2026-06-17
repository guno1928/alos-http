package core

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func classifyH1StreamHeaders(headers [][2]string) (bool, bool) {
	chunked := true
	hasConnection := false
	for i := range headers {
		if EqualFoldASCII(headers[i][0], "connection") {
			hasConnection = true
			continue
		}
		if EqualFoldASCII(headers[i][0], "transfer-encoding") {
			chunked = EqualFoldASCII(headers[i][1], "chunked")
			continue
		}
		if EqualFoldASCII(headers[i][0], "content-length") {
			chunked = false
		}
	}
	return chunked, hasConnection
}

func releaseStreamWriter(sw StreamWriter) {
	switch writer := sw.(type) {
	case *H2StreamWriter:
		H2StreamWriterPool.Put(writer)
	case *H1StreamWriter:
		H1StreamWriterPool.Put(writer)
	case *PlainH1StreamWriter:
		PlainH1StreamWriterPool.Put(writer)
	}
}

type H2StreamWriter struct {
	streamID     uint32
	writeCh      chan<- WriteRequest
	done         <-chan struct{}
	window       *atomic.Int64
	connWindow   *atomic.Int64
	maxFrame     *atomic.Uint32
	limiter      *ConnectionLimiter
	global       *GlobalLimiter
	method       string
	headersSent  bool
	suppressBody bool
	flowCond     *sync.Cond
}

type WriteRequest struct {
	Data        []byte
	Done        chan error
	releaseBuf  *[]byte
	releasePool uint8
}

func bindRequestMethodToStreamWriter(sw StreamWriter, method string) {
	switch writer := sw.(type) {
	case *H2StreamWriter:
		writer.method = method
		writer.suppressBody = false
	case *H1StreamWriter:
		writer.method = method
		writer.suppressBody = false
	case *PlainH1StreamWriter:
		writer.method = method
		writer.suppressBody = false
	}
}

func (w *H2StreamWriter) WriteHeader(statusCode int, headers [][2]string, contentType string) error {
	if w.headersSent {
		return nil
	}
	w.headersSent = true
	w.suppressBody, _ = responseBodyDisposition(w.method, statusCode)

	bp := MediumBufPool.Get().(*[]byte)
	enc := HpackEncoder{}
	enc.Reset((*bp)[:0])
	encodeH2ResponseHeaders(&enc, statusCode, contentType, -1, headers)

	fbp := H2FrameBufPool.Get().(*[]byte)
	headerFrame := H2WriteFrame((*fbp)[:0], H2FrameHeaders, H2FlagEndHeaders, w.streamID, enc.Buf)
	*bp = enc.Buf[:0]
	MediumBufPool.Put(bp)

	err := w.sendFrame(headerFrame)
	*fbp = headerFrame[:0]
	H2FrameBufPool.Put(fbp)
	return err
}

func (w *H2StreamWriter) WriteChunk(data []byte) error {
	if !w.headersSent {
		return ErrStreamClosed
	}
	if w.suppressBody {
		return nil
	}

	maxFrame := int(w.maxFrame.Load())
	remaining := data

	for len(remaining) > 0 {
		chunk := remaining
		if len(chunk) > maxFrame {
			chunk = chunk[:maxFrame]
		}

		waitStart := time.Now()
		w.flowCond.L.Lock()
		for {
			windowAvail := w.window.Load()
			connAvail := w.connWindow.Load()
			avail := windowAvail
			if connAvail < avail {
				avail = connAvail
			}
			if avail > 0 {
				if int64(len(chunk)) > avail {
					chunk = chunk[:int(avail)]
				}
				break
			}
			select {
			case <-w.done:
				w.flowCond.L.Unlock()
				return ErrStreamClosed
			default:
			}
			if time.Since(waitStart) > 30*time.Second {
				w.flowCond.L.Unlock()
				return ErrStreamClosed
			}
			w.flowCond.Wait()
		}
		w.flowCond.L.Unlock()

		if w.limiter != nil {
			w.limiter.ThrottleDownload(int64(len(chunk)))
		}
		if w.global != nil && w.global.Download != nil {
			w.global.Download.Wait(int64(len(chunk)))
		}

		w.window.Add(-int64(len(chunk)))
		w.connWindow.Add(-int64(len(chunk)))

		fbp := H2FrameBufPool.Get().(*[]byte)
		dataFrame := H2WriteFrame((*fbp)[:0], H2FrameData, 0, w.streamID, chunk)
		err := w.sendFrame(dataFrame)
		*fbp = dataFrame[:0]
		H2FrameBufPool.Put(fbp)
		if err != nil {
			return err
		}

		remaining = remaining[len(chunk):]
	}
	return nil
}

func (w *H2StreamWriter) Flush() error {
	return nil
}

func (w *H2StreamWriter) Close() error {
	fbp := H2FrameBufPool.Get().(*[]byte)
	emptyFrame := H2WriteFrame((*fbp)[:0], H2FrameData, H2FlagEndStream, w.streamID, nil)
	err := w.sendFrame(emptyFrame)
	*fbp = emptyFrame[:0]
	H2FrameBufPool.Put(fbp)
	return err
}

func (w *H2StreamWriter) sendFrame(frame []byte) error {
	done := ErrChanPool.Get().(chan error)
	select {
	case w.writeCh <- WriteRequest{Data: frame, Done: done}:
		err := <-done
		ErrChanPool.Put(done)
		return err
	case <-w.done:
		ErrChanPool.Put(done)
		return ErrStreamClosed
	}
}

type H1StreamWriter struct {
	conn         net.Conn
	writer       *TrafficAEAD
	limiter      *ConnectionLimiter
	global       *GlobalLimiter
	method       string
	headersSent  bool
	chunked      bool
	suppressBody bool
	closeAfter   bool
}

func (w *H1StreamWriter) WriteHeader(statusCode int, headers [][2]string, contentType string) error {
	if w.headersSent {
		return nil
	}
	w.headersSent = true
	w.suppressBody, _ = responseBodyDisposition(w.method, statusCode)
	w.chunked, _ = classifyH1StreamHeaders(headers)
	if w.suppressBody {
		w.chunked = false
	}

	bp := LargeBufPool.Get().(*[]byte)
	buf := (*bp)[:0]

	buf = appendStatusLine(buf, statusCode)

	if contentType != "" {
		buf = append(buf, "Content-Type: "...)
		buf = append(buf, contentType...)
		buf = append(buf, '\r', '\n')
	}
	if w.chunked {
		buf = append(buf, "Transfer-Encoding: chunked\r\n"...)
	}
	hasConnection := false
	for i := range headers {
		if EqualFoldASCII(headers[i][0], "connection") {
			hasConnection = true
		}
		buf = append(buf, headers[i][0]...)
		buf = append(buf, ':', ' ')
		buf = append(buf, headers[i][1]...)
		buf = append(buf, '\r', '\n')
	}
	if !hasConnection {
		if w.closeAfter {
			buf = append(buf, "Connection: close\r\n"...)
		} else {
			buf = append(buf, "Connection: keep-alive\r\n"...)
		}
	}
	buf = append(buf, '\r', '\n')

	err := w.writeEncrypted(buf)
	*bp = buf[:0]
	LargeBufPool.Put(bp)
	return err
}

func (w *H1StreamWriter) WriteChunk(data []byte) error {
	if !w.headersSent {
		return ErrStreamClosed
	}
	if w.suppressBody {
		return nil
	}

	if w.limiter != nil {
		w.limiter.ThrottleDownload(int64(len(data)))
	}
	if w.global != nil && w.global.Download != nil {
		w.global.Download.Wait(int64(len(data)))
	}

	if !w.chunked {
		return w.writeEncrypted(data)
	}

	bp := MediumBufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	var sizeBuf [16]byte
	size := appendHex(sizeBuf[:0], int64(len(data)))
	buf = append(buf, size...)
	buf = append(buf, '\r', '\n')
	buf = append(buf, data...)
	buf = append(buf, '\r', '\n')

	err := w.writeEncrypted(buf)
	*bp = buf[:0]
	MediumBufPool.Put(bp)
	return err
}

func (w *H1StreamWriter) Flush() error {
	return nil
}

func (w *H1StreamWriter) Close() error {
	if w.suppressBody || !w.chunked {
		return nil
	}
	return w.writeEncrypted([]byte("0\r\n\r\n"))
}

func (w *H1StreamWriter) writeEncrypted(data []byte) error {
	return WriteAppData(w.conn, w.writer, data)
}

type PlainH1StreamWriter struct {
	conn         net.Conn
	limiter      *ConnectionLimiter
	global       *GlobalLimiter
	method       string
	headersSent  bool
	chunked      bool
	suppressBody bool
	closeAfter   bool
}

func (w *PlainH1StreamWriter) WriteHeader(statusCode int, headers [][2]string, contentType string) error {
	if w.headersSent {
		return nil
	}
	w.headersSent = true
	w.suppressBody, _ = responseBodyDisposition(w.method, statusCode)
	w.chunked, _ = classifyH1StreamHeaders(headers)
	if w.suppressBody {
		w.chunked = false
	}

	bp := LargeBufPool.Get().(*[]byte)
	buf := (*bp)[:0]

	buf = appendStatusLine(buf, statusCode)

	if contentType != "" {
		buf = append(buf, "Content-Type: "...)
		buf = append(buf, contentType...)
		buf = append(buf, '\r', '\n')
	}
	if w.chunked {
		buf = append(buf, "Transfer-Encoding: chunked\r\n"...)
	}
	hasConnection := false
	for i := range headers {
		if EqualFoldASCII(headers[i][0], "connection") {
			hasConnection = true
		}
		buf = append(buf, headers[i][0]...)
		buf = append(buf, ':', ' ')
		buf = append(buf, headers[i][1]...)
		buf = append(buf, '\r', '\n')
	}
	if !hasConnection {
		if w.closeAfter {
			buf = append(buf, "Connection: close\r\n"...)
		} else {
			buf = append(buf, "Connection: keep-alive\r\n"...)
		}
	}
	buf = append(buf, '\r', '\n')

	err := writeFull(w.conn, buf)
	*bp = buf[:0]
	LargeBufPool.Put(bp)
	return err
}

func (w *PlainH1StreamWriter) WriteChunk(data []byte) error {
	if !w.headersSent {
		return ErrStreamClosed
	}
	if w.suppressBody {
		return nil
	}

	if w.limiter != nil {
		w.limiter.ThrottleDownload(int64(len(data)))
	}
	if w.global != nil && w.global.Download != nil {
		w.global.Download.Wait(int64(len(data)))
	}

	if !w.chunked {
		return writeFull(w.conn, data)
	}

	bp := MediumBufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	var sizeBuf [16]byte
	size := appendHex(sizeBuf[:0], int64(len(data)))
	buf = append(buf, size...)
	buf = append(buf, '\r', '\n')
	buf = append(buf, data...)
	buf = append(buf, '\r', '\n')

	err := writeFull(w.conn, buf)
	*bp = buf[:0]
	MediumBufPool.Put(bp)
	return err
}

func (w *PlainH1StreamWriter) Flush() error {
	return nil
}

func (w *PlainH1StreamWriter) Close() error {
	if w.suppressBody || !w.chunked {
		return nil
	}
	return writeFull(w.conn, []byte("0\r\n\r\n"))
}
