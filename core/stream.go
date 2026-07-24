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

// H2StreamWriter writes an HTTP/2 response as HEADERS and DATA frames on a
// single stream, honoring per-stream and per-connection flow control and any
// configured bandwidth limiter. It implements StreamWriter.
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
	serverName   string
	written      int64
	maxWrite     int64
	headersSent  bool
	suppressBody bool
	flowCond     *sync.Cond
}

// WriteRequest is a single write submitted to a connection's serialized
// writer goroutine; the outcome is delivered on Done.
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

// WriteHeader encodes and sends the HTTP/2 HEADERS frame for the stream with
// statusCode, headers, and contentType. Later calls are no-ops.
func (w *H2StreamWriter) WriteHeader(statusCode int, headers [][2]string, contentType string) error {
	if w.headersSent {
		return nil
	}
	w.headersSent = true
	w.suppressBody, _ = responseBodyDisposition(w.method, statusCode)

	bp := MediumBufPool.Get().(*[]byte)
	enc := HpackEncoder{}
	enc.Reset((*bp)[:0])
	encodeH2ResponseHeaders(&enc, statusCode, contentType, -1, headers, w.serverName)

	fbp := H2FrameBufPool.Get().(*[]byte)
	headerFrame := H2WriteFrame((*fbp)[:0], H2FrameHeaders, H2FlagEndHeaders, w.streamID, enc.Buf)
	*bp = enc.Buf[:0]
	MediumBufPool.Put(bp)

	err := w.sendFrame(headerFrame)
	*fbp = headerFrame[:0]
	H2FrameBufPool.Put(fbp)
	return err
}

// WriteChunk sends data as one or more HTTP/2 DATA frames, splitting oversized
// payloads to the negotiated max frame size and waiting for available
// flow-control window (up to 30s) before each frame. It applies any
// configured download rate limit and returns ErrBodyTooLarge if a maximum
// response size was set and is exceeded.
func (w *H2StreamWriter) WriteChunk(data []byte) error {
	if !w.headersSent {
		return ErrStreamClosed
	}
	if w.suppressBody {
		return nil
	}
	if w.maxWrite > 0 {
		w.written += int64(len(data))
		if w.written > w.maxWrite {
			return ErrBodyTooLarge
		}
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

// Flush is a no-op; H2StreamWriter has no internal buffering to flush.
func (w *H2StreamWriter) Flush() error {
	return nil
}

// Close sends an empty DATA frame with END_STREAM set, ending the HTTP/2
// stream.
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

// H1StreamWriter writes an HTTP/1.1 response over an encrypted (TLS)
// connection, using chunked Transfer-Encoding unless the response declares
// Content-Length or has no body. It implements StreamWriter.
type H1StreamWriter struct {
	conn         net.Conn
	writer       *TrafficAEAD
	limiter      *ConnectionLimiter
	global       *GlobalLimiter
	method       string
	serverName   string
	written      int64
	maxWrite     int64
	headersSent  bool
	chunked      bool
	suppressBody bool
	closeAfter   bool
}

// WriteHeader writes the HTTP/1.1 status line and headers, selecting chunked
// Transfer-Encoding unless a Content-Length header is present or the response
// has no body. Later calls are no-ops.
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
	hasServer := false
	for i := range headers {
		if EqualFoldASCII(headers[i][0], "connection") {
			hasConnection = true
		}
		if EqualFoldASCII(headers[i][0], "server") {
			hasServer = true
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
	if !hasServer {
		buf = append(buf, "Server: "...)
		buf = append(buf, w.serverName...)
		buf = append(buf, '\r', '\n')
	}
	buf = append(buf, '\r', '\n')

	err := w.writeEncrypted(buf)
	*bp = buf[:0]
	LargeBufPool.Put(bp)
	return err
}

// WriteChunk writes data to the client, chunk-encoding it when the response
// uses chunked Transfer-Encoding or writing it directly when Content-Length
// was set. It applies any configured download rate limit and returns
// ErrBodyTooLarge if a maximum response size was set and is exceeded.
func (w *H1StreamWriter) WriteChunk(data []byte) error {
	if !w.headersSent {
		return ErrStreamClosed
	}
	if w.suppressBody {
		return nil
	}
	if w.maxWrite > 0 {
		w.written += int64(len(data))
		if w.written > w.maxWrite {
			return ErrBodyTooLarge
		}
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

// Flush is a no-op; H1StreamWriter has no internal buffering to flush.
func (w *H1StreamWriter) Flush() error {
	return nil
}

// Close writes the terminating zero-length chunk when the response is
// chunked; it is a no-op for Content-Length responses or bodiless responses.
func (w *H1StreamWriter) Close() error {
	if w.suppressBody || !w.chunked {
		return nil
	}
	return w.writeEncrypted([]byte("0\r\n\r\n"))
}

func (w *H1StreamWriter) writeEncrypted(data []byte) error {
	return WriteAppData(w.conn, w.writer, data)
}

// PlainH1StreamWriter writes an HTTP/1.1 response over a plaintext
// (non-TLS) connection, using the same Content-Length/chunked selection as
// H1StreamWriter. It implements StreamWriter.
type PlainH1StreamWriter struct {
	conn         net.Conn
	limiter      *ConnectionLimiter
	global       *GlobalLimiter
	method       string
	serverName   string
	written      int64
	maxWrite     int64
	headersSent  bool
	chunked      bool
	suppressBody bool
	closeAfter   bool
}

// WriteHeader writes the HTTP/1.1 status line and headers, selecting chunked
// Transfer-Encoding unless a Content-Length header is present or the response
// has no body. Later calls are no-ops.
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
	hasServer := false
	for i := range headers {
		if EqualFoldASCII(headers[i][0], "connection") {
			hasConnection = true
		}
		if EqualFoldASCII(headers[i][0], "server") {
			hasServer = true
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
	if !hasServer {
		buf = append(buf, "Server: "...)
		buf = append(buf, w.serverName...)
		buf = append(buf, '\r', '\n')
	}
	buf = append(buf, '\r', '\n')

	err := writeFull(w.conn, buf)
	*bp = buf[:0]
	LargeBufPool.Put(bp)
	return err
}

// WriteChunk writes data to the client, chunk-encoding it when the response
// uses chunked Transfer-Encoding or writing it directly when Content-Length
// was set. It applies any configured download rate limit and returns
// ErrBodyTooLarge if a maximum response size was set and is exceeded.
func (w *PlainH1StreamWriter) WriteChunk(data []byte) error {
	if !w.headersSent {
		return ErrStreamClosed
	}
	if w.suppressBody {
		return nil
	}
	if w.maxWrite > 0 {
		w.written += int64(len(data))
		if w.written > w.maxWrite {
			return ErrBodyTooLarge
		}
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

// Flush is a no-op; PlainH1StreamWriter has no internal buffering to flush.
func (w *PlainH1StreamWriter) Flush() error {
	return nil
}

// Close writes the terminating zero-length chunk when the response is
// chunked; it is a no-op for Content-Length responses or bodiless responses.
func (w *PlainH1StreamWriter) Close() error {
	if w.suppressBody || !w.chunked {
		return nil
	}
	return writeFull(w.conn, []byte("0\r\n\r\n"))
}
