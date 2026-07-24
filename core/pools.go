package core

import (
	"bufio"
	"sync"
)

// RecordBufPool pools byte slices sized to hold a maximum-size TLS record plus its 5-byte header.
var RecordBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, MaxRecordSize+5); return &b },
}

// SmallBufPool pools 512-byte scratch buffers.
var SmallBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 512); return &b },
}

// MediumBufPool pools 4096-byte scratch buffers.
var MediumBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 4096); return &b },
}

// LargeBufPool pools 32768-byte scratch buffers.
var LargeBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 32768); return &b },
}

// HdrBufPool pools 5-byte buffers sized for a TLS record header.
var HdrBufPool = sync.Pool{
	New: func() any { b := make([]byte, 5, 5); return &b },
}

// H2FrameBufPool pools byte slices sized for a maximum-size HTTP/2 frame plus its 9-byte header.
var H2FrameBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, H2DefaultMaxFrameSize+9); return &b },
}

// RequestPool pools reusable Request objects.
var RequestPool = sync.Pool{
	New: func() any {
		return &Request{
			Headers: make([][2]string, 0, 16),
			Body:    make([]byte, 0, 1024),
		}
	},
}

// ResponsePool pools reusable Response objects.
var ResponsePool = sync.Pool{
	New: func() any {
		return &Response{
			Headers: make([][2]string, 0, 8),
			body:    make([]byte, 0, 4096),
		}
	},
}

// WriteBufPool pools byte slices sized for a maximum-size TLS record, used for outgoing writes.
var WriteBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, MaxRecordSize); return &b },
}

// StreamPool pools reusable H2Stream objects.
var StreamPool = sync.Pool{
	New: func() any {
		return &H2Stream{
			Headers: make([][2]string, 0, 16),
			Body:    make([]byte, 0, 4096),
		}
	},
}

// FileReadBufPool pools 65536-byte buffers used for file read operations.
var FileReadBufPool = sync.Pool{
	New: func() any { b := make([]byte, 65536); return &b },
}

// H1StreamWriterPool pools reusable H1StreamWriter objects.
var H1StreamWriterPool = sync.Pool{
	New: func() any { return &H1StreamWriter{} },
}

// PlainH1StreamWriterPool pools reusable PlainH1StreamWriter objects.
var PlainH1StreamWriterPool = sync.Pool{
	New: func() any { return &PlainH1StreamWriter{} },
}

// H2StreamWriterPool pools reusable H2StreamWriter objects.
var H2StreamWriterPool = sync.Pool{
	New: func() any { return &H2StreamWriter{} },
}

// ErrChanPool pools buffered error channels with a capacity of 1.
var ErrChanPool = sync.Pool{
	New: func() any { return make(chan error, 1) },
}

// H2FramePool pools reusable H2Frame objects.
var H2FramePool = sync.Pool{
	New: func() any {
		return &H2Frame{
			Payload: make([]byte, 0, 1024),
		}
	},
}

// BufReaderPool pools bufio.Reader instances sized with a 65536-byte buffer.
var BufReaderPool = sync.Pool{
	New: func() any { return bufio.NewReaderSize(nil, 65536) },
}

const (
	connReadBufDefaultCap  = 8192
	connWriteBufDefaultCap = 16384
	connBodyBufDefaultCap  = 4096
	connBufPoolMaxCap      = 256 << 10
)

var connReadBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, connReadBufDefaultCap); return &b },
}

var connWriteBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, connWriteBufDefaultCap); return &b },
}

var connBodyBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, connBodyBufDefaultCap); return &b },
}

var bufBoxPool = sync.Pool{
	New: func() any { return new([]byte) },
}

func acquirePooledBuf(pool *sync.Pool) []byte {
	bp := pool.Get().(*[]byte)
	buf := (*bp)[:0]
	*bp = nil
	bufBoxPool.Put(bp)
	return buf
}

func releasePooledBuf(pool *sync.Pool, buf []byte, maxCap int) {
	if cap(buf) == 0 || cap(buf) > maxCap {
		return
	}
	bp := bufBoxPool.Get().(*[]byte)
	*bp = buf[:0]
	pool.Put(bp)
}

const (
	epollReadBufCap        = 8192
	epollReadBufPoolMaxCap = 2 * epollReadBufCap
)

var epollReadBufPool = sync.Pool{
	New: func() any { b := make([]byte, epollReadBufCap); return &b },
}

var tlsScratchPool = sync.Pool{
	New: func() any { b := make([]byte, 0, MaxRecordPayload); return &b },
}

// HpackDecoderPool pools reusable HPACK decoders.
var HpackDecoderPool = sync.Pool{
	New: func() any { return NewHpackDecoder() },
}

var clientHelloPool = sync.Pool{
	New: func() any { return &ParsedClientHello{} },
}

const (
	epollIOBufCap        = 2048
	epollIOBufPoolMaxCap = 32 << 10
)

var epollIOBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, epollIOBufCap); return &b },
}

func acquireIOBuf() []byte {
	return acquirePooledBuf(&epollIOBufPool)
}

func releaseIOBuf(b []byte) {
	releasePooledBuf(&epollIOBufPool, b, epollIOBufPoolMaxCap)
}

func acquireEpollReadBuf() []byte {
	bp := epollReadBufPool.Get().(*[]byte)
	b := *bp
	*bp = nil
	bufBoxPool.Put(bp)
	if cap(b) < epollReadBufCap {
		b = make([]byte, epollReadBufCap)
	}
	return b[:cap(b)]
}

func releaseEpollReadBuf(b []byte) {
	if cap(b) == 0 || cap(b) > epollReadBufPoolMaxCap {
		return
	}
	bp := bufBoxPool.Get().(*[]byte)
	*bp = b
	epollReadBufPool.Put(bp)
}
