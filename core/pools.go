package core

import (
	"bufio"
	"sync"
)

var RecordBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, MaxRecordSize+5); return &b },
}

var SmallBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 512); return &b },
}

var MediumBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 4096); return &b },
}

var LargeBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 32768); return &b },
}

var HdrBufPool = sync.Pool{
	New: func() any { b := make([]byte, 5, 5); return &b },
}

var H2FrameBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, H2DefaultMaxFrameSize+9); return &b },
}

var RequestPool = sync.Pool{
	New: func() any {
		return &Request{
			Headers: make([][2]string, 0, 16),
			Body:    make([]byte, 0, 1024),
		}
	},
}

var ResponsePool = sync.Pool{
	New: func() any {
		return &Response{
			Headers: make([][2]string, 0, 8),
			body:    make([]byte, 0, 4096),
		}
	},
}

var WriteBufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, MaxRecordSize); return &b },
}

var StreamPool = sync.Pool{
	New: func() any {
		return &H2Stream{
			Headers: make([][2]string, 0, 16),
			Body:    make([]byte, 0, 4096),
		}
	},
}

var FileReadBufPool = sync.Pool{
	New: func() any { b := make([]byte, 65536); return &b },
}

var H1StreamWriterPool = sync.Pool{
	New: func() any { return &H1StreamWriter{} },
}

var PlainH1StreamWriterPool = sync.Pool{
	New: func() any { return &PlainH1StreamWriter{} },
}

var H2StreamWriterPool = sync.Pool{
	New: func() any { return &H2StreamWriter{} },
}

var ErrChanPool = sync.Pool{
	New: func() any { return make(chan error, 1) },
}

var H2FramePool = sync.Pool{
	New: func() any {
		return &H2Frame{
			Payload: make([]byte, 0, 1024),
		}
	},
}

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
	epollReadBufCap        = 2048
	epollReadBufPoolMaxCap = 16 << 10
)

var epollReadBufPool = sync.Pool{
	New: func() any { b := make([]byte, epollReadBufCap); return &b },
}

var tlsScratchPool = sync.Pool{
	New: func() any { b := make([]byte, 0, MaxRecordPayload); return &b },
}

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
