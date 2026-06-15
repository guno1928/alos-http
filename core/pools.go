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
