package core

import (
	"io"
	"net"
	"sync"
	"time"
)

// Param stores one route parameter extracted during routing.
//
//	r.GET("/users/:id", func(req *core.Request, resp *core.Response) {
//	    id := req.Params[0].Value
//	    resp.String(id)
//	})
//
//	r.GET("/teams/:team/users/:user", func(req *core.Request, resp *core.Response) {
//	    team := req.Params[0].Value
//	    user := req.Params[1].Value
//	    resp.String(team + ":" + user)
//	})
type Param struct {
	Key   string
	Value string
}

// Request is the handler-facing view of an incoming request.
//
//	srv.Router.GET("/users/:id", func(req *core.Request, resp *core.Response) {
//	    resp.String(req.Method + " " + req.Path + " for " + req.ParamValue("id"))
//	})
//
//	srv.Router.POST("/echo", func(req *core.Request, resp *core.Response) {
//	    ct := req.Header("Content-Type")
//	    resp.SetHeader("X-Seen-Content-Type", ct)
//	    resp.Bytes(req.Body)
//	})
//
//	srv.Router.GET("/conn", func(req *core.Request, resp *core.Response) {
//	    resp.String(req.RemoteAddr)
//	})
type Request struct {
	Method          string
	Path            string
	Proto           string
	Host            string
	RemoteAddr      string
	Headers         [][2]string
	Body            []byte
	StreamID        uint32
	IsH2            bool
	Params          [8]Param
	ParamCount      int
	StreamWriter    StreamWriter
	conn            net.Conn
	tlsReader       *TrafficAEAD
	tlsWriter       *TrafficAEAD
	hdrBuf          []byte
	hijacked        bool
	cachedCL        string
	cachedConn      string
	cachedTE        string
	cachedHost      string
	cachedAE        string
	cachedOrigin    string
	cachedXFF       string
	cachedXRI       string
	cachedAuth      string
	cachedUpgrade   string
	cachedWSKey     string
	cachedWSVer     string
	headerCacheMask uint32
	server          *Server
	attachConn      func(*Request) net.Conn
	connTakenOver   bool
	hijackReadBuf   []byte
}

const (
	headerCacheContentLength uint32 = 1 << iota
	headerCacheConnection
	headerCacheTransferEncoding
	headerCacheHost
	headerCacheAcceptEncoding
	headerCacheOrigin
	headerCacheXForwardedFor
	headerCacheXRealIP
	headerCacheAuthorization
	headerCacheUpgrade
	headerCacheWSKey
	headerCacheWSVersion
)

func (r *Request) Reset() {
	r.Method = ""
	r.Path = ""
	r.Proto = ""
	r.Host = ""
	r.RemoteAddr = ""
	r.Headers = r.Headers[:0]
	r.Body = r.Body[:0]
	r.StreamID = 0
	r.IsH2 = false
	r.ParamCount = 0
	r.StreamWriter = nil
	r.conn = nil
	r.tlsReader = nil
	r.tlsWriter = nil
	r.hdrBuf = nil
	r.hijacked = false
	r.cachedCL = ""
	r.cachedConn = ""
	r.cachedTE = ""
	r.cachedHost = ""
	r.cachedAE = ""
	r.cachedOrigin = ""
	r.cachedXFF = ""
	r.cachedXRI = ""
	r.cachedAuth = ""
	r.cachedUpgrade = ""
	r.cachedWSKey = ""
	r.cachedWSVer = ""
	r.headerCacheMask = 0
	r.server = nil
	r.attachConn = nil
	r.connTakenOver = false
	r.hijackReadBuf = nil
}

func (r *Request) resetFastH1() {
	r.Headers = r.Headers[:0]
	r.Body = r.Body[:0]
	r.ParamCount = 0
	r.hijacked = false
	if mask := r.headerCacheMask; mask != 0 {
		if mask&headerCacheContentLength != 0 {
			r.cachedCL = ""
		}
		if mask&headerCacheConnection != 0 {
			r.cachedConn = ""
		}
		if mask&headerCacheTransferEncoding != 0 {
			r.cachedTE = ""
		}
		if mask&headerCacheHost != 0 {
			r.cachedHost = ""
		}
		if mask&headerCacheAcceptEncoding != 0 {
			r.cachedAE = ""
		}
		if mask&headerCacheOrigin != 0 {
			r.cachedOrigin = ""
		}
		if mask&headerCacheXForwardedFor != 0 {
			r.cachedXFF = ""
		}
		if mask&headerCacheXRealIP != 0 {
			r.cachedXRI = ""
		}
		if mask&headerCacheAuthorization != 0 {
			r.cachedAuth = ""
		}
		if mask&headerCacheUpgrade != 0 {
			r.cachedUpgrade = ""
		}
		if mask&headerCacheWSKey != 0 {
			r.cachedWSKey = ""
		}
		if mask&headerCacheWSVersion != 0 {
			r.cachedWSVer = ""
		}
		r.headerCacheMask = 0
	}
	r.attachConn = nil
	r.connTakenOver = false
	r.hijackReadBuf = nil
}

func (r *Request) ensureConn() net.Conn {
	if r.conn != nil {
		return r.conn
	}
	if r.attachConn == nil {
		return nil
	}
	return r.attachConn(r)
}

func (r *Request) cacheHeaderLookup(bit uint32, slot *string, name string) string {
	if r.headerCacheMask&bit != 0 {
		return *slot
	}
	for i := range r.Headers {
		if EqualFoldASCII(r.Headers[i][0], name) {
			*slot = r.Headers[i][1]
			r.headerCacheMask |= bit
			return *slot
		}
	}
	r.headerCacheMask |= bit
	return ""
}

// HijackConn hands the connection to the handler for protocols that need raw I/O.
//
//	srv.Router.GET("/raw", func(req *core.Request, resp *core.Response) {
//	    conn := req.HijackConn()
//	    if conn == nil {
//	        resp.Status(500).String("hijack failed")
//	        return
//	    }
//	    defer conn.Close()
//	    _, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nraw"))
//	})
func (r *Request) HijackConn() net.Conn {
	r.hijacked = true
	if r.conn == nil {
		r.ensureConn()
	}
	if r.conn == nil {
		return nil
	}
	if r.tlsReader != nil && r.tlsWriter != nil {
		if len(r.hdrBuf) < 5 {
			return nil
		}
		return &aead13Conn{
			conn:    r.conn,
			reader:  r.tlsReader,
			writer:  r.tlsWriter,
			hdrBuf:  r.hdrBuf,
			readBuf: append([]byte(nil), r.hijackReadBuf...),
		}
	}
	return r.conn
}

type aead13Conn struct {
	conn   net.Conn
	reader *TrafficAEAD
	writer *TrafficAEAD
	hdrBuf []byte

	mu      sync.Mutex
	readBuf []byte
}

func (c *aead13Conn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	const maxSkips = 16
	for skip := 0; skip < maxSkips; skip++ {
		hdr := c.hdrBuf[:5]
		if _, err := io.ReadFull(c.conn, hdr); err != nil {
			return 0, err
		}
		ct := hdr[0]
		length := int(hdr[3])<<8 | int(hdr[4])
		if length > MaxRecordSize {
			return 0, ErrRecordTooLarge
		}
		bp := RecordBufPool.Get().(*[]byte)
		if cap(*bp) < length {
			*bp = make([]byte, length)
		}
		payload := (*bp)[:length]
		if _, err := io.ReadFull(c.conn, payload); err != nil {
			*bp = (*bp)[:0]
			RecordBufPool.Put(bp)
			return 0, err
		}
		if ct == 0x14 {
			*bp = (*bp)[:0]
			RecordBufPool.Put(bp)
			continue
		}
		pt, err := c.reader.Decrypt(payload)
		if err != nil {
			*bp = (*bp)[:0]
			RecordBufPool.Put(bp)
			return 0, err
		}
		content, contentType, err := StripInnerPlaintext(pt)
		if err != nil {
			*bp = (*bp)[:0]
			RecordBufPool.Put(bp)
			return 0, err
		}
		if contentType == 0x15 {
			*bp = (*bp)[:0]
			RecordBufPool.Put(bp)
			return 0, io.EOF
		}
		if contentType != 0x17 {
			*bp = (*bp)[:0]
			RecordBufPool.Put(bp)
			continue
		}
		n := copy(p, content)
		if n < len(content) {
			c.readBuf = append(c.readBuf[:0], content[n:]...)
		}
		*bp = (*bp)[:0]
		RecordBufPool.Put(bp)
		return n, nil
	}
	return 0, ErrTruncated
}

func (c *aead13Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := WriteAppData(c.conn, c.writer, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *aead13Conn) Close() error                       { return c.conn.Close() }
func (c *aead13Conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *aead13Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *aead13Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *aead13Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *aead13Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// Header returns the first matching request header using ASCII case folding.
//
//	auth := req.Header("Authorization")
//	contentType := req.Header("content-type")
//	origin := req.Header("Origin")
func (r *Request) Header(name string) string {
	switch len(name) {
	case 4:
		if EqualFoldASCII(name, "Host") {
			return r.cacheHeaderLookup(headerCacheHost, &r.cachedHost, "Host")
		}
	case 6:
		if EqualFoldASCII(name, "Origin") {
			return r.cacheHeaderLookup(headerCacheOrigin, &r.cachedOrigin, "Origin")
		}
	case 7:
		if EqualFoldASCII(name, "Upgrade") {
			return r.cacheHeaderLookup(headerCacheUpgrade, &r.cachedUpgrade, "Upgrade")
		}
	case 9:
		if EqualFoldASCII(name, "X-Real-IP") {
			return r.cacheHeaderLookup(headerCacheXRealIP, &r.cachedXRI, "X-Real-IP")
		}
	case 10:
		if EqualFoldASCII(name, "Connection") {
			return r.cacheHeaderLookup(headerCacheConnection, &r.cachedConn, "Connection")
		}
	case 13:
		if EqualFoldASCII(name, "Authorization") {
			return r.cacheHeaderLookup(headerCacheAuthorization, &r.cachedAuth, "Authorization")
		}
	case 14:
		if EqualFoldASCII(name, "Content-Length") {
			return r.cacheHeaderLookup(headerCacheContentLength, &r.cachedCL, "Content-Length")
		}
	case 15:
		if EqualFoldASCII(name, "Accept-Encoding") {
			return r.cacheHeaderLookup(headerCacheAcceptEncoding, &r.cachedAE, "Accept-Encoding")
		}
		if EqualFoldASCII(name, "X-Forwarded-For") {
			return r.cacheHeaderLookup(headerCacheXForwardedFor, &r.cachedXFF, "X-Forwarded-For")
		}
	case 17:
		if EqualFoldASCII(name, "Transfer-Encoding") {
			return r.cacheHeaderLookup(headerCacheTransferEncoding, &r.cachedTE, "Transfer-Encoding")
		}
		if EqualFoldASCII(name, "Sec-WebSocket-Key") {
			return r.cacheHeaderLookup(headerCacheWSKey, &r.cachedWSKey, "Sec-WebSocket-Key")
		}
	case 21:
		if EqualFoldASCII(name, "Sec-WebSocket-Version") {
			return r.cacheHeaderLookup(headerCacheWSVersion, &r.cachedWSVer, "Sec-WebSocket-Version")
		}
	}
	for i := range r.Headers {
		if EqualFoldASCII(r.Headers[i][0], name) {
			return r.Headers[i][1]
		}
	}
	return ""
}

// ParamValue returns a named route parameter.
//
//	r.GET("/users/:id", func(req *core.Request, resp *core.Response) {
//	    resp.String(req.ParamValue("id"))
//	})
//
//	r.GET("/users/:id/posts/:postID", func(req *core.Request, resp *core.Response) {
//	    resp.String(req.ParamValue("id") + "/" + req.ParamValue("postID"))
//	})
func (r *Request) ParamValue(name string) string {
	for i := 0; i < r.ParamCount; i++ {
		if r.Params[i].Key == name {
			return r.Params[i].Value
		}
	}
	return ""
}

// SetParam appends a synthetic route parameter.
//
//	r.Use(func(next core.HandlerFunc) core.HandlerFunc {
//	    return func(req *core.Request, resp *core.Response) {
//	        req.SetParam("tenant", "default")
//	        next(req, resp)
//	    }
//	})
func (r *Request) SetParam(key, value string) {
	if r.ParamCount < len(r.Params) {
		r.Params[r.ParamCount] = Param{Key: key, Value: value}
		r.ParamCount++
	}
}
