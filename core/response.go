package core

import (
	"strings"

	"github.com/bytedance/sonic"
)

// StreamWriter is the interface used for chunked and streaming HTTP responses
// (Server-Sent Events, file downloads, long-polling, etc.). Obtain one from
// Response.EnsureStreamWriter inside a route handler.
//
//	sw := resp.EnsureStreamWriter()
//	sw.WriteHeader(200, nil, "text/event-stream")
//	resp.SetStreamer(sw)
//	sw.WriteChunk([]byte("data: hello\n\n"))
//	sw.Close()
type StreamWriter interface {
	WriteHeader(statusCode int, headers [][2]string, contentType string) error
	WriteChunk(data []byte) error
	Flush() error
	Close() error
}

// Response is the mutable response object passed to every handler.
//
//	srv.Router.GET("/text", func(req *core.Request, resp *core.Response) {
//	    resp.Status(200).String("hello")
//	})
//
//	srv.Router.GET("/json", func(req *core.Request, resp *core.Response) {
//	    resp.Status(200).
//	        SetHeader("Cache-Control", "no-store").
//	        JSONString(`{"ok":true}`)
//	})
//
//	srv.Router.GET("/binary", func(req *core.Request, resp *core.Response) {
//	    resp.Status(200).Bytes([]byte{0x41, 0x4c, 0x4f, 0x53})
//	})
type Response struct {
	StatusCode  int
	Headers     [][2]string
	body        []byte
	bodyString  string
	bodyIsText  bool
	ContentType string
	streamer    StreamWriter
	streamed    bool
	sw          StreamWriter
	lazyReq     *Request
}

const bufferShrinkThreshold = 64 << 10

func shrinkBuffer(buf []byte, defaultCap int) []byte {
	if cap(buf) > bufferShrinkThreshold {
		return make([]byte, 0, defaultCap)
	}
	return buf[:0]
}

func (r *Response) Reset() {
	r.StatusCode = 200
	r.Headers = r.Headers[:0]
	r.body = shrinkBuffer(r.body, 4096)
	r.bodyString = ""
	r.bodyIsText = false
	r.ContentType = ""
	r.streamer = nil
	r.streamed = false
	r.sw = nil
	r.lazyReq = nil
}

func (r *Response) resetFastH1() {
	r.StatusCode = 200
	r.Headers = r.Headers[:0]
	r.body = shrinkBuffer(r.body, 4096)
	r.bodyString = ""
	r.bodyIsText = false
	r.ContentType = ""
	r.streamed = false
}

func (r *Response) SetSW(sw StreamWriter) { r.sw = sw }

// EnsureStreamWriter returns a StreamWriter for the current response, creating
// one lazily if needed. On io_uring paths this takes over the connection fd so
// the caller can use chunked/streaming writes. Returns nil if a StreamWriter
// cannot be obtained (e.g. the connection is already gone).
//
//	sw := resp.EnsureStreamWriter()
//	if sw != nil {
//	    sw.WriteHeader(200, nil, "text/plain")
//	    resp.SetStreamer(sw)
//	    sw.WriteChunk([]byte("hello"))
//	    sw.Close()
//	}
func (r *Response) EnsureStreamWriter() StreamWriter {
	return r.ensureSW()
}

func (r *Response) ensureSW() StreamWriter {
	if r.sw != nil {
		return r.sw
	}
	if r.lazyReq == nil || r.lazyReq.server == nil {
		return nil
	}
	req := r.lazyReq
	if req.conn == nil {
		req.ensureConn()
	}
	if req.conn == nil {
		return nil
	}
	var sw StreamWriter
	if req.tlsWriter != nil {
		sw = req.server.NewH1StreamWriter(req.conn, req.tlsWriter)
	} else {
		sw = req.server.NewPlainH1StreamWriter(req.conn)
	}
	if req.connTakenOver {
		switch writer := sw.(type) {
		case *H1StreamWriter:
			writer.closeAfter = true
		case *PlainH1StreamWriter:
			writer.closeAfter = true
		}
	}
	req.StreamWriter = sw
	bindRequestMethodToStreamWriter(sw, req.Method)
	r.sw = sw
	return sw
}

// Status sets the response status code and returns the same Response.
//
//	resp.Status(201).String("created")
//	resp.Status(404).JSONString(`{"error":"not found"}`)
func (r *Response) Status(code int) *Response {
	r.StatusCode = code
	return r
}

func sanitizeHeaderValue(v string) string {
	if strings.IndexByte(v, '\r') < 0 && strings.IndexByte(v, '\n') < 0 && strings.IndexByte(v, 0) < 0 {
		return v
	}
	b := make([]byte, 0, len(v))
	for j := 0; j < len(v); j++ {
		c := v[j]
		if c != '\r' && c != '\n' && c != 0 {
			b = append(b, c)
		}
	}
	return string(b)
}

// SetHeader appends a sanitized response header.
//
//	resp.SetHeader("Cache-Control", "no-store")
//	resp.SetHeader("X-Frame-Options", "DENY")
//	resp.SetHeader("X-Request-ID", "req-42")
func (r *Response) SetHeader(name, value string) *Response {
	r.Headers = append(r.Headers, [2]string{sanitizeHeaderValue(name), sanitizeHeaderValue(value)})
	return r
}

// SetHeaderUnsafe appends a trusted response header without sanitization.
//
//	resp.SetHeaderUnsafe("Server", "ALOS")
func (r *Response) SetHeaderUnsafe(name, value string) *Response {
	r.Headers = append(r.Headers, [2]string{name, value})
	return r
}

// String writes a UTF-8 plain-text response body.
//
//	resp.Status(200).String("hello world")
//	resp.String("pong")
func (r *Response) String(s string) *Response {
	r.ContentType = "text/plain; charset=utf-8"
	r.body = r.body[:0]
	r.bodyString = s
	r.bodyIsText = true
	return r
}

// HTML writes an HTML response body.
//
//	resp.Status(200).HTML("<h1>Welcome</h1>")
func (r *Response) HTML(s string) *Response {
	r.ContentType = "text/html; charset=utf-8"
	r.body = r.body[:0]
	r.bodyString = s
	r.bodyIsText = true
	return r
}

// Bytes writes raw bytes as application/octet-stream.
//
//	resp.Status(200).Bytes(fileData)
func (r *Response) Bytes(b []byte) *Response {
	r.ContentType = "application/octet-stream"
	r.body = append(r.body[:0], b...)
	r.bodyString = ""
	r.bodyIsText = false
	return r
}

// JSON writes already-encoded JSON bytes.
//
//	resp.Status(200).JSON([]byte(`{"users":[]}`))
//	resp.JSON(payload)
func (r *Response) JSON(jsonBytes []byte) *Response {
	r.ContentType = "application/json; charset=utf-8"
	r.body = append(r.body[:0], jsonBytes...)
	r.bodyString = ""
	r.bodyIsText = false
	return r
}

// JSONString writes JSON from a string literal or prebuilt string.
//
//	resp.Status(200).JSONString(`{"ok":true}`)
func (r *Response) JSONString(s string) *Response {
	r.ContentType = "application/json; charset=utf-8"
	r.body = r.body[:0]
	r.bodyString = s
	r.bodyIsText = true
	return r
}

// JSONMarshal marshals a value with sonic and writes the result as JSON.
//
//	type User struct {
//	    ID   int    `json:"id"`
//	    Name string `json:"name"`
//	}
//
//	_ = resp.Status(200).JSONMarshal(User{ID: 1, Name: "Alice"})
//	_ = resp.JSONMarshal(map[string]any{"ok": true})
func (r *Response) JSONMarshal(v any) error {
	data, err := sonic.Marshal(v)
	if err != nil {
		r.Status(500).String("json marshal error")
		return err
	}
	r.ContentType = "application/json; charset=utf-8"
	r.body = append(r.body[:0], data...)
	r.bodyString = ""
	r.bodyIsText = false
	return nil
}

// SetBody replaces the body without changing the current content type.
//
//	resp.ContentType = "application/xml"
//	resp.SetBody([]byte("<ok/>"))
func (r *Response) SetBody(b []byte) {
	r.body = append(r.body[:0], b...)
	r.bodyString = ""
	r.bodyIsText = false
}

func (r *Response) bodyBytesUnsafe() []byte {
	if r.bodyIsText {
		return UnsafeBytes(r.bodyString)
	}
	return r.body
}

func (r *Response) appendBody(dst []byte) []byte {
	if r.bodyIsText {
		return append(dst, r.bodyString...)
	}
	return append(dst, r.body...)
}

// GetBody returns the current in-memory response body.
//
//	body := resp.GetBody()
func (r *Response) GetBody() []byte {
	if r.bodyIsText {
		return []byte(r.bodyString)
	}
	return r.body
}

// BodyLen returns the byte length of the current response body.
func (r *Response) BodyLen() int {
	if r.bodyIsText {
		return len(r.bodyString)
	}
	return len(r.body)
}

func responseBodyDisposition(method string, statusCode int) (suppressBody bool, omitContentLength bool) {
	if statusCode >= 100 && statusCode < 200 {
		return true, true
	}
	switch statusCode {
	case 204, 205:
		return true, true
	case 304:
		suppressBody = true
	}
	if method != "" {
		if EqualFoldASCII(method, "HEAD") {
			suppressBody = true
		}
		if statusCode >= 200 && statusCode < 300 && EqualFoldASCII(method, "CONNECT") {
			return true, true
		}
	}
	return suppressBody, omitContentLength
}

func (r *Response) headerContentLength() int {
	method := ""
	if r.lazyReq != nil {
		method = r.lazyReq.Method
	}
	_, omitContentLength := responseBodyDisposition(method, r.StatusCode)
	if omitContentLength {
		return -1
	}
	return r.BodyLen()
}

func (r *Response) transmittedBodyLen() int {
	method := ""
	if r.lazyReq != nil {
		method = r.lazyReq.Method
	}
	suppressBody, _ := responseBodyDisposition(method, r.StatusCode)
	if suppressBody {
		return 0
	}
	return r.BodyLen()
}

func (r *Response) transmittedBodyBytes() []byte {
	if r.transmittedBodyLen() == 0 {
		return nil
	}
	return r.bodyBytesUnsafe()
}

func (r *Response) appendTransmittedBody(dst []byte) []byte {
	if r.transmittedBodyLen() == 0 {
		return dst
	}
	return r.appendBody(dst)
}

// SetStreamer marks this response as streamed and associates the given
// StreamWriter. Once set, the server skips its normal body-writing path and
// relies on the StreamWriter to deliver data to the client.
func (r *Response) SetStreamer(sw StreamWriter) {
	r.streamer = sw
	r.streamed = true
}

// Streamer returns the StreamWriter previously set with SetStreamer, or nil.
func (r *Response) Streamer() StreamWriter {
	return r.streamer
}

// IsStreamed reports whether a StreamWriter has been set on this response.
func (r *Response) IsStreamed() bool {
	return r.streamed
}

// Redirect sets a Location header and status code, clearing any body; a code of 0 defaults to 302 Found. It returns r for chaining.
//
// Example: resp.Redirect("/login", 302)
// Example: resp.Redirect("https://example.com/", 301)
// Example: resp.Redirect("/dashboard", 0)
func (r *Response) Redirect(url string, code int) *Response {
	if code == 0 {
		code = 302
	}
	r.StatusCode = code
	r.SetHeader("Location", url)
	r.body = r.body[:0]
	r.bodyString = ""
	r.bodyIsText = false
	r.ContentType = ""
	return r
}

// SetCookie appends a Set-Cookie header for the given cookie. It returns r for chaining.
//
// Example: resp.SetCookie(Cookie{Name: "session", Value: id, Path: "/", HttpOnly: true, Secure: true, SameSite: SameSiteLax})
// Example: resp.SetCookie(Cookie{Name: "theme", Value: "dark", MaxAge: 86400})
func (r *Response) SetCookie(cookie Cookie) *Response {
	r.SetHeader("Set-Cookie", cookie.String())
	return r
}

// DeleteCookie appends a Set-Cookie header that expires the named cookie at path "/" on the client. It returns r for chaining.
//
// Example: resp.DeleteCookie("session")
// Example: resp.DeleteCookie("theme")
func (r *Response) DeleteCookie(name string) *Response {
	r.SetHeader("Set-Cookie", deleteCookieString(name, "/", ""))
	return r
}
