package core

import "github.com/bytedance/sonic"

// StreamWriter writes streamed responses a chunk at a time.
//
//	type tickerStream struct{}
//
//	func (tickerStream) WriteHeader(statusCode int, headers [][2]string, contentType string) error { return nil }
//	func (tickerStream) WriteChunk(data []byte) error { return nil }
//	func (tickerStream) Flush() error { return nil }
//	func (tickerStream) Close() error { return nil }
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

func (r *Response) Reset() {
	r.StatusCode = 200
	r.Headers = r.Headers[:0]
	r.body = r.body[:0]
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
	r.body = r.body[:0]
	r.bodyString = ""
	r.bodyIsText = false
	r.ContentType = ""
	r.streamed = false
}

func (r *Response) SetSW(sw StreamWriter) { r.sw = sw }

func (r *Response) ensureSW() StreamWriter {
	if r.sw != nil {
		return r.sw
	}
	if r.lazyReq == nil || r.lazyReq.server == nil || r.lazyReq.conn == nil {
		return nil
	}
	req := r.lazyReq
	var sw StreamWriter
	if req.tlsWriter != nil {
		sw = req.server.NewH1StreamWriter(req.conn, req.tlsWriter)
	} else {
		sw = req.server.NewPlainH1StreamWriter(req.conn)
	}
	req.StreamWriter = sw
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
	for i := 0; i < len(v); i++ {
		if v[i] == '\r' || v[i] == '\n' || v[i] == 0 {
			b := make([]byte, 0, len(v))
			for j := 0; j < len(v); j++ {
				c := v[j]
				if c != '\r' && c != '\n' && c != 0 {
					b = append(b, c)
				}
			}
			return string(b)
		}
	}
	return v
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
		return append(r.body[:0], r.bodyString...)
	}
	return r.body
}

func (r *Response) BodyLen() int {
	if r.bodyIsText {
		return len(r.bodyString)
	}
	return len(r.body)
}

func (r *Response) SetStreamer(sw StreamWriter) {
	r.streamer = sw
	r.streamed = true
}

func (r *Response) Streamer() StreamWriter {
	return r.streamer
}

func (r *Response) IsStreamed() bool {
	return r.streamed
}
