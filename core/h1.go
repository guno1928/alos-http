package core

import (
	"net"
)

var statusLines [600][]byte

var smallCL [256][]byte

func init() {
	codes := map[int]string{
		200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 206: "Partial Content",
		301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
		400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
		405: "Method Not Allowed", 408: "Request Timeout", 413: "Payload Too Large",
		416: "Range Not Satisfiable", 426: "Upgrade Required", 429: "Too Many Requests", 431: "Request Header Fields Too Large",
		500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
	}
	for code, text := range codes {
		line := make([]byte, 0, 48)
		line = append(line, "HTTP/1.1 "...)
		line = appendUint(line, int64(code))
		line = append(line, ' ')
		line = append(line, text...)
		line = append(line, '\r', '\n')
		statusLines[code] = line
	}
	for i := 0; i < 256; i++ {
		b := make([]byte, 0, 32)
		b = append(b, "Content-Length: "...)
		b = appendUint(b, int64(i))
		b = append(b, '\r', '\n')
		smallCL[i] = b
	}
}

func appendStatusLine(buf []byte, code int) []byte {
	if code > 0 && code < len(statusLines) && statusLines[code] != nil {
		return append(buf, statusLines[code]...)
	}
	buf = append(buf, "HTTP/1.1 "...)
	buf = appendUint(buf, int64(code))
	buf = append(buf, ' ')
	buf = append(buf, StatusText(code)...)
	buf = append(buf, '\r', '\n')
	return buf
}

var (
	ctPrefixTextPlain = []byte("Content-Type: text/plain; charset=utf-8\r\n")
	ctPrefixTextHTML  = []byte("Content-Type: text/html; charset=utf-8\r\n")
	ctPrefixJSON      = []byte("Content-Type: application/json; charset=utf-8\r\n")
	ctPrefixOctet     = []byte("Content-Type: application/octet-stream\r\n")
	connKeepAlive     = []byte("Connection: keep-alive\r\nServer: ALOS\r\n")
	connClose         = []byte("Connection: close\r\nServer: ALOS\r\n")
)

func ctPrefixLookup(ct string) []byte {
	switch len(ct) {
	case 25:
		if ct == "text/plain; charset=utf-8" {
			return ctPrefixTextPlain
		}
	case 24:
		if ct == "text/html; charset=utf-8" {
			return ctPrefixTextHTML
		}
		if ct == "application/octet-stream" {
			return ctPrefixOctet
		}
	case 31:
		if ct == "application/json; charset=utf-8" {
			return ctPrefixJSON
		}
	}
	return nil
}

// BuildH1Response serializes resp into a complete HTTP/1.1 response (status
// line, headers, and body) using a buffer drawn from LargeBufPool. It
// returns the built bytes along with the pool slot backing them; the caller
// is responsible for resetting and returning the slot to LargeBufPool.
func BuildH1Response(resp *Response) ([]byte, *[]byte) {
	bp := LargeBufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	headerBodyLen := resp.headerContentLength()

	buf = appendStatusLine(buf, resp.StatusCode)

	if resp.ContentType != "" {
		if pre := ctPrefixLookup(resp.ContentType); pre != nil {
			buf = append(buf, pre...)
		} else {
			buf = append(buf, "Content-Type: "...)
			buf = append(buf, resp.ContentType...)
			buf = append(buf, '\r', '\n')
		}
	}

	if headerBodyLen >= 0 {
		buf = append(buf, "Content-Length: "...)
		buf = appendUint(buf, int64(headerBodyLen))
		buf = append(buf, '\r', '\n')
	}

	for i := range resp.Headers {
		buf = append(buf, resp.Headers[i][0]...)
		buf = append(buf, ':', ' ')
		buf = append(buf, resp.Headers[i][1]...)
		buf = append(buf, '\r', '\n')
	}

	ka, _ := serverConnHeaders(resp)
	buf = append(buf, ka...)
	buf = append(buf, '\r', '\n')
	buf = resp.appendTransmittedBody(buf)

	*bp = buf
	return buf, bp
}

// WriteH1Response encrypts and writes resp to conn as an HTTP/1.1 response
// over the given TLS record writer. Responses small enough to fit in a
// single TLS record are assembled and encrypted directly for minimal
// overhead; larger responses fall back to BuildH1Response followed by
// WriteAppData.
func WriteH1Response(conn net.Conn, writer *TrafficAEAD, resp *Response) error {
	const maxInner = MaxRecordPayload - 1
	body := resp.transmittedBodyBytes()
	bodyLen := len(body)
	headerBodyLen := resp.headerContentLength()
	if bodyLen+256 > maxInner {
		respData, respBP := BuildH1Response(resp)
		err := WriteAppData(conn, writer, respData)
		*respBP = (*respBP)[:0]
		LargeBufPool.Put(respBP)
		return err
	}
	ibp := WriteBufPool.Get().(*[]byte)
	inner := (*ibp)[:0]
	inner = appendStatusLine(inner, resp.StatusCode)
	if resp.ContentType != "" {
		if pre := ctPrefixLookup(resp.ContentType); pre != nil {
			inner = append(inner, pre...)
		} else {
			inner = append(inner, "Content-Type: "...)
			inner = append(inner, resp.ContentType...)
			inner = append(inner, '\r', '\n')
		}
	}
	if headerBodyLen >= 0 {
		inner = append(inner, "Content-Length: "...)
		inner = appendUint(inner, int64(headerBodyLen))
		inner = append(inner, '\r', '\n')
	}
	for i := range resp.Headers {
		inner = append(inner, resp.Headers[i][0]...)
		inner = append(inner, ':', ' ')
		inner = append(inner, resp.Headers[i][1]...)
		inner = append(inner, '\r', '\n')
	}
	ka, _ := serverConnHeaders(resp)
	inner = append(inner, ka...)
	inner = append(inner, '\r', '\n')
	inner = append(inner, body...)
	if len(inner) > maxInner {
		*ibp = (*ibp)[:0]
		WriteBufPool.Put(ibp)
		respData, respBP := BuildH1Response(resp)
		err := WriteAppData(conn, writer, respData)
		*respBP = (*respBP)[:0]
		LargeBufPool.Put(respBP)
		return err
	}
	inner = append(inner, 0x17)
	overhead := writer.Overhead()
	ciphertextLen := len(inner) + overhead
	obp := LargeBufPool.Get().(*[]byte)
	var out []byte
	if cap(*obp) >= 5+ciphertextLen {
		out = (*obp)[:0]
	} else {
		out = make([]byte, 0, 5+ciphertextLen)
	}
	out = append(out, 0x17, 0x03, 0x03, byte(ciphertextLen>>8), byte(ciphertextLen))
	out = writer.EncryptAppend(out, inner)
	err := writeFull(conn, out)
	*ibp = (*ibp)[:0]
	WriteBufPool.Put(ibp)
	*obp = out[:0]
	LargeBufPool.Put(obp)
	return err
}
