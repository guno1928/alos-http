//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"io"
	"time"

	"golang.org/x/sys/unix"
)

func isHopByHopHeader(name string) bool {
	switch {
	case EqualFoldASCII(name, "connection"),
		EqualFoldASCII(name, "keep-alive"),
		EqualFoldASCII(name, "transfer-encoding"),
		EqualFoldASCII(name, "content-length"),
		EqualFoldASCII(name, "upgrade"),
		EqualFoldASCII(name, "proxy-connection"):
		return true
	}
	return false
}

func (s *Server) proxyFetchIntoResponse(route *httpRouteEntry, req *Request, resp *Response) {
	backendConn, err := DialTCP4(route.addr, 5*time.Second)
	if err != nil {
		resp.Status(502).String("Bad Gateway")
		return
	}
	defer backendConn.Close()
	cfg := &DomainConfig{HostHeader: route.hostHeader}
	upstream := buildProxyRequest(nil, req, route.addr, cfg)
	upstream = forceConnectionClose(upstream)
	backendConn.SetWriteDeadline(timeNow().Add(10 * time.Second))
	if err := writeFull(backendConn, upstream); err != nil {
		resp.Status(502).String("Bad Gateway")
		return
	}
	backendConn.SetReadDeadline(timeNow().Add(30 * time.Second))
	br := bufio.NewReaderSize(backendConn, 32768)
	status, _, contentLength, _, chunked, headers, perr := parseHTTPResponse(br)
	if perr != nil {
		resp.Status(502).String("Bad Gateway")
		return
	}
	var body []byte
	if chunked {
		body = epollReadChunkedBody(br)
	} else if contentLength > 0 {
		body = make([]byte, contentLength)
		_, _ = io.ReadFull(br, body)
	} else if contentLength < 0 {
		body, _ = io.ReadAll(br)
	}
	resp.Status(status)
	for i := range headers {
		if isHopByHopHeader(headers[i][0]) {
			continue
		}
		resp.SetHeader(headers[i][0], headers[i][1])
	}
	resp.Bytes(body)
}

func epollReadChunkedBody(br *bufio.Reader) []byte {
	var out []byte
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return out
		}
		size := 0
		for _, ch := range line {
			var d int
			switch {
			case ch >= '0' && ch <= '9':
				d = int(ch - '0')
			case ch >= 'a' && ch <= 'f':
				d = int(ch-'a') + 10
			case ch >= 'A' && ch <= 'F':
				d = int(ch-'A') + 10
			default:
				d = -1
			}
			if d < 0 {
				break
			}
			size = size*16 + d
		}
		if size == 0 {
			return out
		}
		chunk := make([]byte, size)
		if _, err := io.ReadFull(br, chunk); err != nil {
			return out
		}
		out = append(out, chunk...)
		_, _ = br.Discard(2)
	}
}

var epoll502Response = []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

func writeAllRawFd(fd int, p []byte) bool {
	for len(p) > 0 {
		n, err := unix.Write(fd, p)
		if n > 0 {
			p = p[n:]
			continue
		}
		if err == unix.EINTR {
			continue
		}
		return false
	}
	return true
}

func forceConnectionClose(raw []byte) []byte {
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return raw
	}
	lineEnd := bytes.Index(raw, []byte("\r\n"))
	if lineEnd < 0 || lineEnd >= headerEnd {
		return raw
	}
	out := make([]byte, 0, len(raw)+20)
	out = append(out, raw[:lineEnd+2]...)
	out = append(out, "Connection: close\r\n"...)
	rest := raw[lineEnd+2 : headerEnd]
	for len(rest) > 0 {
		nl := bytes.Index(rest, []byte("\r\n"))
		if nl < 0 {
			nl = len(rest)
		}
		line := rest[:nl]
		if !asciiHasPrefixFoldBytes(line, "connection:") {
			out = append(out, line...)
			out = append(out, "\r\n"...)
		}
		if nl >= len(rest) {
			break
		}
		rest = rest[nl+2:]
	}
	out = append(out, "\r\n"...)
	out = append(out, raw[headerEnd+4:]...)
	return out
}

func (s *Server) proxyFetchRaw(route *httpRouteEntry, rawReq []byte) []byte {
	backendConn, err := DialTCP4(route.addr, 5*time.Second)
	if err != nil {
		return epoll502Response
	}
	defer backendConn.Close()
	req := rawReq
	if route.hostHeader != "" {
		req = rewriteHostHeader(req, route.hostHeader)
	}
	req = forceConnectionClose(req)
	backendConn.SetWriteDeadline(timeNow().Add(10 * time.Second))
	if err := writeFull(backendConn, req); err != nil {
		return epoll502Response
	}
	backendConn.SetReadDeadline(timeNow().Add(30 * time.Second))
	var resp []byte
	buf := make([]byte, 32768)
	for {
		n, rerr := backendConn.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	if len(resp) == 0 {
		return epoll502Response
	}
	return resp
}

func (s *Server) epollProxyForward(clientFd int, rawReq []byte, route *httpRouteEntry) {
	defer unix.Close(clientFd)
	_ = unix.SetNonblock(clientFd, false)

	backendConn, err := DialTCP4(route.addr, 5*time.Second)
	if err != nil {
		writeAllRawFd(clientFd, epoll502Response)
		return
	}
	defer backendConn.Close()

	req := rawReq
	if route.hostHeader != "" {
		req = rewriteHostHeader(req, route.hostHeader)
	}
	req = forceConnectionClose(req)

	backendConn.SetWriteDeadline(timeNow().Add(10 * time.Second))
	if err := writeFull(backendConn, req); err != nil {
		writeAllRawFd(clientFd, epoll502Response)
		return
	}

	backendConn.SetReadDeadline(timeNow().Add(30 * time.Second))
	rbp := LargeBufPool.Get().(*[]byte)
	readBuf := (*rbp)[:cap(*rbp)]
	for {
		n, rerr := backendConn.Read(readBuf)
		if n > 0 {
			if !writeAllRawFd(clientFd, readBuf[:n]) {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	*rbp = readBuf[:0]
	LargeBufPool.Put(rbp)
}
