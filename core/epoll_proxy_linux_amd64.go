//go:build linux && amd64

package core

import (
	"bytes"
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



var epoll502Response = []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


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


