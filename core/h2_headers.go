package core

func encodeH2ResponseHeaders(enc *HpackEncoder, statusCode int, contentType string, contentLength int64, headers [][2]string) {
	enc.EncodeStatus(statusCode)

	wroteContentType := false
	wroteContentLength := false
	wroteServer := false

	if contentType != "" {
		enc.EncodeHeader("content-type", contentType)
		wroteContentType = true
	}
	if contentLength >= 0 {
		var clBuf [20]byte
		clStr := appendUint(clBuf[:0], contentLength)
		enc.EncodeHeader("content-length", UnsafeString(clStr))
		wroteContentLength = true
	}

	for i := range headers {
		name := ToLowerASCII(headers[i][0])
		if name == "" {
			continue
		}
		if name[0] == ':' || isHopByHop(name) {
			continue
		}
		switch name {
		case "content-type":
			if wroteContentType {
				continue
			}
			wroteContentType = true
		case "content-length":
			if wroteContentLength {
				continue
			}
			wroteContentLength = true
		case "server":
			if wroteServer {
				continue
			}
			wroteServer = true
		}
		enc.EncodeHeader(name, headers[i][1])
	}

	if !wroteServer {
		enc.EncodeHeader("server", "ALOS")
	}
}
