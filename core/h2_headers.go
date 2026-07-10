package core

func encodeH2ResponseHeaders(enc *HpackEncoder, statusCode int, contentType string, contentLength int64, headers [][2]string, serverName string) {
	enc.EncodeStatus(statusCode)

	wroteContentType := false
	wroteContentLength := false
	wroteServer := false

	if contentType != "" {
		enc.EncodeHeaderFold("content-type", contentType)
		wroteContentType = true
	}
	if contentLength >= 0 {
		var clBuf [20]byte
		clStr := appendUint(clBuf[:0], contentLength)
		enc.EncodeHeaderFold("content-length", UnsafeString(clStr))
		wroteContentLength = true
	}

	switch len(headers) {
	case 0:
	case 1:
		name := headers[0][0]
		if name != "" && name[0] != ':' && !isHopByHopFold(name) {
			switch {
			case EqualFoldASCII(name, "content-type"):
				if !wroteContentType {
					wroteContentType = true
					enc.EncodeHeaderFold(name, headers[0][1])
				}
			case EqualFoldASCII(name, "content-length"):
				if !wroteContentLength {
					wroteContentLength = true
					enc.EncodeHeaderFold(name, headers[0][1])
				}
			case EqualFoldASCII(name, "server"):
				if !wroteServer {
					wroteServer = true
					enc.EncodeHeaderFold(name, headers[0][1])
				}
			default:
				enc.EncodeHeaderFold(name, headers[0][1])
			}
		}
	default:
		for i := range headers {
			name := headers[i][0]
			if name == "" {
				continue
			}
			if name[0] == ':' || isHopByHopFold(name) {
				continue
			}
			switch {
			case EqualFoldASCII(name, "content-type"):
				if wroteContentType {
					continue
				}
				wroteContentType = true
			case EqualFoldASCII(name, "content-length"):
				if wroteContentLength {
					continue
				}
				wroteContentLength = true
			case EqualFoldASCII(name, "server"):
				if wroteServer {
					continue
				}
				wroteServer = true
			}
			enc.EncodeHeaderFold(name, headers[i][1])
		}
	}

	if !wroteServer {
		enc.EncodeHeaderFold("server", serverName)
	}
}
