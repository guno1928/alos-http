package core

import (
	"bufio"
	"io"
	"net"
	"time"
)

func (pe *ProxyEngine) Handle(req *Request, resp *Response) bool {
	host := stripPort(req.Host)
	ds := pe.Lookup(host)
	if ds == nil {
		return false
	}

	if pe.Cache != nil && (req.Method == "GET" || req.Method == "HEAD") {
		entry, hit := pe.Cache.Get(req.Method, host, req.Path, req.Header("accept-encoding"))
		if hit {
			pe.Cache.ServeCached(entry, req, resp)
			if pe.OnResponse != nil {
				pr := &ProxyResponse{
					Domain:     ds.config.Domain,
					Backend:    "cache",
					ClientAddr: req.RemoteAddr,
					Method:     req.Method,
					Path:       req.Path,
					StatusCode: entry.statusCode,
					Headers:    resp.Headers,
				}
				pe.OnResponse(pr)
				resp.Headers = pr.Headers
			}
			return true
		}
	}

	clientIP := extractIP(req.RemoteAddr)

	tried := uint64(0)
	maxRetries := ds.config.MaxRetries
	if maxRetries > len(ds.backends) {
		maxRetries = len(ds.backends)
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		idx := ds.balancer.pick(ds.backends, clientIP)
		if idx < 0 {
			resp.Status(502).String("No healthy backend available")
			return true
		}

		if idx < 64 {
			bit := uint64(1) << uint(idx)
			if tried&bit != 0 {
				continue
			}
			tried |= bit
		}

		b := ds.backends[idx]

		hostOverride := ds.config.HostHeader
		if pe.OnRequest != nil {
			pr := &ProxyRequest{
				Domain:     ds.config.Domain,
				Backend:    b.Addr,
				ClientAddr: req.RemoteAddr,
				Method:     req.Method,
				Path:       req.Path,
				Headers:    req.Headers,
				Host:       hostOverride,
			}
			if !pe.OnRequest(pr) {
				resp.Status(502).String("Request blocked by interceptor")
				return true
			}
			req.Headers = pr.Headers
			hostOverride = pr.Host
		}

		cfgCopy := ds.config
		cfgCopy.HostHeader = hostOverride

		b.ActiveConns.Add(1)
		err := pe.forwardRequest(req, resp, b, &cfgCopy)
		b.ActiveConns.Add(-1)

		if err == nil {
			return true
		}

		if pe.OnError != nil {
			pe.OnError(ProxyError{
				Domain:     ds.config.Domain,
				Backend:    b.Addr,
				ClientAddr: req.RemoteAddr,
				Method:     req.Method,
				Path:       req.Path,
				Attempt:    attempt,
				Err:        err,
			})
		}

		Dbg("[PROXY] backend %s attempt %d failed: %v", b.Addr, attempt, err)
	}

	resp.Status(502).String("All backends failed")
	return true
}

func (pe *ProxyEngine) forwardRequest(req *Request, resp *Response, b *backend, cfg *DomainConfig) error {
	if isWebSocket(req) {
		return pe.forwardWebSocket(req, resp, b, cfg)
	}

	pc, err := b.pool.get()
	if err != nil {
		return err
	}

	if cfg.WriteTimeout > 0 {
		pc.conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
	}

	bp := LargeBufPool.Get().(*[]byte)
	buf := buildProxyRequest((*bp)[:0], req, b.Addr, cfg)
	_, err = pc.conn.Write(buf)
	*bp = buf[:0]
	LargeBufPool.Put(bp)
	if err != nil {
		pc.conn.Close()
		return err
	}

	if cfg.ReadTimeout > 0 {
		pc.conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
	}

	statusCode, contentType, contentLength, isChunked, keepAlive, headers, err := parseHTTPResponse(pc.br)
	if err != nil {
		pc.conn.Close()
		return err
	}

	var manualCache bool
	var manualTTL time.Duration
	var manualMaxHits uint64
	var manualCompress bool
	var manualCompressMin int

	if pe.OnResponse != nil {
		pr := &ProxyResponse{
			Domain:     cfg.Domain,
			Backend:    b.Addr,
			ClientAddr: req.RemoteAddr,
			Method:     req.Method,
			Path:       req.Path,
			StatusCode: statusCode,
			Headers:    headers,
		}
		pe.OnResponse(pr)
		headers = pr.Headers
		statusCode = pr.StatusCode

		if pr.cacheRequested && pe.Cache != nil {
			manualCache = true
			manualTTL = pr.cacheTTL
			manualMaxHits = pr.cacheMaxHits
			manualCompress = pr.cacheCompress
			manualCompressMin = pr.cacheCompressMin
		}
	}

	if manualCache && (isChunked || contentLength > 65536) {
		cacheMax := pe.Cache.config.Load().MaxEntrySize
		if cacheMax <= 0 {
			cacheMax = 4 << 20
		}

		var body []byte
		var bufOK bool

		if isChunked {
			body, bufOK = readChunkedBody(pc.br, cacheMax)
		} else if contentLength <= cacheMax {
			body = make([]byte, contentLength)
			_, err := io.ReadFull(pc.br, body)
			if err != nil {
				pc.conn.Close()
				return err
			}
			bufOK = true
		}

		if bufOK {
			resp.Status(statusCode)
			if contentType != "" {
				resp.ContentType = contentType
			}
			for i := range headers {
				resp.SetHeader(headers[i][0], headers[i][1])
			}
			resp.SetBody(body)

			host := stripPort(req.Host)
			pe.Cache.PutManual(req.Method, host, req.Path, statusCode, headers, contentType, body, manualTTL, manualMaxHits, manualCompress, manualCompressMin)

			if keepAlive {
				b.pool.put(pc)
			} else {
				pc.conn.Close()
			}
			return nil
		}
	}

	if !isChunked && contentLength >= 0 && contentLength <= 65536 {
		resp.Status(statusCode)
		if contentType != "" {
			resp.ContentType = contentType
		}
		for i := range headers {
			resp.SetHeader(headers[i][0], headers[i][1])
		}

		if contentLength > 0 {
			bodyBuf := make([]byte, contentLength)
			_, err := io.ReadFull(pc.br, bodyBuf)
			if err != nil {
				pc.conn.Close()
				return err
			}
			resp.SetBody(bodyBuf)
		}

		if pe.Cache != nil {
			host := stripPort(req.Host)
			if manualCache {
				pe.Cache.PutManual(req.Method, host, req.Path, statusCode, headers, contentType, resp.GetBody(), manualTTL, manualMaxHits, manualCompress, manualCompressMin)
			} else {
				pe.Cache.Put(req.Method, host, req.Path, statusCode, headers, contentType, resp.GetBody())
			}
		}

		if keepAlive {
			b.pool.put(pc)
		} else {
			pc.conn.Close()
		}
		return nil
	}

	sw := req.StreamWriter
	if sw == nil {
		pc.conn.Close()
		resp.Status(502).String("Streaming not available")
		return nil
	}

	respHeaders := make([][2]string, len(headers))
	copy(respHeaders, headers)
	if err := sw.WriteHeader(statusCode, respHeaders, contentType); err != nil {
		pc.conn.Close()
		return err
	}

	rbp := LargeBufPool.Get().(*[]byte)
	readBuf := (*rbp)[:cap(*rbp)]

	if isChunked {
		err = streamChunked(pc.br, sw, readBuf)
	} else if contentLength > 0 {
		err = streamFixed(pc.br, sw, readBuf, contentLength)
	} else {
		err = streamUntilClose(pc.br, sw, readBuf)
	}

	*rbp = readBuf[:0]
	LargeBufPool.Put(rbp)

	sw.Close()
	resp.SetStreamer(sw)
	pc.conn.Close()
	return err
}

func streamFixed(br io.Reader, sw StreamWriter, buf []byte, total int64) error {
	remaining := total
	for remaining > 0 {
		n := int64(len(buf))
		if n > remaining {
			n = remaining
		}
		nr, err := br.Read(buf[:n])
		if nr > 0 {
			if werr := sw.WriteChunk(buf[:nr]); werr != nil {
				return werr
			}
			remaining -= int64(nr)
		}
		if err != nil {
			if err == io.EOF && remaining == 0 {
				return nil
			}
			return err
		}
	}
	return nil
}

func streamChunked(br io.Reader, sw StreamWriter, buf []byte) error {
	for {
		sizeLine, err := readLine(br, buf[:0])
		if err != nil {
			return err
		}
		trimmed := trimASCIISpaceBytes(sizeLine)
		if semi := indexByteSlice(trimmed, ';'); semi >= 0 {
			trimmed = trimmed[:semi]
		}
		size, ok := parseHex64Bytes(trimmed)
		if !ok {
			return ErrProxyBadResponse
		}
		if size == 0 {
			readLine(br, buf[:0])
			return nil
		}
		remaining := size
		for remaining > 0 {
			n := int64(len(buf))
			if n > remaining {
				n = remaining
			}
			nr, rerr := br.Read(buf[:n])
			if nr > 0 {
				if werr := sw.WriteChunk(buf[:nr]); werr != nil {
					return werr
				}
				remaining -= int64(nr)
			}
			if rerr != nil {
				return rerr
			}
		}
		readLine(br, buf[:0])
	}
}

func streamUntilClose(br io.Reader, sw StreamWriter, buf []byte) error {
	for {
		n, err := br.Read(buf)
		if n > 0 {
			if werr := sw.WriteChunk(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func readLine(r io.Reader, buf []byte) ([]byte, error) {
	if br, ok := r.(*bufio.Reader); ok {
		for {
			b, err := br.ReadByte()
			if err != nil {
				return buf, err
			}
			buf = append(buf, b)
			if b == '\n' {
				return buf, nil
			}
			if len(buf) > 8192 {
				return buf, ErrProxyBadResponse
			}
		}
	}
	var oneByte [1]byte
	for {
		_, err := r.Read(oneByte[:])
		if err != nil {
			return buf, err
		}
		buf = append(buf, oneByte[0])
		if oneByte[0] == '\n' {
			return buf, nil
		}
		if len(buf) > 8192 {
			return buf, ErrProxyBadResponse
		}
	}
}

func readChunkedBody(br io.Reader, maxSize int64) ([]byte, bool) {
	body := make([]byte, 0, 8192)
	var lineBuf [64]byte
	for {
		line, err := readLine(br, lineBuf[:0])
		if err != nil {
			return nil, false
		}
		trimmed := trimASCIISpaceBytes(line)
		if semi := indexByteSlice(trimmed, ';'); semi >= 0 {
			trimmed = trimmed[:semi]
		}
		size, ok := parseHex64Bytes(trimmed)
		if !ok {
			return nil, false
		}
		if size == 0 {
			readLine(br, lineBuf[:0])
			return body, true
		}
		if maxSize > 0 && int64(len(body))+size > maxSize {
			return nil, false
		}
		start := len(body)
		needed := start + int(size)
		if needed > cap(body) {
			newCap := cap(body) * 2
			if newCap < needed {
				newCap = needed
			}
			grown := make([]byte, start, newCap)
			copy(grown, body)
			body = grown
		}
		body = body[:needed]
		if _, err := io.ReadFull(br, body[start:needed]); err != nil {
			return nil, false
		}
		readLine(br, lineBuf[:0])
	}
}

func buildProxyRequest(buf []byte, req *Request, backendAddr string, cfg *DomainConfig) []byte {
	buf = append(buf, req.Method...)
	buf = append(buf, ' ')
	if containsCRLF(req.Path) {
		buf = append(buf, '/')
	} else {
		buf = append(buf, req.Path...)
	}
	buf = append(buf, " HTTP/1.1\r\n"...)

	buf = append(buf, "Host: "...)
	if cfg.HostHeader != "" && !containsCRLF(cfg.HostHeader) {
		buf = append(buf, cfg.HostHeader...)
	} else if cfg.PreserveHost && req.Host != "" && !containsCRLF(req.Host) {
		buf = append(buf, req.Host...)
	} else {
		buf = append(buf, stripPort(backendAddr)...)
	}
	buf = append(buf, "\r\n"...)

	wsUpgrade := isWebSocket(req)

	hasUserAgent := false
	hasAccept := false
	for i := range req.Headers {
		name := ToLowerASCII(req.Headers[i][0])
		if isProxyFilteredHeader(name) {
			continue
		}
		if !wsUpgrade && (name == "upgrade" || name == "connection") {
			continue
		}
		if containsCRLF(req.Headers[i][0]) || containsCRLF(req.Headers[i][1]) {
			continue
		}
		if name == "user-agent" {
			hasUserAgent = true
		}
		if name == "accept" {
			hasAccept = true
		}
		buf = append(buf, req.Headers[i][0]...)
		buf = append(buf, ": "...)
		buf = append(buf, req.Headers[i][1]...)
		buf = append(buf, "\r\n"...)
	}

	if !hasUserAgent {
		buf = append(buf, "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"...)
	}
	if !hasAccept {
		buf = append(buf, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"...)
	}

	buf = append(buf, "Accept-Encoding: identity\r\n"...)

	if req.RemoteAddr != "" {
		clientIP := extractIP(req.RemoteAddr)
		if clientIP != "" {
			buf = append(buf, "X-Forwarded-For: "...)
			buf = append(buf, clientIP...)
			buf = append(buf, "\r\n"...)
		}
	}

	if len(req.Body) > 0 {
		buf = append(buf, "Content-Length: "...)
		buf = appendUint(buf, int64(len(req.Body)))
		buf = append(buf, "\r\n"...)
	}

	if !wsUpgrade {
		buf = append(buf, "Connection: keep-alive\r\n"...)
	}
	buf = append(buf, "\r\n"...)

	if len(req.Body) > 0 {
		buf = append(buf, req.Body...)
	}

	return buf
}

func isProxyFilteredHeader(name string) bool {
	if len(name) > 0 && name[0] == ':' {
		return true
	}
	switch name {
	case "host", "content-length", "accept-encoding",
		"keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding":
		return true
	}
	return false
}

func parseHTTPResponse(br *bufio.Reader) (int, string, int64, bool, bool, [][2]string, error) {
	bp := SmallBufPool.Get().(*[]byte)
	lineBuf := (*bp)[:0]

	statusLine, err := readLine(br, lineBuf)
	if err != nil {
		*bp = lineBuf[:0]
		SmallBufPool.Put(bp)
		return 0, "", 0, false, false, nil, err
	}

	statusCode := 0
	s := string(statusLine)
	if len(s) < 12 || s[0] != 'H' {
		*bp = lineBuf[:0]
		SmallBufPool.Put(bp)
		return 0, "", 0, false, false, nil, ErrProxyBadResponse
	}
	for i := 9; i < 12 && i < len(s); i++ {
		d := s[i]
		if d < '0' || d > '9' {
			*bp = lineBuf[:0]
			SmallBufPool.Put(bp)
			return 0, "", 0, false, false, nil, ErrProxyBadResponse
		}
		statusCode = statusCode*10 + int(d-'0')
	}

	var contentType string
	contentLength := int64(-1)
	isChunked := false
	keepAlive := true
	var headers [][2]string

	for {
		lineBuf = lineBuf[:0]
		line, err := readLine(br, lineBuf)
		if err != nil {
			*bp = lineBuf[:0]
			SmallBufPool.Put(bp)
			return statusCode, contentType, contentLength, isChunked, keepAlive, headers, err
		}
		for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			break
		}

		colon := indexByteSlice(line, ':')
		if colon <= 0 {
			continue
		}
		name := string(line[:colon])
		val := string(trimASCIISpaceBytes(line[colon+1:]))
		nameLower := ToLowerASCII(name)

		switch nameLower {
		case "content-type":
			contentType = val
		case "content-length":
			cl, ok := parseUint(val)
			if ok {
				contentLength = int64(cl)
			}
		case "transfer-encoding":
			if EqualFoldASCII(val, "chunked") {
				isChunked = true
			}
		case "connection":
			if EqualFoldASCII(val, "close") {
				keepAlive = false
			}
		}

		if !isHopByHop(nameLower) {
			headers = append(headers, [2]string{name, val})
			if len(headers) > 128 {
				*bp = lineBuf[:0]
				SmallBufPool.Put(bp)
				return statusCode, contentType, contentLength, isChunked, keepAlive, headers, ErrProxyBadResponse
			}
		}
	}

	*bp = lineBuf[:0]
	SmallBufPool.Put(bp)
	return statusCode, contentType, contentLength, isChunked, keepAlive, headers, nil
}

func isWebSocket(req *Request) bool {
	for i := range req.Headers {
		if EqualFoldASCII(req.Headers[i][0], "upgrade") && EqualFoldASCII(req.Headers[i][1], "websocket") {
			return true
		}
	}
	return false
}

func (pe *ProxyEngine) forwardWebSocket(req *Request, resp *Response, b *backend, cfg *DomainConfig) error {
	backendConn, err := DialTCP4(b.Addr, cfg.ConnectTimeout)
	if err != nil {
		return err
	}

	bp := LargeBufPool.Get().(*[]byte)
	buf := buildProxyRequest((*bp)[:0], req, b.Addr, cfg)
	_, err = backendConn.Write(buf)
	*bp = buf[:0]
	LargeBufPool.Put(bp)
	if err != nil {
		backendConn.Close()
		return err
	}

	clientConn := req.HijackConn()
	if clientConn == nil {
		backendConn.Close()
		resp.Status(500).String("WebSocket hijack failed")
		return nil
	}

	rbp := SmallBufPool.Get().(*[]byte)
	upgradeBuf := (*rbp)[:0]

	var one [1]byte
	for {
		_, err := backendConn.Read(one[:])
		if err != nil {
			*rbp = upgradeBuf[:0]
			SmallBufPool.Put(rbp)
			backendConn.Close()
			return err
		}
		upgradeBuf = append(upgradeBuf, one[0])
		if len(upgradeBuf) >= 4 {
			last4 := upgradeBuf[len(upgradeBuf)-4:]
			if last4[0] == '\r' && last4[1] == '\n' && last4[2] == '\r' && last4[3] == '\n' {
				break
			}
		}
		if len(upgradeBuf) > 8192 {
			*rbp = upgradeBuf[:0]
			SmallBufPool.Put(rbp)
			backendConn.Close()
			return ErrProxyBadResponse
		}
	}

	if _, err := clientConn.Write(upgradeBuf); err != nil {
		*rbp = upgradeBuf[:0]
		SmallBufPool.Put(rbp)
		backendConn.Close()
		clientConn.Close()
		return err
	}
	*rbp = upgradeBuf[:0]
	SmallBufPool.Put(rbp)

	if req.StreamWriter != nil {
		resp.SetStreamer(req.StreamWriter)
	}

	done := make(chan struct{}, 2)
	copyBuf := func(dst, src net.Conn) {
		buf := LargeBufPool.Get().(*[]byte)
		io.CopyBuffer(dst, src, (*buf)[:cap(*buf)])
		*buf = (*buf)[:0]
		LargeBufPool.Put(buf)
		done <- struct{}{}
	}
	go copyBuf(backendConn, clientConn)
	go copyBuf(clientConn, backendConn)

	<-done
	backendConn.Close()
	clientConn.Close()
	<-done

	return nil
}

func isHopByHop(name string) bool {
	switch name {
	case "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding":
		return true
	}
	return false
}

func extractIP(addr string) string {
	if addr == "" {
		return ""
	}
	if addr[len(addr)-1] >= '0' && addr[len(addr)-1] <= '9' {
		for i := len(addr) - 1; i >= 0; i-- {
			if addr[i] == ':' {
				return addr[:i]
			}
		}
		return addr
	}
	idx := -1
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			idx = i
			break
		}
	}
	if idx >= 0 {
		if addr[0] == '[' && idx > 0 && addr[idx-1] == ']' {
			return addr[1 : idx-1]
		}
		return addr[:idx]
	}
	return addr
}

func stripPort(host string) string {
	if host == "" {
		return ""
	}
	idx := -1
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			idx = i
			break
		}
	}
	if idx >= 0 {
		hasBracket := false
		bracket := -1
		for i := len(host) - 1; i >= 0; i-- {
			if host[i] == ']' {
				hasBracket = true
				bracket = i
				break
			}
		}
		if hasBracket {
			if bracket < idx {
				return host[:idx]
			}
			return host
		}
		return host[:idx]
	}
	return host
}
