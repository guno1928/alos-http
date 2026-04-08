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

	cacheableMethod := req.Method == "GET" || req.Method == "HEAD"
	cache := pe.Cache
	if cache != nil && cacheableMethod {
		entry, hit := cache.Get(req.Method, host, req.Path, req)
		if hit {
			cache.ServeCached(entry, req, resp)
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
				resp.Status(pr.StatusCode)
				resp.Headers = pr.Headers
			}
			return true
		}
	}

	clientIP := extractIP(req.RemoteAddr)
	baseHeaders := append(make([][2]string, 0, len(req.Headers)), req.Headers...)
	if len(ds.backends) == 0 {
		resp.Status(502).String("No healthy backend available")
		return true
	}

	tried := make([]bool, len(ds.backends))
	maxRetries := ds.config.MaxRetries
	if maxRetries > len(ds.backends)-1 {
		maxRetries = len(ds.backends) - 1
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		idx := pickRetryBackend(ds, clientIP, tried)
		if idx < 0 {
			resp.Status(502).String("No healthy backend available")
			return true
		}
		tried[idx] = true

		b := ds.backends[idx]
		attemptReq := *req
		attemptReq.Headers = append(make([][2]string, 0, len(baseHeaders)), baseHeaders...)

		hostOverride := ds.config.HostHeader
		if pe.OnRequest != nil {
			pr := &ProxyRequest{
				Domain:     ds.config.Domain,
				Backend:    b.Addr,
				ClientAddr: req.RemoteAddr,
				Method:     attemptReq.Method,
				Path:       attemptReq.Path,
				Headers:    attemptReq.Headers,
				Host:       hostOverride,
			}
			if !pe.OnRequest(pr) {
				resp.Status(502).String("Request blocked by interceptor")
				return true
			}
			attemptReq.Path = pr.Path
			attemptReq.Headers = pr.Headers
			hostOverride = pr.Host
		}

		cfgCopy := ds.config
		cfgCopy.HostHeader = hostOverride

		b.ActiveConns.Add(1)
		err := pe.forwardRequest(&attemptReq, resp, b, &cfgCopy)
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
				Attempt:    attempt + 1,
				Err:        err,
			})
		}

		Dbg("[PROXY] backend %s attempt %d failed: %v", b.Addr, attempt+1, err)
	}

	resp.Status(502).String("All backends failed")
	return true
}

func pickRetryBackend(ds *domainState, clientIP string, tried []bool) int {
	idx := ds.balancer.pick(ds.backends, clientIP)
	if idx >= 0 && idx < len(tried) && !tried[idx] {
		return idx
	}
	for i := range ds.backends {
		if tried[i] || !ds.backends[i].Healthy.Load() {
			continue
		}
		return i
	}
	return -1
}

func (pe *ProxyEngine) forwardRequest(req *Request, resp *Response, b *backend, cfg *DomainConfig) error {
	if isWebSocket(req) {
		return pe.forwardWebSocket(req, resp, b, cfg)
	}
	cacheableMethod := req.Method == "GET" || req.Method == "HEAD"
	autoCacheAllowed := cacheableMethod && proxyCacheRequestAllowed(req)
	cache := pe.Cache

	pc, err := b.pool.get()
	if err != nil {
		return err
	}

	if cfg.WriteTimeout > 0 {
		pc.conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
	}

	bp := LargeBufPool.Get().(*[]byte)
	buf := buildProxyRequest((*bp)[:0], req, b.Addr, cfg)
	err = writeFull(pc.conn, buf)
	*bp = buf[:0]
	LargeBufPool.Put(bp)
	if err != nil {
		b.pool.discard(pc)
		return err
	}

	if cfg.ReadTimeout > 0 {
		pc.conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
	}

	statusCode, contentType, contentLength, isChunked, keepAlive, headers, err := parseHTTPResponse(pc.br)
	if err != nil {
		b.pool.discard(pc)
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

		if pr.cacheRequested && cacheableMethod {
			if cache == nil {
				cache = pe.ensureCache()
			}
			if cache != nil {
				manualCache = true
				manualTTL = pr.cacheTTL
				manualMaxHits = pr.cacheMaxHits
				manualCompress = pr.cacheCompress
				manualCompressMin = pr.cacheCompressMin
			}
		}
	}

	if manualCache && (isChunked || contentLength > 65536) {
		cacheMax := cache.config.Load().MaxEntrySize
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
				b.pool.discard(pc)
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
			if manualCache && cache != nil {
				cache.PutManual(req.Method, host, req.Path, statusCode, headers, contentType, body, manualTTL, manualMaxHits, manualCompress, manualCompressMin)
			}

			if keepAlive {
				b.pool.put(pc)
			} else {
				b.pool.discard(pc)
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
				b.pool.discard(pc)
				return err
			}
			resp.SetBody(bodyBuf)
		}

		if manualCache && cache != nil {
			host := stripPort(req.Host)
			cache.PutManual(req.Method, host, req.Path, statusCode, headers, contentType, resp.GetBody(), manualTTL, manualMaxHits, manualCompress, manualCompressMin)
		} else if autoCacheAllowed && cache != nil && proxyCacheResponseAllowed(headers) {
			host := stripPort(req.Host)
			cache.Put(req.Method, host, req.Path, statusCode, headers, contentType, resp.GetBody())
		}

		if keepAlive {
			b.pool.put(pc)
		} else {
			b.pool.discard(pc)
		}
		return nil
	}

	sw := req.StreamWriter
	if sw == nil {
		sw = resp.ensureSW()
	}
	if sw == nil {
		b.pool.discard(pc)
		resp.Status(502).String("Streaming not available")
		return nil
	}

	respHeaders := make([][2]string, len(headers))
	copy(respHeaders, headers)
	if err := sw.WriteHeader(statusCode, respHeaders, contentType); err != nil {
		b.pool.discard(pc)
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
	b.pool.discard(pc)
	if err != nil {
		Dbg("[PROXY] streaming response aborted after headers for %s %s via %s: %v", req.Method, req.Path, b.Addr, err)
	}

	return nil
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
		name := req.Headers[i][0]
		if isProxyFilteredHeaderFold(name) {
			continue
		}
		if !wsUpgrade && (EqualFoldASCII(name, "upgrade") || EqualFoldASCII(name, "connection")) {
			continue
		}
		if containsCRLF(name) || containsCRLF(req.Headers[i][1]) {
			continue
		}
		if EqualFoldASCII(name, "user-agent") {
			hasUserAgent = true
		}
		if EqualFoldASCII(name, "accept") {
			hasAccept = true
		}
		buf = append(buf, name...)
		buf = append(buf, ": "...)
		buf = append(buf, req.Headers[i][1]...)
		buf = append(buf, "\r\n"...)
	}

	if !hasUserAgent {
		_ = hasUserAgent
	}
	_ = hasAccept

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

// isProxyFilteredHeaderFold checks if a header should be filtered in proxy
// requests using case-insensitive comparison (zero allocations).
func isProxyFilteredHeaderFold(name string) bool {
	if len(name) > 0 && name[0] == ':' {
		return true
	}
	switch len(name) {
	case 2:
		return EqualFoldASCII(name, "te")
	case 4:
		return EqualFoldASCII(name, "host")
	case 7:
		return EqualFoldASCII(name, "trailer")
	case 10:
		return EqualFoldASCII(name, "keep-alive")
	case 14:
		return EqualFoldASCII(name, "content-length")
	case 15:
		return EqualFoldASCII(name, "accept-encoding")
	case 17:
		return EqualFoldASCII(name, "transfer-encoding")
	case 18:
		return EqualFoldASCII(name, "proxy-authenticate")
	case 19:
		return EqualFoldASCII(name, "proxy-authorization")
	}
	return false
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

		switch {
		case EqualFoldASCII(name, "content-type"):
			contentType = val
		case EqualFoldASCII(name, "content-length"):
			cl, ok := parseUint(val)
			if ok {
				contentLength = int64(cl)
			}
		case EqualFoldASCII(name, "transfer-encoding"):
			if EqualFoldASCII(val, "chunked") {
				isChunked = true
			}
		case EqualFoldASCII(name, "connection"):
			if EqualFoldASCII(val, "close") {
				keepAlive = false
			}
		}

		if !isHopByHopFold(name) {
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
	nh := len(req.Headers)
	switch {
	case nh == 0:
		return false
	case nh == 1:
		return EqualFoldASCII(req.Headers[0][0], "upgrade") && EqualFoldASCII(req.Headers[0][1], "websocket")
	case nh == 2:
		if EqualFoldASCII(req.Headers[0][0], "upgrade") && EqualFoldASCII(req.Headers[0][1], "websocket") {
			return true
		}
		return EqualFoldASCII(req.Headers[1][0], "upgrade") && EqualFoldASCII(req.Headers[1][1], "websocket")
	case nh == 3:
		if EqualFoldASCII(req.Headers[0][0], "upgrade") && EqualFoldASCII(req.Headers[0][1], "websocket") {
			return true
		}
		if EqualFoldASCII(req.Headers[1][0], "upgrade") && EqualFoldASCII(req.Headers[1][1], "websocket") {
			return true
		}
		return EqualFoldASCII(req.Headers[2][0], "upgrade") && EqualFoldASCII(req.Headers[2][1], "websocket")
	default:
		for i := range req.Headers {
			if EqualFoldASCII(req.Headers[i][0], "upgrade") && EqualFoldASCII(req.Headers[i][1], "websocket") {
				return true
			}
		}
		return false
	}
}

func (pe *ProxyEngine) forwardWebSocket(req *Request, resp *Response, b *backend, cfg *DomainConfig) error {
	backendConn, err := dialBackendConn(b.Addr, b.TLS, b.TLSSkipVerify, cfg.ConnectTimeout)
	if err != nil {
		return err
	}

	bp := LargeBufPool.Get().(*[]byte)
	buf := buildProxyRequest((*bp)[:0], req, b.Addr, cfg)
	err = writeFull(backendConn, buf)
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

	if err := writeFull(clientConn, upgradeBuf); err != nil {
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
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"proxy-connection", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	}
	return false
}

// isHopByHopFold is like isHopByHop but uses case-insensitive comparison.
func isHopByHopFold(name string) bool {
	switch len(name) {
	case 2:
		return EqualFoldASCII(name, "te")
	case 7:
		return EqualFoldASCII(name, "trailer") || EqualFoldASCII(name, "upgrade")
	case 10:
		return EqualFoldASCII(name, "connection") || EqualFoldASCII(name, "keep-alive")
	case 16:
		return EqualFoldASCII(name, "proxy-connection")
	case 17:
		return EqualFoldASCII(name, "transfer-encoding")
	case 18:
		return EqualFoldASCII(name, "proxy-authenticate")
	case 19:
		return EqualFoldASCII(name, "proxy-authorization")
	}
	return false
}

func extractIP(addr string) string {
	if addr == "" {
		return ""
	}
	if addr[0] == '[' {
		end := -1
		for i := 1; i < len(addr); i++ {
			if addr[i] == ']' {
				end = i
				break
			}
		}
		if end > 1 {
			return addr[1:end]
		}
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
