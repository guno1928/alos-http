//go:build linux && amd64

package core

import (
	"strconv"
	"unsafe"
)

// A proxied request is driven entirely inside the worker's event loop: the
// client socket and the backend socket sit in the same epoll set, so parsing a
// request, writing it upstream, reading the response and writing it back are
// four syscalls on one thread with no goroutine and no cross-loop handoff.

const (
	// Responses at or below this size are collected before anything reaches the
	// client, which keeps a retry possible and lets the cache store a body.
	proxyBufferedResponseLimit = 64 << 10
	// Above this much unsent data the backend read side is disarmed until the
	// client drains, so a slow reader cannot pull an unbounded body into memory.
	proxyStreamHighWater = 256 << 10
	proxyStreamLowWater  = 64 << 10
)

const (
	proxyStartServed  = iota // a complete response is already in the write buffer
	proxyStartPending        // an exchange is in flight; the connection must wait
)

type proxyExchange struct {
	Exchange // must stay first: the sink recovers this struct from *Exchange

	w    *epollWorker
	c    *epollConn
	cGen uint32

	pe *ProxyEngine
	ds *domainState
	b  *backend

	attempt int
	tried   []bool

	method     string
	path       string
	clientAddr string

	// When h2Stream is set the response is delivered through the HTTP/2 framing
	// path rather than written into the client's byte stream.
	h2Stream   *H2Stream
	h2StreamID uint32

	// mayCache means a store is possible for this request, so a response that
	// fits the cache is buffered rather than relayed.
	mayCache bool

	keepClient    bool
	headersOut    bool
	streaming     bool
	streamChunked bool
	reqRaw        []byte

	next *proxyExchange
}

// proxyExchangeOf recovers the owning proxyExchange. It is only valid for
// exchanges created by beginProxy, which are exactly those with neither an
// inConn nor a done channel.
func proxyExchangeOf(ex *Exchange) *proxyExchange {
	return (*proxyExchange)(unsafe.Pointer(ex))
}

func (w *epollWorker) pxGet() *proxyExchange {
	px := w.pxFree
	if px != nil {
		w.pxFree = px.next
		req := px.req
		reqRaw := px.reqRaw[:0]
		tried := px.tried[:0]
		*px = proxyExchange{}
		px.req = req
		px.reqRaw = reqRaw
		px.tried = tried
		return px
	}
	px = &proxyExchange{}
	px.req = &fpRequest{}
	return px
}

func (w *epollWorker) pxPut(px *proxyExchange) {
	req := px.req
	*req = fpRequest{}
	reqRaw := px.reqRaw[:0]
	tried := px.tried[:0]
	*px = proxyExchange{}
	px.req = req
	px.reqRaw = reqRaw
	px.tried = tried
	px.next = w.pxFree
	w.pxFree = px
}

// clientAppend adds response bytes to the client's write buffer, encrypting
// them first when the connection is TLS-terminated.
func (w *epollWorker) clientAppend(c *epollConn, plain []byte) {
	if c.tls {
		c.writeBuf = c.sealTLSAppData(c.writeBuf, plain)
		return
	}
	c.writeBuf = append(c.writeBuf, plain...)
}

// writeClientResponse emits a complete response. A plaintext connection is
// filled in place, so the body is copied once on its way to the socket rather
// than staged through a scratch buffer first. TLS still needs one contiguous
// plaintext run to seal.
func (w *epollWorker) writeClientResponse(c *epollConn, status int, headers respHeaders, body []byte, keepAlive bool, contentType string, declaredLen int64) {
	if declaredLen < 0 {
		declaredLen = int64(len(body))
	}
	if !c.tls {
		c.writeBuf = appendProxyResponseHead(c.writeBuf, status, headers, declaredLen, keepAlive, contentType)
		c.writeBuf = append(c.writeBuf, body...)
		return
	}
	scratch := w.beScratch[:0]
	scratch = appendProxyResponseHead(scratch, status, headers, declaredLen, keepAlive, contentType)
	scratch = append(scratch, body...)
	w.beScratch = scratch[:0]
	c.writeBuf = c.sealTLSAppData(c.writeBuf, scratch)
}

// proxyDeclaredLength is what Content-Length must say. A HEAD response carries
// the length the equivalent GET would have returned, not the zero bytes that
// actually travel, so the upstream value is preserved for it.
func proxyDeclaredLength(method string, headers respHeaders, body []byte) int64 {
	if method != "HEAD" {
		return int64(len(body))
	}
	for i, n := 0, headers.count(); i < n; i++ {
		if headers.nameIs(i, "content-length") {
			if v, ok := headers.intValue(i); ok {
				return v
			}
		}
	}
	return int64(len(body))
}

// beginProxy serves req from the proxy engine without leaving the event loop.
// It returns proxyStartServed when a complete response is already buffered, or
// proxyStartPending when a backend exchange is in flight.
func (w *epollWorker) beginProxy(pe *ProxyEngine, ds *domainState, c *epollConn, reqClose bool) int {
	req := &c.req
	host := stripPort(req.Host)

	if pe.Cache != nil && (req.Method == "GET" || req.Method == "HEAD") {
		cachePath := req.Path
		if req.Query != "" {
			cachePath = req.Path + "?" + req.Query
		}
		if entry, hit := pe.Cache.Get(req.Method, host, cachePath, req); hit {
			pe.Cache.ServeCached(entry, req, &c.resp)
			if pe.OnResponse != nil {
				pr := &ProxyResponse{
					Domain:     ds.config.Domain,
					Backend:    "cache",
					ClientAddr: req.RemoteAddr,
					Method:     req.Method,
					Path:       req.Path,
					StatusCode: entry.statusCode,
					Headers:    c.resp.Headers,
				}
				pe.OnResponse(pr)
				c.resp.Status(pr.StatusCode)
				c.resp.Headers = pr.Headers
			}
			return proxyStartServed
		}
	}

	if len(ds.backends) == 0 {
		return w.proxyFailNow(c, 502, "No healthy backend available")
	}

	px := w.pxGet()
	px.w = w
	px.c = c
	px.cGen = c.generation
	px.pe = pe
	px.ds = ds
	px.method = req.Method
	px.path = req.Path
	px.clientAddr = req.RemoteAddr
	px.keepClient = !reqClose
	px.mayCache = pe.Cache != nil && (req.Method == "GET" || req.Method == "HEAD")
	for len(px.tried) < len(ds.backends) {
		px.tried = append(px.tried, false)
	}

	if !w.proxyAttempt(px) {
		return proxyStartServed
	}
	c.proxyEx = px
	return proxyStartPending
}

// proxyAttempt picks a backend and starts an exchange against it. It reports
// false when the request has been answered outright instead.
func (w *epollWorker) proxyAttempt(px *proxyExchange) bool {
	ds := px.ds
	idx := pickRetryBackend(ds, extractIP(px.clientAddr), px.tried)
	if idx < 0 {
		w.proxyFailExchange(px, 502, "No healthy backend available")
		return false
	}
	px.tried[idx] = true
	b := ds.backends[idx]
	px.b = b

	req := &px.c.req
	hostHdr := ds.config.HostHeader
	if px.pe.OnRequest != nil {
		pr := &ProxyRequest{
			Domain:     ds.config.Domain,
			Backend:    b.Addr,
			ClientAddr: px.clientAddr,
			Method:     req.Method,
			Path:       req.Path,
			Headers:    req.Headers,
			Host:       hostHdr,
		}
		originalPath := req.Path
		if !px.pe.OnRequest(pr) {
			w.proxyFailExchange(px, 502, "Request blocked by interceptor")
			return false
		}
		if pr.Path != originalPath {
			// The serialiser prefers RawPath so escaped targets survive; a hook
			// that rewrote Path must therefore drop it, or the rewrite is lost.
			req.RawPath = ""
		}
		req.Path = pr.Path
		req.Headers = pr.Headers
		hostHdr = pr.Host
	}

	authority := fpProxyAuthority(b.Addr)
	if hostHdr == "" {
		if ds.config.PreserveHost {
			hostHdr = req.Host
		} else {
			hostHdr = authority
		}
	}
	px.reqRaw = appendProxyRequest(px.reqRaw[:0], req, hostHdr, extractIP(px.clientAddr))

	ip, port, err := resolveAuthority(authority)
	if err != nil {
		w.proxyRetryOrFail(px, err)
		return px.c.proxyEx != nil || !px.finished
	}

	px.Exchange.ip = ip
	px.Exchange.port = port
	px.Exchange.key = poolKey{authority: authority, tls: b.TLS, skipVerify: b.TLSSkipVerify}
	// The connect timeout bounds reaching the backend; once the request is on
	// the wire h1Proto.attach re-arms the deadline to the read timeout, which
	// each subsequent read then refreshes.
	px.Exchange.connectTimeoutNano = int64(ds.config.ConnectTimeout)
	px.Exchange.readTimeoutNano = int64(ds.config.ReadTimeout)
	px.Exchange.idleTimeoutNano = int64(ds.config.IdleTimeout)
	px.Exchange.maxIdle = ds.config.MaxIdleConns
	px.Exchange.deadline = w.be.nowNano() + proxyStartDeadline(ds)
	px.Exchange.rawRequest = px.reqRaw
	// HEAD responses carry Content-Length but no body; the parser can only know
	// that from the method, so it has to travel with the exchange.
	px.Exchange.req.Method = req.Method
	px.Exchange.resp = fpResponse{}
	px.Exchange.err = nil
	px.finished = false
	px.retried = false

	b.ActiveConns.Add(1)
	w.be.startExchange(&px.Exchange)
	return true
}

// appendProxyStreamHead writes the head of a relayed response. A response of
// unknown length is re-framed as chunked so the client learns where it ends.
func appendProxyStreamHead(dst []byte, status int, headers respHeaders, contentLen int64, keepAlive bool) []byte {
	dst = append(dst, "HTTP/1.1 "...)
	dst = strconv.AppendInt(dst, int64(status), 10)
	dst = append(dst, ' ')
	dst = append(dst, statusText(status)...)
	dst = append(dst, "\r\n"...)
	for i, n := 0, headers.count(); i < n; i++ {
		if headers.hopByHop(i) ||
			headers.nameIs(i, "content-length") ||
			headers.nameIs(i, "transfer-encoding") {
			continue
		}
		dst = headers.appendPair(dst, i)
		dst = append(dst, "\r\n"...)
	}
	if contentLen >= 0 {
		dst = append(dst, "Content-Length: "...)
		dst = strconv.AppendInt(dst, contentLen, 10)
		dst = append(dst, "\r\n"...)
	} else {
		dst = append(dst, "Transfer-Encoding: chunked\r\n"...)
	}
	if keepAlive {
		dst = append(dst, "Connection: keep-alive\r\n"...)
	} else {
		dst = append(dst, "Connection: close\r\n"...)
	}
	return append(dst, "\r\n"...)
}

func appendChunkFrame(dst []byte, data []byte) []byte {
	dst = strconv.AppendUint(dst, uint64(len(data)), 16)
	dst = append(dst, "\r\n"...)
	dst = append(dst, data...)
	return append(dst, "\r\n"...)
}

// proxyMaybeCache stores a fully buffered response, honouring whatever the
// OnResponse hook decided: DontCache suppresses the store outright, CacheThis
// overrides the configured rules with an explicit TTL.
func (w *epollWorker) proxyMaybeCache(px *proxyExchange, status int, headers respHeaders, body []byte, hooked *ProxyResponse) {
	if px.method != "GET" && px.method != "HEAD" {
		return
	}
	if hooked != nil && hooked.cacheSuppressed {
		return
	}
	if px.c == nil {
		return
	}
	cachePath := px.path
	if q := px.c.req.Query; q != "" {
		cachePath = px.path + "?" + q
	}
	host := stripPort(px.c.req.Host)
	// A cache entry outlives the exchange, so this is one of the few places that
	// needs the headers as strings. putEntry copies the slice it is given.
	stored := w.headerStrings(headers)
	ctype := proxyContentType(stored)
	if hooked != nil && hooked.cacheRequested {
		px.pe.Cache.PutManual(px.method, host, cachePath, status, stored, ctype, body,
			hooked.cacheTTL, hooked.cacheMaxHits, hooked.cacheCompress, hooked.cacheCompressMin)
		return
	}
	px.pe.Cache.Put(px.method, host, cachePath, status, stored, ctype, body)
}

// headerStrings materialises headers for the consumers that genuinely need
// them: the cache, HTTP/2 framing and user hooks. The scratch slice is reused,
// and every caller either copies it or finishes with it before returning.
func (w *epollWorker) headerStrings(h respHeaders) [][2]string {
	if h.str != nil {
		return h.str
	}
	w.hdrStrings = w.hdrStrings[:0]
	for _, kv := range h.raw {
		w.hdrStrings = append(w.hdrStrings, [2]string{lowerHeaderName(kv[0]), string(kv[1])})
	}
	return w.hdrStrings
}

// proxyStartDeadline is the budget for reaching the backend. It must stay the
// connect timeout alone, or a blackholed backend would be held open for the
// much longer read timeout. h1Proto.attach re-arms the deadline as soon as the
// request is written, which for a pooled connection is immediately.
func proxyStartDeadline(ds *domainState) int64 {
	if t := int64(ds.config.ConnectTimeout); t > 0 {
		return t
	}
	return int64(ds.config.ReadTimeout)
}

func (w *epollWorker) proxyFailNow(c *epollConn, status int, msg string) int {
	c.resp.Reset()
	c.resp.Status(status).String(msg)
	return proxyStartServed
}

// proxyFailExchange answers the client with an error and discards the exchange.
func (w *epollWorker) proxyFailExchange(px *proxyExchange, status int, msg string) {
	c := px.c
	if c != nil && c.generation == px.cGen && c.fd >= 0 {
		c.resp.Reset()
		c.resp.Status(status).String(msg)
		c.proxyEx = nil
	}
	w.pxPut(px)
}

func (w *epollWorker) proxyRetryOrFail(px *proxyExchange, err error) {
	if px.b != nil {
		px.b.ActiveConns.Add(-1)
		if px.pe.OnError != nil {
			px.pe.OnError(ProxyError{
				Domain:     px.ds.config.Domain,
				Backend:    px.b.Addr,
				ClientAddr: px.clientAddr,
				Method:     px.method,
				Path:       px.path,
				Attempt:    px.attempt + 1,
				Err:        err,
			})
		}
		px.b = nil
	}

	// With the client already gone there is nobody to answer or retry for.
	if px.c == nil {
		w.pxPut(px)
		return
	}
	// Once any response byte has left, the client is committed to this attempt.
	if px.headersOut {
		w.proxyAbort(px)
		return
	}
	maxRetries := px.ds.config.MaxRetries
	if maxRetries > len(px.ds.backends)-1 {
		maxRetries = len(px.ds.backends) - 1
	}
	if px.attempt >= maxRetries {
		w.proxyFinishClient(px, 502, respHeaders{}, []byte("All backends failed"), "text/plain; charset=utf-8")
		return
	}
	px.attempt++
	w.proxyAttempt(px)
}

// proxyAbort tears the client connection down when a failure arrives after the
// response has already started and a clean error is no longer possible.
func (w *epollWorker) proxyAbort(px *proxyExchange) {
	c := px.c
	if c != nil && c.generation == px.cGen && c.fd >= 0 {
		c.proxyEx = nil
		c.dispatching = false
		c.releaseH1BodyBudget()
		if c.inFlight > 0 {
			c.inFlight--
		}
		c.closeAfter = true
		w.flush(c)
	}
	w.pxPut(px)
}

// proxyFinishClient writes a complete response and releases the exchange.
func (w *epollWorker) proxyFinishClient(px *proxyExchange, status int, headers respHeaders, body []byte, contentType string) {
	c := px.c
	if c == nil || c.generation != px.cGen || c.fd < 0 {
		w.pxPut(px)
		return
	}
	w.writeClientResponse(c, status, headers, body, px.keepClient, contentType,
		proxyDeclaredLength(px.method, headers, body))

	c.proxyEx = nil
	c.dispatching = false
	c.releaseH1BodyBudget()
	if c.inFlight > 0 {
		c.inFlight--
	}
	if !px.keepClient {
		c.closeAfter = true
	}
	w.pxPut(px)
	w.proxyResume(c)
}

// proxyResume flushes the finished response and picks up any pipelined request
// that already arrived on the same connection.
func (w *epollWorker) proxyResume(c *epollConn) {
	if !w.flush(c) {
		return
	}
	if c.fd < 0 || c.closeAfter {
		return
	}
	// A TLS connection buffers decrypted requests in appBuf; a plaintext one
	// keeps them in readBuf.
	var action int
	if c.tls {
		if c.appBufOff >= len(c.appBuf) {
			return
		}
		action = c.epollProcessTLS(w.server)
	} else {
		if c.readN <= c.h1Off {
			return
		}
		action = c.epollProcess(w.server)
	}
	if action == epollActionCloseAfterFlush {
		c.closeAfter = true
		w.flush(c)
	}
}

// appendProxyResponseHead writes a status line and headers for a response the
// proxy generated itself.
func appendProxyResponseHead(dst []byte, status int, headers respHeaders, bodyLen int64, keepAlive bool, contentType string) []byte {
	dst = append(dst, "HTTP/1.1 "...)
	dst = strconv.AppendInt(dst, int64(status), 10)
	dst = append(dst, ' ')
	dst = append(dst, statusText(status)...)
	dst = append(dst, "\r\n"...)
	for i, n := 0, headers.count(); i < n; i++ {
		if headers.hopByHop(i) || headers.nameIs(i, "content-length") {
			continue
		}
		dst = headers.appendPair(dst, i)
		dst = append(dst, "\r\n"...)
	}
	if contentType != "" {
		dst = append(dst, "Content-Type: "...)
		dst = append(dst, contentType...)
		dst = append(dst, "\r\n"...)
	}
	dst = append(dst, "Content-Length: "...)
	dst = strconv.AppendInt(dst, int64(bodyLen), 10)
	dst = append(dst, "\r\n"...)
	if keepAlive {
		dst = append(dst, "Connection: keep-alive\r\n"...)
	} else {
		dst = append(dst, "Connection: close\r\n"...)
	}
	return append(dst, "\r\n"...)
}

func proxyContentType(headers [][2]string) string {
	for _, h := range headers {
		if headerNameIs(h[0], "content-type") {
			return h[1]
		}
	}
	return ""
}
