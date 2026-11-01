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
	proxyStartDispatch
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
	cacheHost  string
	cacheKey   string
	cacheGen   uint64
	cache      *ProxyCache

	// When h2Stream is set the response is delivered through the HTTP/2 framing
	// path rather than written into the client's byte stream.
	h2Stream   *H2Stream
	h2StreamID uint32

	// mayCache means a store is possible for this request, so a response that
	// fits the cache is buffered rather than relayed.
	mayCache   bool
	reqCacheOK bool

	keepClient    bool
	headersOut    bool
	streaming     bool
	streamChunked bool
	starting      bool
	reqRaw        []byte

	h2Body     []byte
	h2Reserved int64
	h2Expected int64
	refusal    proxyRefusal
	h2Streamed bool

	admission proxyAdmission

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
		h2Body := px.h2Body[:0]
		*px = proxyExchange{}
		px.req = req
		px.reqRaw = reqRaw
		px.tried = tried
		px.h2Body = h2Body
		return px
	}
	px = &proxyExchange{}
	px.req = &fpRequest{}
	return px
}

func (w *epollWorker) pxPut(px *proxyExchange) {
	px.discardH2Buffer()
	px.admission.release(w.server)
	req := px.req
	*req = fpRequest{}
	reqRaw := px.reqRaw[:0]
	tried := px.tried[:0]
	h2Body := px.h2Body[:0]
	if cap(h2Body) > proxyH2BodyKeep {
		h2Body = nil
	}
	*px = proxyExchange{}
	px.req = req
	px.reqRaw = reqRaw
	px.tried = tried
	px.h2Body = h2Body
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
	scratch := appendProxyResponseHead(w.beScratch[:0], status, headers, declaredLen, keepAlive, contentType)
	w.beScratch = scratch[:0]
	c.writeBuf = c.sealTLSAppDataParts(c.writeBuf, scratch, body)
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
	cacheableMethod := req.Method == "GET" || req.Method == "HEAD"
	reqCacheOK := false
	cachePath := ""

	admission, outcome := w.admitProxyRequest(req, &c.resp)
	if outcome != proxyAdmitted {
		return outcome.startResult()
	}
	if pe.hasHooks() {
		promoteRequestStrings(req)
	}

	cache := pe.activeCache()
	if cache != nil && cacheableMethod {
		reqCacheOK = proxyCacheRequestAllowed(req)
		cachePath = proxyRequestTarget(req)
		if entry, hit := cache.GetFP(req.Method, host, cachePath, reqCacheOK); hit {
			admission.release(w.server)
			w.serveProxyCacheHit(pe, ds, cache, entry, req, &c.resp)
			return proxyStartServed
		}
	}

	if len(ds.backends) == 0 {
		admission.release(w.server)
		return w.proxyFailNow(c, 502, "No healthy backend available")
	}

	px := w.pxGet()
	px.admission = admission
	px.w = w
	px.c = c
	px.cGen = c.generation
	px.pe = pe
	px.ds = ds
	px.method = req.Method
	px.path = req.Path
	px.clientAddr = req.RemoteAddr
	px.keepClient = !reqClose
	px.mayCache = cache != nil && cacheableMethod
	px.reqCacheOK = reqCacheOK
	px.cacheHost = host
	px.cacheKey = cachePath
	px.cacheGen = cache.purgeGeneration()
	px.cache = cache
	for len(px.tried) < len(ds.backends) {
		px.tried = append(px.tried, false)
	}

	if r := w.proxyAttempt(px); r.status != 0 {
		w.pxPut(px)
		return w.proxyFailNow(c, r.status, r.msg)
	}
	c.proxyEx = px
	return proxyStartPending
}

type proxyRefusal struct {
	status int
	msg    string
}

var (
	proxyRefusedNoBackend  = proxyRefusal{502, "No healthy backend available"}
	proxyRefusedByHook     = proxyRefusal{502, "Request blocked by interceptor"}
	proxyRefusedHookFailed = proxyRefusal{502, "Proxy hook failed"}
)

func (r proxyRefusal) answer(resp *Response) {
	resp.Reset()
	resp.Status(r.status).String(r.msg)
}

type proxyAdmission struct {
	requestSlot bool
	ipSlot      *ipReqCounter
}

func (a *proxyAdmission) release(s *Server) {
	if a.ipSlot != nil {
		a.ipSlot.release()
		a.ipSlot = nil
	}
	if a.requestSlot {
		s.releaseRequestSlot()
		a.requestSlot = false
	}
}

type proxyAdmitOutcome uint8

const (
	proxyAdmitted proxyAdmitOutcome = iota
	proxyAdmitAnswered
	proxyAdmitDispatch
)

func (o proxyAdmitOutcome) startResult() int {
	if o == proxyAdmitDispatch {
		return proxyStartDispatch
	}
	return proxyStartServed
}

func (s *Server) proxyNeedsDispatch(pe *ProxyEngine, req *Request) bool {
	if s.onRequestHooks.Load() != nil || isTLSH1Upgrade(req) {
		return true
	}
	if pe == httpRouteEngine {
		return false
	}
	if s.onResponseHooks.Load() == nil && s.corsEngine.Load() == nil &&
		!s.config.EnableCompress && s.config.MaxWriteSize <= 0 {
		return false
	}
	return req.Header("Upgrade") == ""
}

func isTLSH1Upgrade(req *Request) bool {
	return req.IsTLS && !req.IsH2 && req.h1UpgradeFieldSeen()
}

func (w *epollWorker) admitProxyRequest(req *Request, resp *Response) (proxyAdmission, proxyAdmitOutcome) {
	s := w.server
	if !s.tryAcquireRequestSlot() {
		statsBlocked()
		resp.Status(503).String("Service Unavailable")
		return proxyAdmission{}, proxyAdmitAnswered
	}
	a := proxyAdmission{requestSlot: true}
	if s.perIPLimiter == nil && s.rateLimitEngine.Load() == nil && s.onRequestHooks.Load() == nil {
		return a, proxyAdmitted
	}
	return w.admitGuardedProxyRequest(a, req, resp)
}

func (w *epollWorker) admitGuardedProxyRequest(a proxyAdmission, req *Request, resp *Response) (proxyAdmission, proxyAdmitOutcome) {
	s := w.server
	if s.onRequestHooks.Load() != nil {
		a.release(s)
		return proxyAdmission{}, proxyAdmitDispatch
	}
	clientIP := extractIP(req.RemoteAddr)
	if s.perIPLimiter != nil {
		slot, ok := s.perIPLimiter.hold(clientIP, s.perIPRequestLimit())
		if !ok {
			a.release(s)
			statsBlocked()
			resp.Status(429).String("Too Many Requests")
			return proxyAdmission{}, proxyAdmitAnswered
		}
		a.ipSlot = slot
	}
	if outcome := w.proxiedRateLimitOutcome(clientIP, req, resp); outcome != proxyAdmitted {
		a.release(s)
		return proxyAdmission{}, outcome
	}
	return a, proxyAdmitted
}

func (w *epollWorker) proxiedRateLimitOutcome(clientIP string, req *Request, resp *Response) proxyAdmitOutcome {
	rl := w.server.rateLimitEngine.Load()
	if rl == nil || clientIP == "" {
		return proxyAdmitted
	}
	allowed, cr, retryAfter := rl.Check(clientIP, req.Path)
	if allowed {
		return proxyAdmitted
	}
	refusal := rateLimitRefusal{rule: cr, retryAfter: retryAfter}
	if refusal.runsHook(rl) {
		req.loopRateLimitRefusal = refusal
		return proxyAdmitDispatch
	}
	statsBlocked()
	answerTooManyRequests(resp, refusal.retryAfter)
	return proxyAdmitAnswered
}

const (
	proxyHookInlineHeaders      = 8
	proxyHookSmallInlineHeaders = 2
	proxyHookMidInlineHeaders   = 4
	proxyCacheBackend           = "cache"
)

type proxyHookRequest struct {
	ProxyRequest
	headers [proxyHookInlineHeaders][2]string
}

type proxyHookResponse struct {
	ProxyResponse
	headers [proxyHookInlineHeaders][2]string
}

type proxyHookResponseSmall struct {
	ProxyResponse
	headers [proxyHookSmallInlineHeaders][2]string
}

type proxyHookResponseMid struct {
	ProxyResponse
	headers [proxyHookMidInlineHeaders][2]string
}

func newProxyHookResponse(headerCount int) *ProxyResponse {
	switch {
	case headerCount <= proxyHookSmallInlineHeaders:
		hook := &proxyHookResponseSmall{}
		hook.Headers = hook.headers[:0]
		return &hook.ProxyResponse
	case headerCount <= proxyHookMidInlineHeaders:
		hook := &proxyHookResponseMid{}
		hook.Headers = hook.headers[:0]
		return &hook.ProxyResponse
	case headerCount <= proxyHookInlineHeaders:
		hook := &proxyHookResponse{}
		hook.Headers = hook.headers[:0]
		return &hook.ProxyResponse
	}
	return &ProxyResponse{Headers: make([][2]string, 0, headerCount)}
}

func newCacheHitHookResponse(ds *domainState, entry *cacheEntry, req *Request, resp *Response) *ProxyResponse {
	pr := newProxyHookResponse(len(resp.Headers))
	pr.Domain = ds.config.Domain
	pr.Backend = proxyCacheBackend
	pr.ClientAddr = req.RemoteAddr
	pr.Method = req.Method
	pr.Path = req.Path
	pr.StatusCode = entry.statusCode
	pr.Headers = append(pr.Headers, resp.Headers...)
	return pr
}

func adoptHookResponse(resp *Response, pr *ProxyResponse) {
	resp.Status(pr.StatusCode)
	resp.Headers = append(resp.Headers[:0], pr.Headers...)
}

func (pe *ProxyEngine) hasHooks() bool {
	return pe.requestHook() != nil || pe.responseHook() != nil || pe.errorHook() != nil
}

func (w *epollWorker) guardUserHook(req *Request, call func()) (completed bool) {
	defer func() {
		if r := recover(); r != nil {
			w.server.reportPanic(req, r)
			completed = false
		}
	}()
	call()
	return true
}

func (w *epollWorker) serveProxyCacheHit(pe *ProxyEngine, ds *domainState, cache *ProxyCache, entry *cacheEntry, req *Request, resp *Response) {
	cache.ServeCached(entry, req, resp)
	onResponse := pe.responseHook()
	if onResponse == nil {
		return
	}
	pr := newCacheHitHookResponse(ds, entry, req, resp)
	if !w.guardUserHook(req, func() { onResponse(pr) }) {
		proxyRefusedHookFailed.answer(resp)
		return
	}
	adoptHookResponse(resp, pr)
}

func proxyRefusalFor(status int) proxyRefusal {
	return proxyRefusal{status, proxyFailureMessage(status)}
}

func (px *proxyExchange) cachePutOptions() cachePutOptions {
	return cachePutOptions{generation: px.cacheGen, offload: true}
}

func (px *proxyExchange) request() *Request {
	if px.h2Stream != nil {
		return &px.h2Stream.req
	}
	return &px.c.req
}

func (w *epollWorker) proxyAttempt(px *proxyExchange) proxyRefusal {
	for {
		r, err := w.proxyStartBackend(px)
		if err == nil {
			return r
		}
		w.proxyRecordFailure(px, err)
		if status := proxyNextAttempt(px, err); status != 0 {
			return proxyRefusalFor(status)
		}
	}
}

func (w *epollWorker) proxyStartBackend(px *proxyExchange) (proxyRefusal, error) {
	ds := px.ds
	idx := pickRetryBackend(ds, extractIP(px.clientAddr), px.tried)
	if idx < 0 {
		return proxyRefusedNoBackend, nil
	}
	px.tried[idx] = true
	b := ds.backends[idx]
	px.b = b
	px.discardH2Buffer()

	req := px.request()
	hostHdr := ds.config.HostHeader
	if onRequest := px.pe.requestHook(); onRequest != nil {
		hook := &proxyHookRequest{}
		pr := &hook.ProxyRequest
		pr.Domain = ds.config.Domain
		pr.Backend = b.Addr
		pr.ClientAddr = px.clientAddr
		pr.Method = req.Method
		pr.Path = req.Path
		pr.Headers = append(hook.headers[:0], req.Headers...)
		pr.Host = hostHdr
		originalPath := req.Path
		allowed := false
		if !w.guardUserHook(req, func() { allowed = onRequest(pr) }) {
			px.b = nil
			return proxyRefusedHookFailed, nil
		}
		if !allowed {
			px.b = nil
			return proxyRefusedByHook, nil
		}
		if pr.Path != originalPath {
			// The serialiser prefers RawPath so escaped targets survive; a hook
			// that rewrote Path must therefore drop it, or the rewrite is lost.
			req.RawPath = ""
		}
		req.Path = pr.Path
		req.Headers = append(req.Headers[:0], pr.Headers...)
		hostHdr = pr.Host
	}

	authority := b.fpAuthority()
	if hostHdr == "" {
		if ds.config.PreserveHost && req.Host != "" {
			hostHdr = req.Host
		} else {
			hostHdr = authority
		}
	}
	px.reqRaw = appendProxyRequest(px.reqRaw[:0], req, hostHdr)
	px.Exchange.wroteRequest = false
	px.Exchange.replayable = proxyRequestReplayable(req.Method, req.Headers, ds.config.TrustIdempotencyKey)

	ip, port, err := b.fpResolve(authority)
	if err != nil {
		return proxyRefusal{}, err
	}

	px.Exchange.ip = ip
	px.Exchange.port = port
	px.Exchange.key = poolKey{authority: authority, tls: b.TLS, skipVerify: b.TLSSkipVerify, trust: b.trust}
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
	px.starting = true
	w.be.startExchange(&px.Exchange)
	px.starting = false
	if px.finished {
		b.ActiveConns.Add(-1)
		return proxyRefusal{}, px.Exchange.err
	}
	return proxyRefusal{}, nil
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
	if !headers.hasDate() {
		dst = append(dst, currentHTTPDateLine()[:]...)
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

func (h respHeaders) hasDate() bool {
	if h.raw != nil {
		for i := range h.raw {
			if headerNameIsBytes(h.raw[i][0], "date") {
				return true
			}
		}
		return false
	}
	for i := range h.str {
		if name := h.str[i][0]; name == "date" || headerNameIs(name, "date") {
			return true
		}
	}
	return false
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
	manual := hooked != nil && hooked.cacheRequested
	if !manual && !px.reqCacheOK {
		return
	}
	cachePath := px.cacheKey
	host := px.cacheHost
	// A cache entry outlives the exchange, so this is one of the few places that
	// needs the headers as strings. putEntry copies the slice it is given.
	stored := w.headerStrings(headers)
	ctype := proxyContentType(stored)
	if manual {
		px.cache.putManual(px.method, host, cachePath, status, stored, ctype, body,
			hooked.cacheTTL, hooked.cacheMaxHits, hooked.cacheCompress, hooked.cacheCompressMin, px.cachePutOptions())
		return
	}
	if !proxyCacheResponseAllowed(stored) {
		return
	}
	px.cache.put(px.method, host, cachePath, status, stored, ctype, body, px.cachePutOptions())
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

func (w *epollWorker) proxyRecordFailure(px *proxyExchange, err error) {
	if px.b == nil {
		return
	}
	px.ds.outlier.recordFailure(px.b)
	if onError := px.pe.errorHook(); onError != nil {
		perr := ProxyError{
			Domain:     px.ds.config.Domain,
			Backend:    px.b.Addr,
			ClientAddr: px.clientAddr,
			Method:     px.method,
			Path:       px.path,
			Attempt:    px.attempt + 1,
			Err:        err,
		}
		w.guardUserHook(nil, func() { onError(perr) })
	}
	px.b = nil
}

func proxyNextAttempt(px *proxyExchange, err error) int {
	maxRetries := px.ds.config.MaxRetries
	if maxRetries > len(px.ds.backends)-1 {
		maxRetries = len(px.ds.backends) - 1
	}
	attemptErr := fpAttemptError(err, px.Exchange.wroteRequest, false)
	if px.attempt >= maxRetries || !proxyMayRetry(px.Exchange.replayable, attemptErr) {
		return proxyFailureStatus(attemptErr)
	}
	px.attempt++
	return 0
}

func (w *epollWorker) proxyRetry(px *proxyExchange, err error) proxyRefusal {
	if status := proxyNextAttempt(px, err); status != 0 {
		return proxyRefusalFor(status)
	}
	return w.proxyAttempt(px)
}

func (w *epollWorker) proxyRetryOrFail(px *proxyExchange, err error) {
	w.proxyRecordFailure(px, err)

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
	if r := w.proxyRetry(px, err); r.status != 0 {
		w.proxyRefuse(px, r)
	}
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
// that already arrived on the same connection, or a read edge that was seen
// while the exchange was in flight.
func (w *epollWorker) proxyResume(c *epollConn) {
	if !w.flush(c) {
		return
	}
	if c.fd < 0 || c.closeAfter {
		return
	}
	if c.readPending {
		w.readable(c, false)
		return
	}
	if c.readN > c.h1Off || c.tlsAppPending() {
		w.serviceBuffered(c, false, false)
		return
	}
	c.compactH1ReadBuffer()
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
	if !headers.hasDate() {
		dst = append(dst, currentHTTPDateLine()[:]...)
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
