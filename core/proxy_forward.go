//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"

	"github.com/guno1928/turbo"
)

// Handle serves req against the proxy domain matching req.Host: it returns a cached response when available, otherwise forwards the request to a healthy backend with retries, writing the result into resp. It reports false only when req.Host has no registered proxy domain, leaving resp untouched.
func (pe *ProxyEngine) Handle(req *Request, resp *Response) bool {
	host := stripPort(req.Host)
	ds := pe.Lookup(host)
	if ds == nil {
		return false
	}

	pe.serveDomain(ds, host, req, resp)
	return true
}

func (pe *ProxyEngine) serveDomain(ds *domainState, host string, req *Request, resp *Response) {
	cacheableMethod := req.Method == "GET" || req.Method == "HEAD"
	cache := pe.activeCache()
	if cache != nil && cacheableMethod {
		cachePath := req.Path
		if req.Query != "" {
			cachePath = req.Path + "?" + req.Query
		}
		entry, hit := cache.Get(req.Method, host, cachePath, req)
		if hit {
			cache.ServeCached(entry, req, resp)
			if onResponse := pe.responseHook(); onResponse != nil {
				pr := newCacheHitHookResponse(ds, entry, req, resp)
				onResponse(pr)
				adoptHookResponse(resp, pr)
			}
			return
		}
	}

	clientIP := extractIP(req.RemoteAddr)
	if len(ds.backends) == 0 {
		resp.Status(502).String("No healthy backend available")
		return
	}

	tried := make([]bool, len(ds.backends))
	replayable := proxyRequestReplayable(req.Method, req.Headers, ds.config.TrustIdempotencyKey)
	var lastErr error
	maxRetries := ds.config.MaxRetries
	if maxRetries > len(ds.backends)-1 {
		maxRetries = len(ds.backends) - 1
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		idx := pickRetryBackend(ds, clientIP, tried)
		if idx < 0 {
			resp.Status(502).String("No healthy backend available")
			return
		}
		tried[idx] = true

		b := ds.backends[idx]
		attemptReq := *req

		hostOverride := ds.config.HostHeader
		if onRequest := pe.requestHook(); onRequest != nil {
			attemptReq.Headers = append(make([][2]string, 0, len(req.Headers)), req.Headers...)
			pr := &ProxyRequest{
				Domain:     ds.config.Domain,
				Backend:    b.Addr,
				ClientAddr: req.RemoteAddr,
				Method:     attemptReq.Method,
				Path:       attemptReq.Path,
				Headers:    attemptReq.Headers,
				Host:       hostOverride,
			}
			if !onRequest(pr) {
				resp.Status(502).String("Request blocked by interceptor")
				return
			}
			attemptReq.Path = pr.Path
			attemptReq.Headers = pr.Headers
			hostOverride = pr.Host
		}

		cfgCopy := ds.config
		cfgCopy.HostHeader = hostOverride

		b.ActiveConns.Add(1)
		err := pe.forwardRequest(&attemptReq, resp, b, &cfgCopy)
		adoptAttemptTakeover(req, &attemptReq)
		b.ActiveConns.Add(-1)

		if err == nil {
			ds.outlier.recordStatus(b, resp.StatusCode)
			return
		}
		ds.outlier.recordFailure(b)

		if onError := pe.errorHook(); onError != nil {
			onError(ProxyError{
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
		lastErr = err
		if !proxyMayRetry(replayable, err) {
			break
		}
	}

	status := proxyFailureStatus(lastErr)
	resp.Status(status).String(proxyFailureMessage(status))
}

func pickRetryBackend(ds *domainState, clientIP string, tried []bool) int {
	now := ds.outlier.now()
	idx := ds.balancer.pick(ds.backends, clientIP, now)
	if idx >= 0 && idx < len(tried) && !tried[idx] {
		return idx
	}
	for i := range ds.backends {
		if tried[i] || !ds.backends[i].available(now) {
			continue
		}
		return i
	}
	return -1
}

func isProxyFilteredHeaderFold(name string) bool {
	if len(name) > 0 && name[0] == ':' {
		return true
	}
	switch len(name) {
	case 2:
		return headerNameIs(name, "te")
	case 4:
		return headerNameIs(name, "host")
	case 7:
		return headerNameIs(name, "trailer")
	case 9:
		return headerNameIs(name, "x-real-ip") || headerNameIs(name, "forwarded")
	case 10:
		return headerNameIs(name, "keep-alive")
	case 14:
		return headerNameIs(name, "content-length")
	case 15:
		return headerNameIs(name, "accept-encoding") || headerNameIs(name, "x-forwarded-for")
	case 16:
		return headerNameIs(name, "x-forwarded-host")
	case 17:
		return headerNameIs(name, "transfer-encoding") || headerNameIs(name, "x-forwarded-proto")
	case 18:
		return headerNameIs(name, "proxy-authenticate")
	case 19:
		return headerNameIs(name, "proxy-authorization")
	}
	return false
}

const upgradeAnswerHeadHint = 512

func adoptAttemptTakeover(req, attempt *Request) {
	if !attempt.hijacked && !attempt.connTakenOver {
		return
	}
	req.hijacked = attempt.hijacked
	req.connTakenOver = attempt.connTakenOver
	req.conn = attempt.conn
	req.attachConn = attempt.attachConn
}

func deadlineAfter(d time.Duration) time.Time {
	return time.Unix(0, turbo.UnixNano()+int64(d))
}

func upgradeHostHeader(req *Request, b *backend, cfg *DomainConfig) string {
	if host := fpProxyHostHeader(req, cfg); host != "" {
		return host
	}
	return fpProxyAuthority(b.Addr)
}

func answeredUpgradeError(err error) error {
	var netErr net.Error
	return &proxyAttemptError{err: err, wroteRequest: true, gotResponse: true, timeout: errors.As(err, &netErr) && netErr.Timeout()}
}

func (pe *ProxyEngine) forwardUpgrade(req *Request, resp *Response, b *backend, cfg *DomainConfig) error {
	backendConn, err := dialBackendConn(b.Addr, b.TLS, b.TLSSkipVerify, b.trust, cfg.ConnectTimeout)
	if err != nil {
		return err
	}
	tunnelled := false
	defer func() {
		if !tunnelled {
			backendConn.Close()
		}
	}()

	bp := LargeBufPool.Get().(*[]byte)
	upstream := appendProxyRequest((*bp)[:0], req, upgradeHostHeader(req, b, cfg))
	defer func() {
		*bp = upstream[:0]
		putBoxedBufCapped(&LargeBufPool, bp, largeBufPoolMaxCap)
	}()
	if err := writeFull(backendConn, upstream); err != nil {
		return err
	}

	var p h1Parser
	chunked, contentLen, err := readUpgradeAnswer(backendConn, &p, req.Method, cfg.ReadTimeout)
	if err != nil {
		return err
	}
	if p.status != http.StatusSwitchingProtocols {
		if err := relayDeclinedUpgrade(backendConn, &p, chunked, contentLen, req, resp, cfg.ReadTimeout); err != nil {
			return answeredUpgradeError(err)
		}
		return nil
	}
	if !p.upgradeGranted(&Exchange{rawRequest: upstream}) {
		return answeredUpgradeError(ErrProxyBadResponse)
	}

	clientConn := req.HijackConn()
	if clientConn == nil {
		resp.Status(500).String("WebSocket hijack failed")
		return nil
	}
	tunnelled = true
	if err := writeFull(clientConn, appendTunnelResponseHead(upstream[:0], p.hdr)); err != nil {
		backendConn.Close()
		clientConn.Close()
		return nil
	}
	if req.StreamWriter != nil {
		resp.SetStreamer(req.StreamWriter)
	}
	_ = backendConn.SetReadDeadline(time.Time{})
	go pipeUpgradeTunnel(clientConn, backendConn)
	return nil
}

func readUpgradeAnswer(conn net.Conn, p *h1Parser, method string, readTimeout time.Duration) (chunked bool, contentLen int64, err error) {
	if err := conn.SetReadDeadline(deadlineAfter(readTimeout)); err != nil {
		return false, -1, err
	}
	head := make([]byte, 0, upgradeAnswerHeadHint)
	for {
		head, err = readResponseHead(conn, head[:0])
		if err != nil {
			return false, -1, err
		}
		p.hdr = p.hdr[:0]
		chunked, contentLen, err = p.parseHeaderBlock(head[:len(head)-len(fpCrlfcrlf)], method)
		if err != nil {
			return false, -1, answeredUpgradeError(ErrProxyBadResponse)
		}
		if p.status == http.StatusSwitchingProtocols || p.status < http.StatusContinue || p.status >= http.StatusOK {
			return chunked, contentLen, nil
		}
	}
}

func readResponseHead(conn net.Conn, head []byte) ([]byte, error) {
	var one [1]byte
	for !bytes.HasSuffix(head, fpCrlfcrlf) {
		if len(head) >= defaultMaxHeader {
			return nil, answeredUpgradeError(ErrProxyBadResponse)
		}
		if _, err := conn.Read(one[:]); err != nil {
			return nil, err
		}
		head = append(head, one[0])
	}
	return head, nil
}

func relayDeclinedUpgrade(conn net.Conn, p *h1Parser, chunked bool, contentLen int64, req *Request, resp *Response, readTimeout time.Duration) error {
	fields := p.stringHeaders()
	headers := relayableResponseHeaders(fields)
	contentType := fpResponseContentType(fields)
	if p.noBody {
		chunked, contentLen = false, 0
	}
	var sw StreamWriter
	if chunked || contentLen < 0 || contentLen > fpProxyBufferLimit {
		sw = req.StreamWriter
		if sw == nil {
			sw = resp.ensureSW()
		}
	}
	var body io.Reader = conn
	switch {
	case chunked:
		body = httputil.NewChunkedReader(bufio.NewReader(conn))
	case contentLen >= 0:
		body = io.LimitReader(conn, contentLen)
	}
	if sw == nil {
		_ = conn.SetReadDeadline(deadlineAfter(readTimeout))
		buffered, err := io.ReadAll(io.LimitReader(body, defaultMaxBody+1))
		if err != nil {
			return err
		}
		if len(buffered) > defaultMaxBody {
			return errFPBodyTooLarge
		}
		resp.Status(p.status)
		if contentType != "" {
			resp.ContentType = contentType
		}
		for i := range headers {
			resp.SetHeader(headers[i][0], headers[i][1])
		}
		if len(buffered) > 0 {
			copy(resp.prepareBody(len(buffered)), buffered)
		}
		return nil
	}
	if contentLen >= 0 {
		headers = append(headers, [2]string{"Content-Length", strconv.FormatInt(contentLen, 10)})
	}
	if err := sw.WriteHeader(p.status, headers, contentType); err != nil {
		return err
	}
	bp := LargeBufPool.Get().(*[]byte)
	defer putBoxedBufCapped(&LargeBufPool, bp, largeBufPoolMaxCap)
	buf := (*bp)[:cap(*bp)]
	for {
		_ = conn.SetReadDeadline(deadlineAfter(readTimeout))
		n, err := body.Read(buf)
		if n > 0 {
			if werr := sw.WriteChunk(buf[:n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if err := sw.Flush(); err != nil {
		return err
	}
	return sw.Close()
}

func pipeUpgradeTunnel(clientConn, backendConn net.Conn) {
	done := make(chan struct{}, 2)
	copyBuf := func(dst, src net.Conn) {
		buf := LargeBufPool.Get().(*[]byte)
		io.CopyBuffer(dst, src, (*buf)[:cap(*buf)])
		putBoxedBufCapped(&LargeBufPool, buf, largeBufPoolMaxCap)
		done <- struct{}{}
	}
	go copyBuf(backendConn, clientConn)
	go copyBuf(clientConn, backendConn)

	<-done
	backendConn.Close()
	clientConn.Close()
	<-done
}

func extractIP(addr string) string {
	if addr == "" {
		return ""
	}
	if addr[0] == '[' {
		for i := 1; i < len(addr); i++ {
			if addr[i] == ']' {
				return addr[1:i]
			}
		}
		return addr
	}
	lastColon := -1
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			if lastColon == -1 {
				lastColon = i
			} else {
				return addr
			}
		}
	}
	if lastColon >= 0 {
		return addr[:lastColon]
	}
	return addr
}

func stripPort(host string) string {
	if host == "" {
		return ""
	}
	if host[0] == '[' {
		if bracket := indexByte(host, ']'); bracket > 0 {
			return host[1:bracket]
		}
		return host
	}
	lastColon := -1
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			if lastColon >= 0 {
				return host
			}
			lastColon = i
		}
	}
	if lastColon > 0 {
		return host[:lastColon]
	}
	return host
}

// matchProxyTarget resolves a request to the proxy domain that should serve it.
// A host-matched proxy domain wins; failing that a port-80 path route is tried,
// which is how ACME HTTP-01 challenges are forwarded. Both return a domainState
// so the one in-loop engine serves them, rather than the path routes going
// through a second implementation that dialled the backend per request.
func (s *Server) matchProxyTarget(req *Request) (*ProxyEngine, *domainState) {
	if pe := s.proxy.Load(); pe != nil && req.Host != "" {
		if ds := pe.Lookup(stripPort(req.Host)); ds != nil {
			return pe, ds
		}
	}
	if ds := s.matchHTTPRoute(req); ds != nil {
		return httpRouteEngine, ds
	}
	return nil, nil
}

func (s *Server) matchHTTPRoute(req *Request) *domainState {
	if hr := s.httpRouter.Load(); hr != nil && !req.IsTLS {
		if route := hr.match(req.Path); route != nil && route.ds != nil && httpRouteTargetSafe(req) {
			return route.ds
		}
	}
	return nil
}

func preferRawRoutePath(req *Request) {
	rawPath, _ := splitPathQuery(req.RawPath)
	if rawPath != req.Path && sanitizeSplitPath(rawPath) == req.Path {
		req.Path = rawPath
	}
}
