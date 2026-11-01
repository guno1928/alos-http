//go:build linux && amd64

package core

import (
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guno1928/turbo"
)

// HTTPRoute defines an HTTP (non-TLS) routing rule for the server. When the
// server receives a plain HTTP request, it matches the path against PathPrefix
// and forwards to Backend. This is used with Server.SetHTTPRoutes.
//
//	srv.SetHTTPRoutes([]core.HTTPRoute{
//	    {PathPrefix: "/.well-known/acme-challenge/", Backend: "127.0.0.1:8080"},
//	    {PathPrefix: "/", Backend: "https://example.com"},
//	})
type HTTPRoute struct {
	PathPrefix string
	Backend    string
	HostHeader string
}

type httpRouteEntry struct {
	pathPrefix string
	addr       string
	hostHeader string
	// ds lets a port-80 route be served by the unified proxy engine instead of
	// a second implementation that dialled the backend on every request.
	ds *domainState
}

// httpRouteEngine carries no cache and no hooks: a port-80 route has none of
// that configuration, but the in-loop proxy path expects a ProxyEngine to ask.
var httpRouteEngine = &ProxyEngine{}

// newHTTPRouteDomain wraps one path-prefix route as a single-backend domain so
// beginProxy can serve it, which brings connection pooling, per-request
// timeouts and non-blocking relaying to a path that had none.
func newHTTPRouteDomain(addr, hostHeader string) *domainState {
	cfg := DomainConfig{
		Domain:       addr,
		HostHeader:   hostHeader,
		PreserveHost: hostHeader == "",
		Backends:     []BackendConfig{{Addr: addr}},
	}
	cfg.normalize()
	b := &backend{Addr: addr}
	b.Healthy.Store(true)
	return newDomainState(cfg, []*backend{b})
}

type httpRoutesSnapshot struct {
	routes []httpRouteEntry
}

// HTTPRouter holds a set of path-prefix rules that proxy plain HTTP requests
// to backend servers instead of redirecting to HTTPS. It is managed
// internally by Server via SetHTTPRoutes, AddHTTPRoute, and RemoveHTTPRoute.
type HTTPRouter struct {
	snapshot atomic.Pointer[httpRoutesSnapshot]
	mu       sync.Mutex
}

func newHTTPRouter() *HTTPRouter {
	hr := &HTTPRouter{}
	hr.snapshot.Store(&httpRoutesSnapshot{})
	return hr
}

func normalizeRouteAddr(addr string) string {
	if len(addr) > 7 && addr[:7] == "http://" {
		addr = addr[7:]
		if idx := indexByte(addr, '/'); idx >= 0 {
			addr = addr[:idx]
		}
	}
	if len(addr) > 8 && addr[:8] == "https://" {
		addr = addr[8:]
		if idx := indexByte(addr, '/'); idx >= 0 {
			addr = addr[:idx]
		}
	}
	hasColon := false
	for i := 0; i < len(addr); i++ {
		if addr[i] == ':' {
			hasColon = true
			break
		}
	}
	if !hasColon {
		addr += ":80"
	}
	return addr
}

// SetRoutes replaces the router's entire set of routes with routes,
// normalizing each backend address.
//
// Example: hr.SetRoutes([]HTTPRoute{{PathPrefix: "/api/", Backend: "10.0.0.5:3000"}})
func (hr *HTTPRouter) SetRoutes(routes []HTTPRoute) {
	hr.mu.Lock()
	defer hr.mu.Unlock()
	entries := make([]httpRouteEntry, len(routes))
	for i, r := range routes {
		addr := normalizeRouteAddr(r.Backend)
		entries[i] = httpRouteEntry{
			pathPrefix: r.PathPrefix,
			addr:       addr,
			hostHeader: r.HostHeader,
			ds:         newHTTPRouteDomain(addr, r.HostHeader),
		}
	}
	hr.snapshot.Store(&httpRoutesSnapshot{routes: entries})
}

// AddRoute appends a single route without replacing existing ones.
//
// Example: hr.AddRoute(HTTPRoute{PathPrefix: "/api/", Backend: "10.0.0.5:3000"})
func (hr *HTTPRouter) AddRoute(route HTTPRoute) {
	hr.mu.Lock()
	old := hr.snapshot.Load()
	addr := normalizeRouteAddr(route.Backend)
	entry := httpRouteEntry{
		pathPrefix: route.PathPrefix,
		addr:       addr,
		hostHeader: route.HostHeader,
		ds:         newHTTPRouteDomain(addr, route.HostHeader),
	}
	newRoutes := make([]httpRouteEntry, len(old.routes)+1)
	copy(newRoutes, old.routes)
	newRoutes[len(old.routes)] = entry
	hr.snapshot.Store(&httpRoutesSnapshot{routes: newRoutes})
	hr.mu.Unlock()
}

// RemoveRoute removes the route with the given path prefix.
//
// Example: hr.RemoveRoute("/api/")
func (hr *HTTPRouter) RemoveRoute(pathPrefix string) {
	hr.mu.Lock()
	old := hr.snapshot.Load()
	newRoutes := make([]httpRouteEntry, 0, len(old.routes))
	for _, r := range old.routes {
		if r.pathPrefix != pathPrefix {
			newRoutes = append(newRoutes, r)
		}
	}
	hr.snapshot.Store(&httpRoutesSnapshot{routes: newRoutes})
	hr.mu.Unlock()
}

func (hr *HTTPRouter) match(path string) *httpRouteEntry {
	snap := hr.snapshot.Load()
	for i := range snap.routes {
		if hasPrefix(path, snap.routes[i].pathPrefix) {
			return &snap.routes[i]
		}
	}
	return nil
}

func (s *Server) startHTTPRedirect() error {
	addr := s.config.HTTPAddr
	if addr == "-" || addr == "off" || addr == "disable" {
		return nil
	}
	if addr == "" {
		addr = defaultHTTPAddr(s.config.Addr)
		if addr == "-" || addr == "off" || addr == "disable" {
			return nil
		}
	}

	numListeners := s.config.Listeners
	if numListeners <= 0 {
		numListeners = 1
	}

	listeners, err := createListeners(addr, numListeners)
	if err != nil {
		return err
	}
	go func(items []net.Listener) {
		<-s.done
		for _, ln := range items {
			_ = ln.Close()
		}
	}(listeners)
	budget := &httpRedirectBudget{}
	for _, ln := range listeners {
		ln := ln
		go s.serveHTTPRedirectListener(ln, budget)
	}
	s.logger().Info("HTTP redirect listening", "addr", addr, "listeners", len(listeners))
	return nil
}

const (
	acceptRetryMinDelay = 5 * time.Millisecond
	acceptRetryMaxDelay = time.Second
)

func nextAcceptRetryDelay(prev time.Duration) time.Duration {
	if prev <= 0 {
		return acceptRetryMinDelay
	}
	return min(prev*2, acceptRetryMaxDelay)
}

const httpRedirectConnShare = 8

type httpRedirectBudget struct {
	active atomic.Int64
}

func (b *httpRedirectBudget) tryAcquire(maxConns int64) bool {
	n := b.active.Add(1)
	if maxConns > 0 && n > max(maxConns/httpRedirectConnShare, 1) {
		b.active.Add(-1)
		return false
	}
	return true
}

func (b *httpRedirectBudget) release() {
	b.active.Add(-1)
}

func (s *Server) serveHTTPRedirectListener(listener net.Listener, budget *httpRedirectBudget) {
	var retryDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.doneClosed() || errors.Is(err, net.ErrClosed) {
				return
			}
			retryDelay = nextAcceptRetryDelay(retryDelay)
			turbo.Sleep(retryDelay)
			continue
		}
		retryDelay = 0
		go s.serveHTTPRedirectConn(conn, budget)
	}
}

func (s *Server) serveHTTPRedirectConn(conn net.Conn, budget *httpRedirectBudget) {
	limits := s.limits.Load()
	if !budget.tryAcquire(limits.MaxConns) {
		conn.Close()
		return
	}
	defer budget.release()
	if limiter := s.perIPConnLimiter.Load(); limiter != nil && limits.MaxConnsPerIP > 0 && !s.trustedProxies.active {
		key := extractIP(conn.RemoteAddr().String())
		if !limiter.acquire(key, limits.MaxConnsPerIP) {
			conn.Close()
			return
		}
		defer limiter.release(key)
	}
	if !s.tryTrackConn() {
		conn.Close()
		return
	}
	defer s.releaseTrackedConn()
	s.handleHTTPRedirect(conn)
}

func (s *Server) handleHTTPRedirect(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(timeNow().Add(5 * time.Second))

	bp := SmallBufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	defer func() {
		*bp = buf[:0]
		SmallBufPool.Put(bp)
	}()

	tmp := make([]byte, 512)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if containsHeaderEnd(buf) || err != nil || len(buf) > 4096 {
			break
		}
	}

	host, path := extractHostPath(buf)

	path, pathOK := originFormTarget(path)
	if !ValidateHost(host) || !pathOK {
		writeHTTPRouteStatus(conn, 400)
		return
	}

	if hr := s.httpRouter.Load(); hr != nil {
		route := hr.match(sanitizeRequestPath(path))
		if route != nil && route.ds != nil {
			s.proxyHTTPRoute(conn, buf, route.ds)
			return
		}
	}

	if hasPrefix(path, "/.well-known/acme-challenge/") {
		if debugFlag.Load() {
			Dbg("[HTTP] ACME challenge request from %s: %s%s", conn.RemoteAddr(), host, path)
		}

		ai := s.acme.Load()
		if ai != nil && ai.acmeNode != "" {
			if debugFlag.Load() {
				Dbg("[HTTP] proxying ACME challenge to node %s", ai.acmeNode)
			}
			s.proxyHTTPRoute(conn, buf, newHTTPRouteDomain(normalizeRouteAddr(ai.acmeNode), ""))
			return
		}

		if ai != nil {
			resp, ok := ai.HandleHTTP01(path)
			if ok {
				if debugFlag.Load() {
					Dbg("[HTTP] ACME challenge SERVED: %s (len=%d)", path, len(resp))
				}
				_ = writeFull(conn, buildACMEResponse(resp))
				return
			}
			if debugFlag.Load() {
				Dbg("[HTTP] ACME challenge NOT FOUND in handler: %s", path)
			}
		} else {
			if debugFlag.Load() {
				Dbg("[HTTP] ACME challenge request but ACME not enabled: %s", path)
			}
		}

		writeHTTPRouteStatus(conn, 404)
		return
	}

	if host == "" {
		host = "localhost"
	}

	httpsPort := extractPort(s.config.Addr)
	var location string
	if httpsPort == "443" {
		location = "https://" + host + path
	} else {
		location = "https://" + host + ":" + httpsPort + path
	}

	resp := buildRedirectResponse(location)
	_ = writeFull(conn, resp)
}

func (s *Server) proxyHTTPRoute(conn net.Conn, raw []byte, ds *domainState) {
	req := &Request{}
	headerEnd, contentLength, hasContentLength, _, reject, chunked, tooLarge, ok := parseH1RequestHead(raw, req, s.limits.Load().MaxHeaderSize, s.config.MaxHeaderCount)
	switch {
	case tooLarge:
		writeHTTPRouteStatus(conn, 431)
		return
	case !ok || reject != h1RejectNone || req.expect == h1ExpectUnknown || !httpRouteTargetSafe(req):
		writeHTTPRouteStatus(conn, 400)
		return
	case hasContentLength && s.requestBodyTooLarge(contentLength):
		writeHTTPRouteStatus(conn, 413)
		return
	}
	switch {
	case chunked:
		body, status, err := s.readHTTPRouteChunkedBody(conn, raw[headerEnd:], req.expect == h1ExpectContinue)
		if status != 0 {
			writeHTTPRouteStatus(conn, status)
		}
		if status != 0 || err != nil {
			return
		}
		req.Body = body
	case hasContentLength && contentLength > 0:
		body, err := readHTTPRouteBody(conn, raw, headerEnd, contentLength, req.expect == h1ExpectContinue)
		if err != nil {
			return
		}
		req.Body = body
	}
	req.Path, _ = splitPathQuery(req.RawPath)
	req.Host = req.cachedHost
	req.setOwnedRemoteAddr(conn.RemoteAddr().String())
	if s.trustedProxies.active {
		applyTrustedRealIP(req, s.trustedProxies)
	}
	req.server = s
	req.conn = conn
	req.connTakenOver = true
	resp := &Response{}
	resp.lazyReq = req

	b := ds.backends[0]
	err := httpRouteEngine.forwardRequestFP(req, resp, b, &ds.config)
	if sw := req.StreamWriter; sw != nil {
		releaseStreamWriter(sw)
		return
	}
	if err != nil {
		s.logger().Warn("HTTP route backend failed", "backend", b.Addr, "path", req.Path, "err", err)
		writeHTTPRouteStatus(conn, proxyFailureStatus(err))
		return
	}
	_ = writeFull(conn, appendPlainResponseClose(resp, nil))
}

func writeHTTPRouteStatus(conn net.Conn, status int) {
	out := make([]byte, 0, 96+httpDateLineLen)
	out = append(out, "HTTP/1.1 "...)
	out = appendInt(out, status)
	out = append(out, ' ')
	out = append(out, statusText(status)...)
	out = append(out, "\r\n"...)
	out = append(out, currentHTTPDateLine()[:]...)
	out = append(out, "Content-Length: 0\r\nConnection: close\r\n\r\n"...)
	_ = writeFull(conn, out)
}

const (
	httpRouteBodyGrowStep    = 64 << 10
	httpRouteChunkedReadStep = 16 << 10
)

var httpRouteContinue = []byte("HTTP/1.1 100 Continue\r\n\r\n")

func readHTTPRouteBody(conn net.Conn, raw []byte, headerEnd, contentLength int, sendContinue bool) ([]byte, error) {
	need := headerEnd + contentLength
	if len(raw) < need && sendContinue {
		if err := writeFull(conn, httpRouteContinue); err != nil {
			return nil, err
		}
	}
	buf := raw
	for len(buf) < need {
		if len(buf) == cap(buf) {
			buf = slices.Grow(buf, min(need-len(buf), max(len(buf), httpRouteBodyGrowStep)))
		}
		n, err := conn.Read(buf[len(buf):min(need, cap(buf))])
		buf = buf[:len(buf)+n]
		if err != nil && len(buf) < need {
			return nil, err
		}
	}
	return buf[headerEnd:need], nil
}

func (s *Server) readHTTPRouteChunkedBody(conn net.Conn, in []byte, sendContinue bool) (body []byte, status int, err error) {
	var d chunkedDecoder
	for !d.done() {
		consumed, data, decodeErr := d.next(in)
		if decodeErr != nil {
			return nil, 400, nil
		}
		in = in[consumed:]
		body = append(body, data...)
		if s.requestBodyTooLarge(len(body)) {
			return nil, 413, nil
		}
		if consumed > 0 {
			continue
		}
		if sendContinue {
			sendContinue = false
			if err := writeFull(conn, httpRouteContinue); err != nil {
				return nil, 0, err
			}
		}
		in = slices.Grow(in, httpRouteChunkedReadStep)
		n, readErr := conn.Read(in[len(in):cap(in)])
		in = in[:len(in)+n]
		if readErr != nil && n == 0 {
			return nil, 0, readErr
		}
	}
	return body, 0, nil
}

func httpRouteTargetSafe(req *Request) bool {
	rawPath, _ := splitPathQuery(req.RawPath)
	return hasCanonicalSegments(rawPath) && !hasEncodedPathDelimiter(rawPath) && indexByte(rawPath, '\\') < 0
}

func hasCanonicalSegments(p string) bool {
	if len(p) == 0 || p[0] != '/' {
		return false
	}
	start := 1
	for i := 1; i <= len(p); i++ {
		if i < len(p) && p[i] != '/' {
			continue
		}
		seg := p[start:i]
		if seg == "." || seg == ".." || seg == "" && i < len(p) {
			return false
		}
		start = i + 1
	}
	return true
}

func hasEncodedPathDelimiter(p string) bool {
	for i := 0; i+2 < len(p); i++ {
		if p[i] != '%' {
			continue
		}
		hi, lo := p[i+1], p[i+2]|0x20
		if hi == '2' && (lo == 'e' || lo == 'f') || hi == '5' && lo == 'c' {
			return true
		}
	}
	return false
}

func buildACMEResponse(body []byte) []byte {
	bp := SmallBufPool.Get().(*[]byte)
	buf := (*bp)[:0]

	buf = append(buf, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "...)
	buf = appendInt(buf, len(body))
	buf = append(buf, "\r\n"...)
	buf = append(buf, currentHTTPDateLine()[:]...)
	buf = append(buf, "Connection: close\r\n\r\n"...)
	buf = append(buf, body...)

	result := make([]byte, len(buf))
	copy(result, buf)
	*bp = buf[:0]
	SmallBufPool.Put(bp)
	return result
}

func appendInt(dst []byte, n int) []byte {
	if n < 0 {
		n = 0
	}
	var tmp [20]byte
	i := len(tmp)
	if n == 0 {
		return append(dst, '0')
	}
	for n > 0 {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
	}
	return append(dst, tmp[i:]...)
}

func containsHeaderEnd(data []byte) bool {
	for i := 0; i+3 < len(data); i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			return true
		}
	}
	return false
}

func originFormTarget(target string) (string, bool) {
	if containsCRLF(target) {
		return "", false
	}
	if hasPrefix(target, "http://") || hasPrefix(target, "https://") {
		authority := target[indexByte(target, ':')+3:]
		if slash := indexByte(authority, '/'); slash >= 0 {
			target = authority[slash:]
		} else {
			target = "/"
		}
	}
	if len(target) == 0 || target[0] != '/' {
		return "", false
	}
	return target, true
}

func extractHostPath(data []byte) (string, string) {
	s := UnsafeString(data)
	path := "/"
	lineEnd := indexCRLF(s)
	if lineEnd > 0 {
		requestLine := s[:lineEnd]
		sp1 := indexByte(requestLine, ' ')
		if sp1 > 0 {
			rest := requestLine[sp1+1:]
			sp2 := indexByte(rest, ' ')
			if sp2 > 0 {
				path = rest[:sp2]
			} else {
				path = rest
			}
		}
	}

	host := ""
	rest := s
	for {
		nl := indexCRLF(rest)
		if nl < 0 || nl == 0 {
			break
		}
		line := rest[:nl]
		rest = rest[nl+2:]
		colon := indexByte(line, ':')
		if colon > 0 && EqualFoldASCII(line[:colon], "host") {
			host = trimASCIISpace(line[colon+1:])
			if len(host) > 0 && host[0] == '[' {
				if bracket := indexByte(host, ']'); bracket > 0 {
					host = host[1:bracket]
				}
			} else {
				for i := len(host) - 1; i >= 0; i-- {
					if host[i] == ':' {
						host = host[:i]
						break
					}
				}
			}
			break
		}
	}
	return host, path
}

func defaultHTTPAddr(httpsAddr string) string {
	port := extractPort(httpsAddr)
	host := ""
	for i := len(httpsAddr) - 1; i >= 0; i-- {
		if httpsAddr[i] == ':' {
			host = httpsAddr[:i]
			break
		}
	}
	switch port {
	case "443":
		return host + ":80"
	case "8443":
		return host + ":8080"
	default:
		return "-"
	}
}

func extractPort(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[i+1:]
		}
	}
	return "443"
}

func buildRedirectResponse(location string) []byte {
	bp := SmallBufPool.Get().(*[]byte)
	buf := (*bp)[:0]

	buf = append(buf, "HTTP/1.1 301 Moved Permanently\r\nLocation: "...)
	buf = append(buf, location...)
	buf = append(buf, "\r\n"...)
	buf = append(buf, currentHTTPDateLine()[:]...)
	buf = append(buf, "Content-Length: 0\r\nConnection: close\r\n\r\n"...)

	result := make([]byte, len(buf))
	copy(result, buf)
	*bp = buf[:0]
	SmallBufPool.Put(bp)
	return result
}
