package core

import (
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
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
	entries := make([]httpRouteEntry, len(routes))
	for i, r := range routes {
		entries[i] = httpRouteEntry{
			pathPrefix: r.PathPrefix,
			addr:       normalizeRouteAddr(r.Backend),
			hostHeader: r.HostHeader,
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
	entry := httpRouteEntry{
		pathPrefix: route.PathPrefix,
		addr:       normalizeRouteAddr(route.Backend),
		hostHeader: route.HostHeader,
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
	for _, ln := range listeners {
		ln := ln
		go s.serveHTTPRedirectListener(ln)
	}
	log.Printf("[HTTP] %d redirect listener(s) started on %s", len(listeners), addr)
	return nil
}

func (s *Server) serveHTTPRedirectListener(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.doneClosed() || errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return
		}
		go s.serveHTTPRedirectConn(conn)
	}
}

func (s *Server) serveHTTPRedirectConn(conn net.Conn) {
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

	if !ValidateHost(host) {
		_ = writeFull(conn, []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}
	for i := 0; i < len(path); i++ {
		if path[i] == '\r' || path[i] == '\n' {
			_ = writeFull(conn, []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			return
		}
	}

	if s.httpRouter != nil {
		route := s.httpRouter.match(path)
		if route != nil {
			s.proxyHTTPRoute(conn, buf, route, host, path)
			return
		}
	}

	if hasPrefix(path, "/.well-known/acme-challenge/") {
		if debugFlag.Load() {
			log.Printf("[HTTP] ACME challenge request from %s: %s%s", conn.RemoteAddr(), host, path)
		}

		if s.acme != nil && s.acme.acmeNode != "" {
			if debugFlag.Load() {
				log.Printf("[HTTP] proxying ACME challenge to node %s", s.acme.acmeNode)
			}
			route := &httpRouteEntry{
				pathPrefix: "/.well-known/acme-challenge/",
				addr:       normalizeRouteAddr(s.acme.acmeNode),
			}
			s.proxyHTTPRoute(conn, buf, route, host, path)
			return
		}

		if s.acme != nil {
			resp, ok := s.acme.HandleHTTP01(path)
			if ok {
				if debugFlag.Load() {
					log.Printf("[HTTP] ACME challenge SERVED: %s (len=%d)", path, len(resp))
				}
				_ = writeFull(conn, buildACMEResponse(resp))
				return
			}
			if debugFlag.Load() {
				log.Printf("[HTTP] ACME challenge NOT FOUND in handler: %s", path)
			}
		} else {
			if debugFlag.Load() {
				log.Printf("[HTTP] ACME challenge request but ACME not enabled: %s", path)
			}
		}

		_ = writeFull(conn, []byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
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

func (s *Server) proxyHTTPRoute(clientConn net.Conn, rawReq []byte, route *httpRouteEntry, host, path string) {
	backendConn, err := DialTCP4(route.addr, 5*time.Second)
	if err != nil {
		log.Printf("[HTTP-ROUTE] failed to connect to %s for %s: %v", route.addr, path, err)
		_ = writeFull(clientConn, []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}
	defer backendConn.Close()

	if route.hostHeader != "" {
		rawReq = rewriteHostHeader(rawReq, route.hostHeader)
	}

	backendConn.SetWriteDeadline(timeNow().Add(10 * time.Second))
	err = writeFull(backendConn, rawReq)
	if err != nil {
		log.Printf("[HTTP-ROUTE] write to %s failed: %v", route.addr, err)
		_ = writeFull(clientConn, []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}

	backendConn.SetReadDeadline(timeNow().Add(30 * time.Second))
	rbp := LargeBufPool.Get().(*[]byte)
	readBuf := (*rbp)[:cap(*rbp)]
	for {
		n, rerr := backendConn.Read(readBuf)
		if n > 0 {
			if err := writeFull(clientConn, readBuf[:n]); err != nil {
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

func rewriteHostHeader(raw []byte, newHost string) []byte {
	s := UnsafeString(raw)
	hostIdx := -1
	hostEnd := -1
	rest := s
	offset := 0
	for {
		nl := indexCRLF(rest)
		if nl < 0 || nl == 0 {
			break
		}
		line := rest[:nl]
		colon := indexByte(line, ':')
		if colon > 0 && EqualFoldASCII(line[:colon], "host") {
			hostIdx = offset + colon + 1
			hostEnd = offset + nl
			break
		}
		offset += nl + 2
		rest = rest[nl+2:]
	}
	if hostIdx < 0 {
		return raw
	}
	bp := MediumBufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	buf = append(buf, raw[:hostIdx]...)
	buf = append(buf, ' ')
	buf = append(buf, newHost...)
	buf = append(buf, raw[hostEnd:]...)
	result := make([]byte, len(buf))
	copy(result, buf)
	*bp = buf[:0]
	MediumBufPool.Put(bp)
	return result
}

func buildACMEResponse(body []byte) []byte {
	bp := SmallBufPool.Get().(*[]byte)
	buf := (*bp)[:0]

	buf = append(buf, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "...)
	buf = appendInt(buf, len(body))
	buf = append(buf, "\r\nConnection: close\r\n\r\n"...)
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
	buf = append(buf, "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"...)

	result := make([]byte, len(buf))
	copy(result, buf)
	*bp = buf[:0]
	SmallBufPool.Put(bp)
	return result
}
