package core

import (
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Recovery returns middleware that catches panics in downstream handlers
// and responds with 500 Internal Server Error instead of crashing the
// process. Always register it first in the middleware chain.
//
//	s.Router.Use(core.Recovery())
func Recovery() MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[PANIC] %s %s: %v", req.Method, req.Path, r)
					resp.Status(500).String("Internal Server Error")
				}
			}()
			next(req, resp)
		}
	}
}

// Logger returns middleware that logs every request with method, path,
// status code, and elapsed time to the standard logger.
//
//	s.Router.Use(core.Logger())
func Logger() MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			start := time.Now()
			next(req, resp)
			elapsed := time.Since(start)
			log.Printf("[%s] %s %s %d %s",
				req.Proto, req.Method, req.Path, resp.StatusCode, elapsed)
		}
	}
}

// CORSConfig controls Cross-Origin Resource Sharing headers.
//
//	cfg := core.CORSConfig{
//		AllowOrigins:     []string{"https://example.com", "https://app.example.com"},
//		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
//		AllowHeaders:     []string{"Content-Type", "Authorization"},
//		ExposeHeaders:    []string{"X-Request-ID"},
//		AllowCredentials: true,
//		MaxAge:           86400,
//	}
//
// Set AllowOrigins to []string{"*"} to allow all origins. When
// AllowCredentials is true and the origin is "*", the actual
// Origin header value is reflected back (per the CORS spec).
type CORSConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           int
}

type corsSnapshot struct {
	origins     string
	methods     string
	headers     string
	expose      string
	maxAge      string
	credentials bool
	wildcard    bool
	originMap   map[string]struct{}
}

type trustedProxyMatcher struct {
	active   bool
	trustAll bool
	nets     []*net.IPNet
	ips      []net.IP
}

func newCORSSnapshot(cfg CORSConfig) *corsSnapshot {
	snap := &corsSnapshot{
		origins:     strings.Join(cfg.AllowOrigins, ", "),
		methods:     strings.Join(cfg.AllowMethods, ", "),
		headers:     strings.Join(cfg.AllowHeaders, ", "),
		expose:      strings.Join(cfg.ExposeHeaders, ", "),
		maxAge:      string(appendUint(nil, int64(cfg.MaxAge))),
		credentials: cfg.AllowCredentials,
	}
	if len(cfg.AllowOrigins) == 0 || (len(cfg.AllowOrigins) == 1 && cfg.AllowOrigins[0] == "*") {
		snap.wildcard = true
	} else {
		snap.originMap = make(map[string]struct{}, len(cfg.AllowOrigins))
		for _, o := range cfg.AllowOrigins {
			snap.originMap[o] = struct{}{}
		}
	}
	return snap
}

// CORSEngine holds a snapshot of the CORS config and can be updated
// at runtime without restarting the server. Access to the snapshot is
// lock-free via atomic.Pointer.
type CORSEngine struct {
	snapshot atomic.Pointer[corsSnapshot]
}

// NewCORSEngine creates a CORSEngine with the given config.
func NewCORSEngine(cfg CORSConfig) *CORSEngine {
	ce := &CORSEngine{}
	ce.snapshot.Store(newCORSSnapshot(cfg))
	return ce
}

func (ce *CORSEngine) Update(cfg CORSConfig) {
	ce.snapshot.Store(newCORSSnapshot(cfg))
}

func newTrustedProxyMatcher(trustedProxies []string, trustAllWhenEmpty bool) trustedProxyMatcher {
	matcher := trustedProxyMatcher{}
	if len(trustedProxies) == 0 {
		matcher.active = trustAllWhenEmpty
		matcher.trustAll = trustAllWhenEmpty
		return matcher
	}
	matcher.active = true
	for _, p := range trustedProxies {
		if _, cidr, err := net.ParseCIDR(p); err == nil {
			matcher.nets = append(matcher.nets, cidr)
			continue
		}
		if ip := net.ParseIP(p); ip != nil {
			matcher.ips = append(matcher.ips, ip)
		}
	}
	return matcher
}

func (m trustedProxyMatcher) allows(remoteAddr string) bool {
	if !m.active {
		return false
	}
	if m.trustAll {
		return true
	}
	host := extractIP(remoteAddr)
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range m.nets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, tip := range m.ips {
		if tip.Equal(ip) {
			return true
		}
	}
	return false
}

func applyTrustedRealIP(req *Request, matcher trustedProxyMatcher) {
	if req == nil || !matcher.allows(req.RemoteAddr) {
		return
	}
	if xff := req.Header("x-forwarded-for"); xff != "" {
		ip := lastXFFEntry(xff)
		if isValidIP(ip) {
			req.RemoteAddr = ip
			return
		}
	}
	if xri := req.Header("x-real-ip"); xri != "" {
		ip := trimASCIISpace(xri)
		if isValidIP(ip) {
			req.RemoteAddr = ip
		}
	}
}

func lastXFFEntry(xff string) string {
	last := xff
	for i := len(xff) - 1; i >= 0; i-- {
		if xff[i] == ',' {
			last = xff[i+1:]
			break
		}
	}
	return trimASCIISpace(last)
}

func (ce *CORSEngine) Config() CORSConfig {
	snap := ce.snapshot.Load()
	if snap == nil {
		return CORSConfig{}
	}
	var origins []string
	if snap.wildcard {
		origins = []string{"*"}
	} else {
		origins = make([]string, 0, len(snap.originMap))
		for o := range snap.originMap {
			origins = append(origins, o)
		}
	}
	return CORSConfig{
		AllowOrigins:     origins,
		AllowCredentials: snap.credentials,
	}
}

func (ce *CORSEngine) Middleware() MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			snap := ce.snapshot.Load()
			if snap == nil {
				next(req, resp)
				return
			}
			ce.applyCORS(snap, req, resp)
			if req.Method == "OPTIONS" {
				resp.Status(204)
				return
			}
			next(req, resp)
		}
	}
}

func (ce *CORSEngine) applyCORS(snap *corsSnapshot, req *Request, resp *Response) {
	origin := req.Header("origin")
	if snap.wildcard {
		if snap.credentials && origin != "" {
			resp.SetHeader("access-control-allow-origin", origin)
		} else {
			resp.SetHeaderUnsafe("access-control-allow-origin", "*")
		}
	} else if origin != "" {
		if _, ok := snap.originMap[origin]; ok {
			resp.SetHeaderUnsafe("access-control-allow-origin", origin)
			resp.SetHeaderUnsafe("vary", "Origin")
		}
	}
	if snap.methods != "" {
		resp.SetHeaderUnsafe("access-control-allow-methods", snap.methods)
	}
	if snap.headers != "" {
		resp.SetHeaderUnsafe("access-control-allow-headers", snap.headers)
	}
	if snap.expose != "" {
		resp.SetHeaderUnsafe("access-control-expose-headers", snap.expose)
	}
	if snap.credentials {
		resp.SetHeaderUnsafe("access-control-allow-credentials", "true")
	}
	if snap.maxAge != "0" && snap.maxAge != "" {
		resp.SetHeaderUnsafe("access-control-max-age", snap.maxAge)
	}
}

// CORS returns a one-shot middleware from a static CORSConfig. For
// runtime-updatable CORS use NewCORSEngine + CORSEngine.Middleware.
//
//	s.Router.Use(core.CORS(core.CORSConfig{
//		AllowOrigins: []string{"*"},
//		AllowMethods: []string{"GET", "POST"},
//	}))
func CORS(config CORSConfig) MiddlewareFunc {
	ce := NewCORSEngine(config)
	return ce.Middleware()
}

var requestIDCounter atomic.Uint64

// RequestID returns middleware that assigns a monotonically increasing
// integer ID to each request via the X-Request-ID response header.
//
//	s.Router.Use(core.RequestID())
func RequestID() MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			id := requestIDCounter.Add(1)
			var buf [20]byte
			s := appendUint(buf[:0], int64(id))
			resp.SetHeaderUnsafe("x-request-id", string(s))
			next(req, resp)
		}
	}
}

// SecurityHeadersConfig controls which security-related headers are
// injected into every response.
//
//	cfg := core.SecurityHeadersConfig{
//		ContentTypeNosniff: true,
//		XFrameOptions:      "DENY",
//		XSSProtection:      true,
//		HSTSMaxAge:         63072000,
//		HSTSSubdomains:     true,
//		HSTSPreload:        true,
//		ReferrerPolicy:     "strict-origin-when-cross-origin",
//	}
type SecurityHeadersConfig struct {
	ContentTypeNosniff bool
	XFrameOptions      string
	XSSProtection      bool
	HSTSMaxAge         int
	HSTSSubdomains     bool
	HSTSPreload        bool
	ReferrerPolicy     string
}

// DefaultSecurityHeaders returns a SecurityHeadersConfig with all
// protections enabled: nosniff, DENY framing, XSS filter, 2-year HSTS
// with includeSubDomains and preload, and strict-origin-when-cross-origin
// referrer policy.
func DefaultSecurityHeaders() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		ContentTypeNosniff: true,
		XFrameOptions:      "DENY",
		XSSProtection:      true,
		HSTSMaxAge:         63072000,
		HSTSSubdomains:     true,
		HSTSPreload:        true,
		ReferrerPolicy:     "strict-origin-when-cross-origin",
	}
}

// SecurityHeaders returns middleware that injects the configured
// security headers into every response.
//
//	s.Router.Use(core.SecurityHeaders(core.DefaultSecurityHeaders()))
func SecurityHeaders(cfg SecurityHeadersConfig) MiddlewareFunc {
	var hsts string
	if cfg.HSTSMaxAge > 0 {
		var b [64]byte
		buf := b[:0]
		buf = append(buf, "max-age="...)
		buf = appendUint(buf, int64(cfg.HSTSMaxAge))
		if cfg.HSTSSubdomains {
			buf = append(buf, "; includeSubDomains"...)
		}
		if cfg.HSTSPreload {
			buf = append(buf, "; preload"...)
		}
		hsts = string(buf)
	}

	var staticHeaders [][2]string
	if cfg.ContentTypeNosniff {
		staticHeaders = append(staticHeaders, [2]string{"x-content-type-options", "nosniff"})
	}
	if cfg.XFrameOptions != "" {
		staticHeaders = append(staticHeaders, [2]string{"x-frame-options", cfg.XFrameOptions})
	}
	if cfg.XSSProtection {
		staticHeaders = append(staticHeaders, [2]string{"x-xss-protection", "1; mode=block"})
	}
	if hsts != "" {
		staticHeaders = append(staticHeaders, [2]string{"strict-transport-security", hsts})
	}
	if cfg.ReferrerPolicy != "" {
		staticHeaders = append(staticHeaders, [2]string{"referrer-policy", cfg.ReferrerPolicy})
	}

	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			next(req, resp)
			resp.Headers = append(resp.Headers, staticHeaders...)
		}
	}
}

// CompressConfig controls response compression.
//
//	cfg := core.CompressConfig{
//		Level:   6,     // gzip/deflate level (1-9)
//		MinSize: 512,   // skip compression below this body size
//	}
type CompressConfig struct {
	Level   int
	MinSize int
}

var gzipWriterPool = [10]sync.Pool{}
var deflateWriterPool = [10]sync.Pool{}

func init() {
	for i := 1; i <= 9; i++ {
		level := i
		gzipWriterPool[i] = sync.Pool{
			New: func() any {
				w, _ := gzip.NewWriterLevel(io.Discard, level)
				return w
			},
		}
		deflateWriterPool[i] = sync.Pool{
			New: func() any {
				w, _ := flate.NewWriter(io.Discard, level)
				return w
			},
		}
	}
}

// Compress returns middleware that gzip- or deflate-compresses response
// bodies based on the client's Accept-Encoding header. Responses below
// MinSize bytes or already streamed are left untouched.
//
//	s.Router.Use(core.Compress(core.CompressConfig{Level: 6, MinSize: 512}))
func Compress(cfg CompressConfig) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			next(req, resp)
			applyConfiguredCompression(req, resp, cfg)
		}
	}
}

func applyConfiguredCompression(req *Request, resp *Response, cfg CompressConfig) {
	level := cfg.Level
	if level < 1 || level > 9 {
		level = 6
	}
	minSize := cfg.MinSize
	if minSize <= 0 {
		minSize = 256
	}

	if resp == nil || req == nil || resp.IsStreamed() || resp.transmittedBodyLen() < minSize {
		return
	}
	if responseHasHeader(resp.Headers, "content-encoding") {
		return
	}

	enc := negotiateEncoding(req.Header("accept-encoding"))
	if enc == encodingNone {
		return
	}

	body := resp.transmittedBodyBytes()
	bp := LargeBufPool.Get().(*[]byte)
	buf := (*bp)[:0]

	switch enc {
	case encodingGzip:
		gw := gzipWriterPool[level].Get().(*gzip.Writer)
		w := newBytesWriter(&buf)
		gw.Reset(w)
		_, _ = gw.Write(body)
		_ = gw.Close()
		gzipWriterPool[level].Put(gw)
		w.buf = nil
		bytesWriterPool.Put(w)
		resp.SetHeaderUnsafe("Content-Encoding", "gzip")
	case encodingDeflate:
		fw := deflateWriterPool[level].Get().(*flate.Writer)
		w := newBytesWriter(&buf)
		fw.Reset(w)
		_, _ = fw.Write(body)
		_ = fw.Close()
		deflateWriterPool[level].Put(fw)
		w.buf = nil
		bytesWriterPool.Put(w)
		resp.SetHeaderUnsafe("Content-Encoding", "deflate")
	}

	if len(buf) > 0 && len(buf) < len(body) {
		resp.SetBody(buf)
		resp.SetHeaderUnsafe("Vary", "Accept-Encoding")
	}

	*bp = buf[:0]
	LargeBufPool.Put(bp)
}

func responseHasHeader(headers [][2]string, name string) bool {
	switch len(headers) {
	case 0:
		return false
	case 1:
		return EqualFoldASCII(headers[0][0], name)
	case 2:
		return EqualFoldASCII(headers[0][0], name) || EqualFoldASCII(headers[1][0], name)
	case 3:
		return EqualFoldASCII(headers[0][0], name) || EqualFoldASCII(headers[1][0], name) || EqualFoldASCII(headers[2][0], name)
	default:
		for i := range headers {
			if EqualFoldASCII(headers[i][0], name) {
				return true
			}
		}
		return false
	}
}

type encodingType uint8

const (
	encodingNone    encodingType = 0
	encodingGzip    encodingType = 1
	encodingDeflate encodingType = 2
)

func negotiateEncoding(accept string) encodingType {
	if accept == "" {
		return encodingNone
	}
	var bestGzip, bestDeflate int8
	bestGzip = -1
	bestDeflate = -1
	for i := 0; i < len(accept); {
		for i < len(accept) && (accept[i] == ' ' || accept[i] == ',') {
			i++
		}
		tokenStart := i
		for i < len(accept) && accept[i] != ',' && accept[i] != ';' {
			i++
		}
		tokenEnd := i
		for tokenEnd > tokenStart && accept[tokenEnd-1] == ' ' {
			tokenEnd--
		}
		token := accept[tokenStart:tokenEnd]
		q := int8(1)
		if i < len(accept) && accept[i] == ';' {
			i++
			for i < len(accept) && accept[i] == ' ' {
				i++
			}
			if i+2 <= len(accept) && (accept[i] == 'q' || accept[i] == 'Q') && accept[i+1] == '=' {
				i += 2
				if i < len(accept) && accept[i] == '0' {
					isZero := true
					if i+1 < len(accept) && accept[i+1] != ',' && accept[i+1] != ' ' && accept[i+1] != ';' {
						isZero = false
					}
					if isZero {
						q = 0
					}
				}
			}
			for i < len(accept) && accept[i] != ',' {
				i++
			}
		}
		switch {
		case len(token) == 4 && (token[0] == 'g' || token[0] == 'G') &&
			(token[1] == 'z' || token[1] == 'Z') &&
			(token[2] == 'i' || token[2] == 'I') &&
			(token[3] == 'p' || token[3] == 'P'):
			bestGzip = q
		case len(token) == 7 && (token[0] == 'd' || token[0] == 'D') &&
			EqualFoldASCII(token, "deflate"):
			bestDeflate = q
		}
	}
	if bestGzip > 0 {
		return encodingGzip
	}
	if bestDeflate > 0 {
		return encodingDeflate
	}
	return encodingNone
}

var bytesWriterPool = sync.Pool{
	New: func() any {
		return &bytesWriter{}
	},
}

type bytesWriter struct {
	buf *[]byte
}

func newBytesWriter(buf *[]byte) *bytesWriter {
	w := bytesWriterPool.Get().(*bytesWriter)
	w.buf = buf
	return w
}

func (w *bytesWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}

// Timeout returns middleware that aborts the handler if it takes longer
// than d. The client receives a 504 Gateway Timeout.
//
//	s.Router.Use(core.Timeout(10 * time.Second))
func Timeout(d time.Duration) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			done := make(chan struct{}, 1)
			tmpReq := *req
			tmpReq.Params = req.Params
			tmpReq.ParamCount = req.ParamCount
			if len(req.Headers) > 0 {
				tmpReq.Headers = append(make([][2]string, 0, len(req.Headers)), req.Headers...)
			} else {
				tmpReq.Headers = nil
			}
			if len(req.Body) > 0 {
				tmpReq.Body = append([]byte(nil), req.Body...)
			} else {
				tmpReq.Body = nil
			}
			// The handler runs in a detached goroutine that can outlive the
			// timeout; once it does, req may be Reset and reused for the next
			// request on the connection. tmpReq := *req shallow-copies the
			// store/queryCache/formCache map headers, so the still-running
			// handler and the recycled req would race on the same maps
			// (concurrent map write -> panic). Give tmpReq its own maps:
			// store may carry context from upstream middleware so copy it;
			// the query/form caches are pure derivations of the copied
			// Query/Body and are reparsed lazily, so nil suffices.
			if req.store != nil {
				storeCopy := make(map[string]any, len(req.store))
				for k, v := range req.store {
					storeCopy[k] = v
				}
				tmpReq.store = storeCopy
			} else {
				tmpReq.store = nil
			}
			tmpReq.queryCache = nil
			tmpReq.formCache = nil
			tmpReq.StreamWriter = nil
			tmpReq.conn = nil
			tmpReq.tlsReader = nil
			tmpReq.tlsWriter = nil
			tmpReq.hdrBuf = nil
			tmpReq.attachConn = nil
			tmpResp := ResponsePool.Get().(*Response)
			tmpResp.Reset()
			tmpResp.lazyReq = &tmpReq

			var timedOut atomic.Bool

			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[PANIC] timeout handler: %v", r)
					}
					done <- struct{}{}
				}()
				next(&tmpReq, tmpResp)
			}()
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-done:
				if !timedOut.Load() {
					resp.StatusCode = tmpResp.StatusCode
					resp.ContentType = tmpResp.ContentType
					resp.SetBody(tmpResp.GetBody())
					for i := range tmpResp.Headers {
						resp.SetHeader(tmpResp.Headers[i][0], tmpResp.Headers[i][1])
					}
					if tmpResp.IsStreamed() {
						resp.SetStreamer(tmpResp.Streamer())
					}
					tmpResp.Reset()
					ResponsePool.Put(tmpResp)
				}
			case <-timer.C:
				timedOut.Store(true)
				go func() {
					<-done
					tmpResp.Reset()
					ResponsePool.Put(tmpResp)
				}()
				resp.Status(504).String("Gateway Timeout")
			}
		}
	}
}

// BodyLimit returns middleware that rejects bodies larger than maxBytes
// with 413 Payload Too Large. It checks Content-Length first, then the
// actual body length.
//
//	s.Router.Use(core.BodyLimit(10 << 20)) // 10 MiB
func BodyLimit(maxBytes int64) MiddlewareFunc {
	maxStr := string(appendUint(nil, maxBytes))
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			clStr := req.Header("content-length")
			if clStr != "" {
				cl, ok := parseUint(clStr)
				if ok && int64(cl) > maxBytes {
					resp.Status(413).String("Payload Too Large")
					return
				}
			}
			if int64(len(req.Body)) > maxBytes {
				resp.Status(413).String("Payload Too Large")
				_ = maxStr
				return
			}
			next(req, resp)
		}
	}
}

// RealIP returns middleware that overwrites req.RemoteAddr with the
// value from X-Forwarded-For or X-Real-IP headers. When trustedProxies
// is non-empty, the header is only trusted if the direct client IP
// matches one of the listed CIDRs or IPs. When trustedProxies is empty,
// the header is always trusted — only use this behind a known proxy.
//
//	s.Router.Use(core.RealIP("10.0.0.0/8", "172.16.0.0/12"))
func RealIP(trustedProxies ...string) MiddlewareFunc {
	var nets []*net.IPNet
	var ips []net.IP
	for _, p := range trustedProxies {
		if _, cidr, err := net.ParseCIDR(p); err == nil {
			nets = append(nets, cidr)
		} else if ip := net.ParseIP(p); ip != nil {
			ips = append(ips, ip)
		}
	}
	hasTrust := len(nets) > 0 || len(ips) > 0

	isTrusted := func(remoteAddr string) bool {
		if !hasTrust {
			return true
		}
		host := extractIP(remoteAddr)
		ip := net.ParseIP(host)
		if ip == nil {
			return false
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		for _, tip := range ips {
			if tip.Equal(ip) {
				return true
			}
		}
		return false
	}

	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			if isTrusted(req.RemoteAddr) {
				if xff := req.Header("x-forwarded-for"); xff != "" {
					ip := lastXFFEntry(xff)
					if isValidIP(ip) {
						req.RemoteAddr = ip
					}
				} else if xri := req.Header("x-real-ip"); xri != "" {
					ip := trimASCIISpace(xri)
					if isValidIP(ip) {
						req.RemoteAddr = ip
					}
				}
			}
			next(req, resp)
		}
	}
}

// AllowMethods returns middleware that rejects requests whose method
// is not in the given list with 405 Method Not Allowed.
//
//	s.Router.Use(core.AllowMethods("GET", "POST"))
func AllowMethods(methods ...string) MiddlewareFunc {
	allowed := make(map[string]struct{}, len(methods))
	for _, m := range methods {
		allowed[m] = struct{}{}
	}
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			if _, ok := allowed[req.Method]; !ok {
				resp.Status(405).String("Method Not Allowed")
				return
			}
			next(req, resp)
		}
	}
}

// BasicAuthConfig holds username/password pairs and the HTTP Basic
// Auth realm string.
//
//	cfg := core.BasicAuthConfig{
//		Users: map[string]string{"admin": "secret"},
//		Realm: "Admin Panel",
//	}
type BasicAuthConfig struct {
	Users map[string]string
	Realm string
}

// BasicAuth returns middleware that requires HTTP Basic credentials.
// Passwords are compared in constant time. If the realm is empty it
// defaults to "Restricted".
//
//	s.Router.Use(core.BasicAuth(core.BasicAuthConfig{
//		Users: map[string]string{"admin": "secret"},
//		Realm: "Admin Panel",
//	}))
func BasicAuth(cfg BasicAuthConfig) MiddlewareFunc {
	realm := cfg.Realm
	if realm == "" {
		realm = "Restricted"
	}
	realm = sanitizeAuthRealm(realm)
	challenge := "Basic realm=\"" + realm + "\""

	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			auth := req.Header("authorization")
			if auth == "" || len(auth) < 7 || !EqualFoldASCII(auth[:6], "basic ") {
				resp.Status(401).
					SetHeader("WWW-Authenticate", challenge).
					String("Unauthorized")
				return
			}
			decoded, err := decodeBase64(auth[6:])
			if err != nil || len(decoded) == 0 {
				resp.Status(401).
					SetHeader("WWW-Authenticate", challenge).
					String("Unauthorized")
				return
			}
			colon := -1
			for i := 0; i < len(decoded); i++ {
				if decoded[i] == ':' {
					colon = i
					break
				}
			}
			if colon < 0 {
				resp.Status(401).
					SetHeader("WWW-Authenticate", challenge).
					String("Unauthorized")
				return
			}
			user := decoded[:colon]
			pass := decoded[colon+1:]
			expectedPass, ok := cfg.Users[user]
			if !ok {
				expectedPass = pass
			}
			expectedHash := sha256.Sum256([]byte(expectedPass))
			passHash := sha256.Sum256([]byte(pass))
			if !ok || subtle.ConstantTimeCompare(expectedHash[:], passHash[:]) != 1 {
				resp.Status(401).
					SetHeader("WWW-Authenticate", challenge).
					String("Unauthorized")
				return
			}
			next(req, resp)
		}
	}
}

func sanitizeAuthRealm(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\\' || c == '\r' || c == '\n' || c < 0x20 {
			continue
		}
		b = append(b, c)
	}
	return string(b)
}

// If returns middleware that conditionally applies inner only when
// predicate returns true for the current request.
//
//	s.Router.Use(core.If(
//		func(req *core.Request) bool { return req.Path != "/health" },
//		core.Logger(),
//	))
func If(predicate func(*Request) bool, inner MiddlewareFunc) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		wrapped := inner(next)
		return func(req *Request, resp *Response) {
			if predicate(req) {
				wrapped(req, resp)
			} else {
				next(req, resp)
			}
		}
	}
}

// Header returns middleware that sets a fixed response header on every
// request.
//
//	s.Router.Use(core.Header("X-Powered-By", "ALOS"))
func Header(name, value string) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			next(req, resp)
			resp.SetHeader(name, value)
		}
	}
}

func decodeBase64(s string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return "", err
		}
	}
	return string(data), nil
}
