//go:build linux && amd64

package core

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Recovery returns middleware that recovers from panics in downstream handlers and responds with 500 Internal Server Error. Register it first in the chain.
func Recovery() MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			defer func() {
				if r := recover(); r != nil {
					req.server.reportPanic(req, r)
					resp.Status(500).String("Internal Server Error")
				}
			}()
			next(req, resp)
		}
	}
}

// Logger returns middleware that logs each request's protocol, method, path, status code, and elapsed time to the standard logger.
func Logger() MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			start := time.Now()
			next(req, resp)
			elapsed := time.Since(start)
			req.server.logger().Info("request", "proto", req.Proto, "method", req.Method, "path", req.Path, "status", resp.StatusCode, "elapsed", elapsed)
		}
	}
}

// CORSConfig controls Cross-Origin Resource Sharing response headers.
//
// AllowOrigins lists permitted origins; an empty slice or []string{"*"} allows all origins.
//
//	Example: AllowOrigins: []string{"https://example.com"} allows a single origin.
//	Example: AllowOrigins: []string{"*"} allows all origins (Access-Control-Allow-Origin: *).
//	Example: AllowOrigins: nil also allows all origins.
//
// AllowMethods lists methods sent in Access-Control-Allow-Methods; omitted when empty.
//
//	Example: AllowMethods: []string{"GET", "POST", "OPTIONS"} advertises those methods.
//
// AllowHeaders lists request headers sent in Access-Control-Allow-Headers; omitted when empty.
//
//	Example: AllowHeaders: []string{"Content-Type", "Authorization"} permits those request headers.
//
// ExposeHeaders lists response headers sent in Access-Control-Expose-Headers; omitted when empty.
//
//	Example: ExposeHeaders: []string{"X-Request-ID"} exposes that header to the browser.
//
// AllowCredentials sets Access-Control-Allow-Credentials; it is not emitted alongside a wildcard origin.
//
//	Example: AllowCredentials: true allows cookies and credentials on matched non-wildcard origins.
//
// MaxAge is the preflight cache lifetime in seconds for Access-Control-Max-Age; omitted when 0.
//
//	Example: MaxAge: 86400 caches preflight results for one day.
//	Example: MaxAge: 0 omits the Access-Control-Max-Age header.
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

// CORSEngine holds a CORS configuration snapshot that can be replaced at runtime without restarting the server. Reads of the snapshot are lock-free.
type CORSEngine struct {
	snapshot atomic.Pointer[corsSnapshot]
}

// NewCORSEngine returns a CORSEngine initialized with cfg.
//
// Example: ce := NewCORSEngine(CORSConfig{AllowOrigins: []string{"*"}})
// Example: ce := NewCORSEngine(CORSConfig{AllowOrigins: []string{"https://app.example.com"}, AllowCredentials: true})
func NewCORSEngine(cfg CORSConfig) *CORSEngine {
	ce := &CORSEngine{}
	ce.snapshot.Store(newCORSSnapshot(cfg))
	return ce
}

// Update atomically replaces the engine's configuration with cfg.
//
// Example: ce.Update(CORSConfig{AllowOrigins: []string{"https://new.example.com"}})
// Example: ce.Update(CORSConfig{AllowOrigins: []string{"*"}})
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
		ip := net.ParseIP(p)
		if ip == nil {
			panic(fmt.Sprintf("core: invalid trusted proxy %q", p))
		}
		matcher.ips = append(matcher.ips, ip)
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
	req.peerAddr = req.RemoteAddr
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

// Config returns a CORSConfig reflecting the engine's current origins and credentials setting.
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

// Middleware returns a MiddlewareFunc that applies the engine's current CORS headers and answers preflight OPTIONS requests with 204.
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
	if snap.wildcard {
		resp.SetHeaderUnsafe("access-control-allow-origin", "*")
	} else {
		addVaryField(resp, "Origin")
		if origin := req.Header("origin"); origin != "" {
			if _, ok := snap.originMap[origin]; ok {
				resp.SetHeaderUnsafe("access-control-allow-origin", cookieStripCTL(origin))
			}
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
	if snap.credentials && !snap.wildcard {
		resp.SetHeaderUnsafe("access-control-allow-credentials", "true")
	}
	if snap.maxAge != "0" && snap.maxAge != "" {
		resp.SetHeaderUnsafe("access-control-max-age", snap.maxAge)
	}
}

// CORS returns middleware built from a static CORSConfig. For runtime-updatable CORS, use NewCORSEngine with CORSEngine.Middleware.
//
// Example: app.Use(CORS(CORSConfig{AllowOrigins: []string{"*"}}))
// Example: app.Use(CORS(CORSConfig{AllowOrigins: []string{"https://example.com"}, AllowMethods: []string{"GET", "POST"}}))
// Example: app.Use(CORS(CORSConfig{AllowOrigins: []string{"https://app.example.com"}, AllowCredentials: true}))
func CORS(config CORSConfig) MiddlewareFunc {
	ce := NewCORSEngine(config)
	return ce.Middleware()
}

var requestIDCounter atomic.Uint64

// RequestID returns middleware that assigns each request a monotonically increasing id via the X-Request-ID response header.
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

// SecurityHeadersConfig selects which security-related response headers are injected into every response.
//
// ContentTypeNosniff emits "X-Content-Type-Options: nosniff" when true.
//
//	Example: ContentTypeNosniff: true prevents MIME type sniffing.
//
// XFrameOptions sets the X-Frame-Options header; omitted when empty.
//
//	Example: XFrameOptions: "DENY" forbids framing entirely.
//	Example: XFrameOptions: "SAMEORIGIN" allows framing by same-origin pages.
//
// XSSProtection emits "X-XSS-Protection: 1; mode=block" when true.
//
//	Example: XSSProtection: true enables the legacy XSS filter.
//
// HSTSMaxAge sets the Strict-Transport-Security max-age in seconds; the header is omitted when <= 0.
//
//	Example: HSTSMaxAge: 63072000 enables HSTS for two years.
//	Example: HSTSMaxAge: 0 omits the Strict-Transport-Security header.
//
// HSTSSubdomains appends "; includeSubDomains" to the HSTS header when true (requires HSTSMaxAge > 0).
//
//	Example: HSTSSubdomains: true applies HSTS to all subdomains.
//
// HSTSPreload appends "; preload" to the HSTS header when true (requires HSTSMaxAge > 0).
//
//	Example: HSTSPreload: true marks the host eligible for browser preload lists.
//
// ReferrerPolicy sets the Referrer-Policy header; omitted when empty.
//
//	Example: ReferrerPolicy: "strict-origin-when-cross-origin" sends the origin on cross-origin requests.
//	Example: ReferrerPolicy: "no-referrer" never sends the Referer header.
type SecurityHeadersConfig struct {
	ContentTypeNosniff        bool
	XFrameOptions             string
	XSSProtection             bool
	HSTSMaxAge                int
	HSTSSubdomains            bool
	HSTSPreload               bool
	ReferrerPolicy            string
	ContentSecurityPolicy     string
	PermissionsPolicy         string
	CrossOriginOpenerPolicy   string
	CrossOriginResourcePolicy string
	CrossOriginEmbedderPolicy string
}

// DefaultSecurityHeaders returns a SecurityHeadersConfig with nosniff, X-Frame-Options DENY, the XSS filter, two-year HSTS with includeSubDomains and preload, a strict-origin-when-cross-origin referrer policy, and Cross-Origin-Opener-Policy same-origin.
func DefaultSecurityHeaders() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		ContentTypeNosniff:      true,
		XFrameOptions:           "DENY",
		XSSProtection:           true,
		HSTSMaxAge:              63072000,
		HSTSSubdomains:          true,
		HSTSPreload:             true,
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		CrossOriginOpenerPolicy: "same-origin",
	}
}

// SecurityHeaders returns middleware that appends the configured security headers to every response. See SecurityHeadersConfig for per-field behavior.
//
// Example: app.Use(SecurityHeaders(DefaultSecurityHeaders()))
// Example: app.Use(SecurityHeaders(SecurityHeadersConfig{ContentTypeNosniff: true, XFrameOptions: "DENY"}))
// Example: app.Use(SecurityHeaders(SecurityHeadersConfig{HSTSMaxAge: 31536000, HSTSSubdomains: true}))
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
	if cfg.XSSProtection {
		staticHeaders = append(staticHeaders, [2]string{"x-xss-protection", "1; mode=block"})
	}
	if hsts != "" {
		staticHeaders = append(staticHeaders, [2]string{"strict-transport-security", hsts})
	}
	for _, h := range [...][2]string{
		{"x-frame-options", cfg.XFrameOptions},
		{"referrer-policy", cfg.ReferrerPolicy},
		{"content-security-policy", cfg.ContentSecurityPolicy},
		{"permissions-policy", cfg.PermissionsPolicy},
		{"cross-origin-opener-policy", cfg.CrossOriginOpenerPolicy},
		{"cross-origin-resource-policy", cfg.CrossOriginResourcePolicy},
		{"cross-origin-embedder-policy", cfg.CrossOriginEmbedderPolicy},
	} {
		if value := sanitizeHeaderValue(h[1]); value != "" {
			staticHeaders = append(staticHeaders, [2]string{h[0], value})
		}
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
// Level is the gzip/deflate compression level from 1 (fastest) to 9 (smallest); values outside 1–9 fall back to 2.
//
//	Example: Level: 1 favors speed over ratio.
//	Example: Level: 9 favors ratio over speed.
//	Example: Level: 0 is out of range and uses the default 2.
//
// MinSize is the minimum body size in bytes to compress; smaller bodies are sent uncompressed. Values <= 0 fall back to 256.
//
//	Example: MinSize: 512 skips compression for bodies under 512 bytes.
//	Example: MinSize: 0 uses the default of 256.
type CompressConfig struct {
	Level       int
	MinSize     int
	BrotliLevel int
}

const (
	defaultCompressLevel   = 2
	defaultCompressMinSize = 256
)

// Compress returns middleware that brotli-, gzip- or deflate-compresses response bodies per the request's Accept-Encoding header, leaving streamed responses and bodies below cfg.MinSize untouched. See CompressConfig for defaults.
//
// Example: app.Use(Compress(CompressConfig{}))
// Example: app.Use(Compress(CompressConfig{Level: 6, MinSize: 512}))
// Example: app.Use(Compress(CompressConfig{Level: 9, MinSize: 1024}))
func Compress(cfg CompressConfig) MiddlewareFunc {
	cfg = normalizeCompressConfig(cfg)
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			next(req, resp)
			applyNormalizedCompression(req, resp, &cfg)
		}
	}
}

func normalizeCompressConfig(cfg CompressConfig) CompressConfig {
	if cfg.Level < 1 || cfg.Level > 9 {
		cfg.Level = defaultCompressLevel
	}
	if cfg.MinSize <= 0 {
		cfg.MinSize = defaultCompressMinSize
	}
	cfg.BrotliLevel = normalizeBrotliLevel(cfg.BrotliLevel)
	return cfg
}

func applyConfiguredCompression(req *Request, resp *Response, cfg CompressConfig) {
	cfg = normalizeCompressConfig(cfg)
	applyNormalizedCompression(req, resp, &cfg)
}

func applyNormalizedCompression(req *Request, resp *Response, cfg *CompressConfig) {
	level := cfg.Level
	minSize := cfg.MinSize

	if resp == nil || req == nil || resp.IsStreamed() || resp.fileBody || resp.StatusCode == http.StatusPartialContent {
		return
	}
	body := resp.transmittedBodyBytes()
	if req.Method == "HEAD" {
		body = resp.bodyBytesUnsafe()
	}
	if len(body) < minSize {
		return
	}
	if responseHasHeader(resp.Headers, "content-encoding") || responseHasHeader(resp.Headers, "content-range") {
		return
	}

	enc := negotiateEncoding(req.Header("accept-encoding"), offerAllEncodings)
	if enc == encodingNone {
		addVaryAcceptEncoding(resp)
		return
	}
	if enc == encodingBrotli {
		level = cfg.BrotliLevel
	}

	bp := LargeBufPool.Get().(*[]byte)
	buf := appendCompressed((*bp)[:0], body, enc, level)
	if len(buf) > 0 && len(buf) < len(body) {
		resp.SetBody(buf)
		resp.SetHeaderUnsafe("Content-Encoding", contentEncodingNames[enc])
		weakenStrongETag(resp.Headers)
	}
	addVaryAcceptEncoding(resp)

	*bp = buf
	putBoxedBufCapped(&LargeBufPool, bp, largeBufPoolMaxCap)
}

func weakenStrongETag(headers [][2]string) {
	for i := range headers {
		if EqualFoldASCII(headers[i][0], "etag") && strings.HasPrefix(headers[i][1], `"`) {
			headers[i][1] = "W/" + headers[i][1]
		}
	}
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

type bytesWriter struct {
	buf []byte
}

func (w *bytesWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	return len(p), nil
}

// Timeout returns middleware that runs the handler with a deadline of d and responds 504 Gateway Timeout if it has not completed in time.
//
// Example: app.Use(Timeout(5 * time.Second))
// Example: app.Use(Timeout(100 * time.Millisecond))
// Example: app.Use(Timeout(time.Minute))
func cloneDetachedStrings(r *Request) {
	r.Method = strings.Clone(r.Method)
	r.Path = strings.Clone(r.Path)
	r.RawPath = strings.Clone(r.RawPath)
	r.Query = strings.Clone(r.Query)
	r.Proto = strings.Clone(r.Proto)
	r.Host = strings.Clone(r.Host)
	r.RemoteAddr = strings.Clone(r.RemoteAddr)
	r.cachedCL = strings.Clone(r.cachedCL)
	r.cachedConn = strings.Clone(r.cachedConn)
	r.cachedTE = strings.Clone(r.cachedTE)
	r.cachedHost = strings.Clone(r.cachedHost)
	r.cachedAE = strings.Clone(r.cachedAE)
	r.cachedOrigin = strings.Clone(r.cachedOrigin)
	r.cachedXFF = strings.Clone(r.cachedXFF)
	r.cachedXRI = strings.Clone(r.cachedXRI)
	r.cachedAuth = strings.Clone(r.cachedAuth)
	r.cachedUpgrade = strings.Clone(r.cachedUpgrade)
	r.cachedWSKey = strings.Clone(r.cachedWSKey)
	r.cachedWSVer = strings.Clone(r.cachedWSVer)
	for i := range r.Headers {
		r.Headers[i][0] = strings.Clone(r.Headers[i][0])
		r.Headers[i][1] = strings.Clone(r.Headers[i][1])
	}
	for i := 0; i < r.ParamCount && i < len(r.Params); i++ {
		r.Params[i].Key = strings.Clone(r.Params[i].Key)
		r.Params[i].Value = strings.Clone(r.Params[i].Value)
	}
}

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
			cloneDetachedStrings(&tmpReq)
			if len(req.store) > 0 {
				clonedStore := make(map[string]any, len(req.store))
				for k, v := range req.store {
					clonedStore[k] = v
				}
				tmpReq.store = clonedStore
			} else {
				tmpReq.store = nil
			}
			tmpReq.StreamWriter = nil
			tmpReq.swFactory = nil
			tmpReq.h2Stream = nil
			tmpReq.h2Tunnel = nil
			tmpReq.conn = nil
			tmpReq.tlsReader = nil
			tmpReq.tlsWriter = nil
			tmpReq.hdrBuf = nil
			tmpReq.attachConn = nil
			tmpReq.detachLazyCaches()
			ctx, cancel := context.WithTimeout(req.Context(), d)
			defer cancel()
			tmpReq.ctx = ctx
			tmpResp := ResponsePool.Get().(*Response)
			tmpResp.Reset()
			tmpResp.lazyReq = &tmpReq

			var timedOut atomic.Bool

			go func() {
				defer func() {
					if r := recover(); r != nil {
						tmpReq.server.reportPanic(&tmpReq, r)
					}
					done <- struct{}{}
				}()
				next(&tmpReq, tmpResp)
			}()
			select {
			case <-done:
				if !timedOut.Load() {
					resp.StatusCode = tmpResp.StatusCode
					resp.ContentType = tmpResp.ContentType
					resp.SetBody(tmpResp.GetBody())
					for i := range tmpResp.Headers {
						resp.SetHeader(tmpResp.Headers[i][0], tmpResp.Headers[i][1])
					}
					tmpResp.Reset()
					releaseResponseToPool(tmpResp)
				}
			case <-ctx.Done():
				timedOut.Store(true)
				go func() {
					<-done
					tmpResp.Reset()
					releaseResponseToPool(tmpResp)
				}()
				resp.Status(504).String("Gateway Timeout")
			}
		}
	}
}

// BodyLimit returns middleware that rejects requests whose body exceeds maxBytes with 413 Payload Too Large, checking Content-Length first and then the actual body length.
//
// Example: app.Use(BodyLimit(1 << 20))
// Example: app.Use(BodyLimit(10 << 20))
// Example: app.Use(BodyLimit(512 * 1024))
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

// RealIP returns middleware that overwrites req.RemoteAddr from the X-Forwarded-For or X-Real-IP header. When trustedProxies are given, the header is honored only if the direct peer matches one of the listed IPs or CIDRs; when none are given, the header is always trusted, so use that form only behind a trusted proxy.
//
// Example: app.Use(RealIP())
// Example: app.Use(RealIP("10.0.0.0/8"))
// Example: app.Use(RealIP("172.16.0.0/12", "192.168.1.1"))
func RealIP(trustedProxies ...string) MiddlewareFunc {
	trusted := newTrustedProxyMatcher(trustedProxies, true)

	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			if trusted.allows(req.RemoteAddr) {
				if req.peerAddr == "" {
					req.peerAddr = req.RemoteAddr
				}
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

// AllowMethods returns middleware that responds 405 Method Not Allowed when the request method is not in methods.
//
// Example: app.Use(AllowMethods("GET"))
// Example: app.Use(AllowMethods("GET", "POST", "OPTIONS"))
// Example: app.Use(AllowMethods("GET", "HEAD", "PUT", "DELETE"))
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

// BasicAuthConfig configures the BasicAuth middleware.
//
// Users maps usernames to passwords; passwords are compared in constant time.
//
//	Example: Users: map[string]string{"admin": "secret"} accepts admin/secret.
//	Example: Users: map[string]string{"alice": "pw1", "bob": "pw2"} accepts multiple users.
//
// Realm is the HTTP Basic authentication realm; defaults to "Restricted" when empty.
//
//	Example: Realm: "Admin Panel" shows that realm in the auth prompt.
//	Example: Realm: "" uses the default "Restricted".
type BasicAuthConfig struct {
	Users map[string]string
	Realm string
}

// BasicAuth returns middleware that requires HTTP Basic credentials, comparing passwords in constant time and challenging unauthenticated requests with 401 and a WWW-Authenticate header. See BasicAuthConfig for defaults.
//
// Example: app.Use(BasicAuth(BasicAuthConfig{Users: map[string]string{"admin": "secret"}}))
// Example: app.Use(BasicAuth(BasicAuthConfig{Users: users, Realm: "Admin Panel"}))
func BasicAuth(cfg BasicAuthConfig) MiddlewareFunc {
	realm := cfg.Realm
	if realm == "" {
		realm = "Restricted"
	}
	realm = sanitizeAuthRealm(realm)
	challenge := "Basic realm=\"" + realm + "\""

	userHashes := make(map[string][32]byte, len(cfg.Users))
	for u, p := range cfg.Users {
		userHashes[u] = sha256.Sum256([]byte(p))
	}

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
			passHash := sha256.Sum256([]byte(pass))
			expectedHash, ok := userHashes[user]
			passwordMatches := subtle.ConstantTimeCompare(expectedHash[:], passHash[:])
			if !ok || passwordMatches != 1 {
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

// If returns middleware that applies inner only when predicate returns true for the request, otherwise the request bypasses inner.
//
// Example: app.Use(If(func(r *Request) bool { return r.Path != "/health" }, Logger()))
// Example: app.Use(If(func(r *Request) bool { return r.Method == "POST" }, BodyLimit(1<<20)))
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

// Header returns middleware that sets a fixed response header on every request.
//
// Example: app.Use(Header("X-Powered-By", "ALOS"))
// Example: app.Use(Header("Cache-Control", "no-store"))
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
