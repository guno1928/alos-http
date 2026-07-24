package core

import (
	"compress/gzip"
	"strings"
	"sync"
	"time"

	"github.com/guno1928/alosmap"
	"github.com/guno1928/turbo"
)

// CacheConfig configures the in-memory response cache built by Cache and
// NewResponseCache. The zero value is valid; each field below falls back to a
// default when left zero.
//
// TTL is how long a cached response stays fresh; 0 defaults to 60s.
//
//	Example: TTL: 30 * time.Second.
//	Example: TTL: 5 * time.Minute.
//
// Methods lists the HTTP methods eligible for caching; empty defaults to {"GET"}.
//
//	Example: Methods: []string{"GET"}.
//	Example: Methods: []string{"GET", "HEAD"}.
//
// IgnoreQuery, when true, drops the query string from the cache key so that
// "/p?a=1" and "/p?a=2" share one entry; defaults to false (the query is keyed).
//
//	Example: IgnoreQuery: true.
//	Example: IgnoreQuery: false.
//
// MaxEntries caps the number of stored responses; 0 defaults to 10000. When the
// cache is full the oldest entries are evicted first.
//
//	Example: MaxEntries: 50000.
//
// MaxBodyBytes is the largest response body that will be cached; 0 defaults to
// 1 MiB. Larger responses bypass the cache entirely.
//
//	Example: MaxBodyBytes: 4 << 20.
//
// Gzip, when true, pre-compresses cacheable text-like responses and serves the
// gzip copy to clients that send Accept-Encoding: gzip; defaults to false.
//
//	Example: Gzip: true.
//
// GzipMinBytes is the minimum body size pre-compressed when Gzip is set; 0
// defaults to 512.
//
//	Example: GzipMinBytes: 1024.
//
// GzipLevel is the gzip level used when Gzip is set; values outside 1–9 default
// to 6.
//
//	Example: GzipLevel: 9.
//
// SweepInterval is how often expired and overflow entries are reaped; 0 defaults
// to 15s.
//
//	Example: SweepInterval: 30 * time.Second.
//
// CacheableStatus decides which status codes may be cached; nil caches only 200.
//
//	Example: CacheableStatus: func(code int) bool { return code == 200 || code == 404 }.
type CacheConfig struct {
	TTL           time.Duration
	Methods       []string
	IgnoreQuery   bool
	MaxEntries    int
	MaxBodyBytes  int
	Gzip          bool
	GzipMinBytes  int
	GzipLevel     int
	SweepInterval time.Duration
	CacheableStatus func(int) bool
}

type cachedResponse struct {
	status      int
	headers     [][2]string
	contentType string
	body        []byte
	gzipBody    []byte
	expiresAtNs int64
	storedAtNs  int64
}

// ResponseCache is a concurrent in-memory HTTP response cache. Create one with
// NewResponseCache, or use the Cache middleware, and call Stop to release its
// background sweeper.
type ResponseCache struct {
	cfg      CacheConfig
	store    *alosmap.TypedMap[string, *cachedResponse]
	methods  map[string]struct{}
	ttlNs    int64
	stop     chan struct{}
	stopOnce sync.Once
}

// Cache returns middleware that caches handler responses in memory according to
// cfg. It is the middleware form of NewResponseCache.
//
// Example: s.Router.Use(Cache(CacheConfig{TTL: time.Minute}))
// Example: s.Router.Use(Cache(CacheConfig{TTL: 5 * time.Minute, Gzip: true, Methods: []string{"GET", "HEAD"}}))
func Cache(cfg CacheConfig) MiddlewareFunc {
	rc := NewResponseCache(cfg)
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			rc.handle(next, req, resp)
		}
	}
}

// NewResponseCache builds a ResponseCache from cfg, applying defaults for any
// zero field (TTL 60s, Methods {"GET"}, MaxEntries 10000, MaxBodyBytes 1 MiB,
// GzipMinBytes 512, GzipLevel 6, SweepInterval 15s) and starting the background
// sweeper. Call Stop when done to end the sweeper goroutine.
//
// Example: rc := NewResponseCache(CacheConfig{})
// Example: rc := NewResponseCache(CacheConfig{TTL: 10 * time.Second, MaxEntries: 1000})
func NewResponseCache(cfg CacheConfig) *ResponseCache {
	if cfg.TTL <= 0 {
		cfg.TTL = 60 * time.Second
	}
	if len(cfg.Methods) == 0 {
		cfg.Methods = []string{"GET"}
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 10000
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.GzipMinBytes <= 0 {
		cfg.GzipMinBytes = 512
	}
	if cfg.GzipLevel < 1 || cfg.GzipLevel > 9 {
		cfg.GzipLevel = 6
	}
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = 15 * time.Second
	}
	methods := make(map[string]struct{}, len(cfg.Methods))
	for _, m := range cfg.Methods {
		methods[strings.ToUpper(m)] = struct{}{}
	}
	rc := &ResponseCache{
		cfg:     cfg,
		store:   alosmap.NewTyped[string, *cachedResponse]().Prealloc(128),
		methods: methods,
		ttlNs:   int64(cfg.TTL),
		stop:    make(chan struct{}),
	}
	go rc.sweepLoop()
	return rc
}

// Stop halts the background sweeper. It is safe to call multiple times.
func (rc *ResponseCache) Stop() {
	if rc == nil {
		return
	}
	rc.stopOnce.Do(func() { close(rc.stop) })
}

// Len returns the number of entries currently cached.
func (rc *ResponseCache) Len() int { return rc.store.Len() }

// Purge removes every cached entry.
func (rc *ResponseCache) Purge() { rc.store.Clear() }

func (rc *ResponseCache) handle(next HandlerFunc, req *Request, resp *Response) {
	if _, ok := rc.methods[req.Method]; !ok {
		next(req, resp)
		return
	}
	key := rc.key(req)
	wantGzip := rc.cfg.Gzip && acceptsGzip(req.Header("accept-encoding"))
	if ent, ok := rc.store.Load(key); ok {
		if turbo.UnixNano() <= ent.expiresAtNs {
			serveCached(resp, ent, wantGzip)
			return
		}
		rc.store.Delete(key)
	}
	next(req, resp)
	ent := rc.captureAndStore(key, resp)
	if ent != nil && wantGzip && ent.gzipBody != nil {
		serveCached(resp, ent, true)
	}
}

func (rc *ResponseCache) captureAndStore(key string, resp *Response) *cachedResponse {
	if resp == nil || resp.IsStreamed() {
		return nil
	}
	status := resp.StatusCode
	if !rc.statusCacheable(status) {
		return nil
	}
	if !cacheableHeaders(resp.Headers) {
		return nil
	}
	body := resp.transmittedBodyBytes()
	if len(body) > rc.cfg.MaxBodyBytes {
		return nil
	}
	if rc.store.Len() >= rc.cfg.MaxEntries {
		rc.evictExpired()
		if rc.store.Len() >= rc.cfg.MaxEntries {
			return nil
		}
	}
	now := turbo.UnixNano()
	ent := &cachedResponse{
		status:      status,
		headers:     cloneHeaders(resp.Headers),
		contentType: strings.Clone(resp.ContentType),
		body:        cloneBytes(body),
		expiresAtNs: now + rc.ttlNs,
		storedAtNs:  now,
	}
	if rc.cfg.Gzip && len(body) >= rc.cfg.GzipMinBytes && compressibleType(resp.ContentType) {
		ent.gzipBody = gzipEncode(body, rc.cfg.GzipLevel)
	}
	rc.store.Store(key, ent)
	return ent
}

func (rc *ResponseCache) statusCacheable(status int) bool {
	if rc.cfg.CacheableStatus != nil {
		return rc.cfg.CacheableStatus(status)
	}
	return status == 200
}

func serveCached(resp *Response, ent *cachedResponse, wantGzip bool) {
	resp.StatusCode = ent.status
	resp.Headers = append(resp.Headers[:0], ent.headers...)
	resp.ContentType = ent.contentType
	if wantGzip && ent.gzipBody != nil {
		resp.SetBody(ent.gzipBody)
		resp.SetHeaderUnsafe("Content-Encoding", "gzip")
		resp.SetHeaderUnsafe("Vary", "Accept-Encoding")
	} else {
		resp.SetBody(ent.body)
	}
}

func (rc *ResponseCache) key(req *Request) string {
	var b strings.Builder
	b.Grow(len(req.Method) + len(req.Host) + len(req.Path) + len(req.Query) + 8)
	b.WriteString(req.Method)
	b.WriteByte(' ')
	b.WriteString(req.Host)
	b.WriteString(req.Path)
	if !rc.cfg.IgnoreQuery && req.Query != "" {
		b.WriteByte('?')
		b.WriteString(req.Query)
	}
	return b.String()
}

func (rc *ResponseCache) sweepLoop() {
	ticker := turbo.NewTicker(rc.cfg.SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-rc.stop:
			return
		case <-ticker.C:
			rc.evictExpired()
			rc.evictOverflow()
		}
	}
}

func (rc *ResponseCache) evictExpired() {
	now := turbo.UnixNano()
	rc.store.Range(func(key string, ent *cachedResponse) bool {
		if now > ent.expiresAtNs {
			rc.store.Delete(key)
		}
		return true
	})
}

func (rc *ResponseCache) evictOverflow() {
	over := rc.store.Len() - rc.cfg.MaxEntries
	if over <= 0 {
		return
	}
	type aged struct {
		key string
		ts  int64
	}
	victims := make([]aged, 0, over*2)
	rc.store.Range(func(key string, ent *cachedResponse) bool {
		victims = append(victims, aged{key, ent.storedAtNs})
		return true
	})
	for i := 1; i < len(victims); i++ {
		v := victims[i]
		j := i - 1
		for j >= 0 && victims[j].ts > v.ts {
			victims[j+1] = victims[j]
			j--
		}
		victims[j+1] = v
	}
	for i := 0; i < over && i < len(victims); i++ {
		rc.store.Delete(victims[i].key)
	}
}

func cacheableHeaders(headers [][2]string) bool {
	for i := range headers {
		k := headers[i][0]
		if EqualFoldASCII(k, "set-cookie") || EqualFoldASCII(k, "content-encoding") {
			return false
		}
		if EqualFoldASCII(k, "cache-control") {
			v := strings.ToLower(headers[i][1])
			if strings.Contains(v, "no-store") || strings.Contains(v, "no-cache") || strings.Contains(v, "private") {
				return false
			}
		}
	}
	return true
}

func compressibleType(ct string) bool {
	if ct == "" {
		return true
	}
	lc := strings.ToLower(ct)
	if strings.HasPrefix(lc, "text/") {
		return true
	}
	return strings.Contains(lc, "json") ||
		strings.Contains(lc, "javascript") ||
		strings.Contains(lc, "xml") ||
		strings.Contains(lc, "svg") ||
		strings.Contains(lc, "html") ||
		strings.Contains(lc, "css")
}

func cloneHeaders(h [][2]string) [][2]string {
	if len(h) == 0 {
		return nil
	}
	out := make([][2]string, len(h))
	for i := range h {
		out[i] = [2]string{strings.Clone(h[i][0]), strings.Clone(h[i][1])}
	}
	return out
}

func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func gzipEncode(body []byte, level int) []byte {
	bp := LargeBufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	gw := gzipWriterPool[level].Get().(*gzip.Writer)
	w := newBytesWriter(&buf)
	gw.Reset(w)
	_, _ = gw.Write(body)
	_ = gw.Close()
	gzipWriterPool[level].Put(gw)
	w.buf = nil
	bytesWriterPool.Put(w)
	var out []byte
	if len(buf) > 0 && len(buf) < len(body) {
		out = make([]byte, len(buf))
		copy(out, buf)
	}
	*bp = buf[:0]
	LargeBufPool.Put(bp)
	return out
}
