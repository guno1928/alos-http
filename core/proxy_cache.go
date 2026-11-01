//go:build linux && amd64

package core

import (
	"compress/flate"
	"compress/gzip"
	"hash/maphash"
	"io"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/andybalholm/brotli"
	"github.com/guno1928/alosmap"
)

// CacheRule configures caching for a specific path prefix within a ProxyCacheConfig.Rules list. If PathPrefix is empty it acts as a default rule matching every path.
//
// PathPrefix is the request path prefix this rule applies to; empty matches every path.
//
//	Example: PathPrefix: "/api/".
//
// MaxAge is the TTL applied to entries matched by this rule; 0 falls back to ProxyCacheConfig.DefaultMaxAge.
//
//	Example: MaxAge: 10 * time.Minute.
//
// Methods restricts this rule to specific HTTP methods; empty matches any method eligible for caching (GET or HEAD).
//
//	Example: Methods: []string{"GET"}.
//
// MaxBytes is currently unused and has no effect; entry size is capped by ProxyCacheConfig.MaxEntrySize instead.
//
//	Example: MaxBytes: 1 << 20.
//
// StatusOnly restricts this rule to specific response status codes; empty matches any status eligible for caching (only 200).
//
//	Example: StatusOnly: []int{200}.
type CacheRule struct {
	PathPrefix string
	MaxAge     time.Duration
	Methods    []string
	MaxBytes   int64
	StatusOnly []int
}

// ProxyCacheConfig controls how the reverse proxy caches backend responses. The zero
// value is valid; NewProxyCache and UpdateConfig apply defaults to zero-valued fields.
//
// Rules lists path-specific caching rules, consulted in order; the first rule whose
// PathPrefix, Methods, and StatusOnly all match supplies the TTL. Only GET/HEAD
// responses with a 200 status are ever eligible. An empty Rules caches
// every eligible response using DefaultMaxAge; a non-empty Rules that matches nothing
// skips caching.
//
//	Example: Rules: []core.CacheRule{{PathPrefix: "/static/", MaxAge: time.Hour}}.
//
// MaxEntrySize is the largest response body that may be cached, in bytes; 0 defaults
// to 4 MiB. Larger responses bypass the cache.
//
//	Example: MaxEntrySize: 8 << 20.
//
// DefaultMaxAge is the TTL used when Rules is empty, or for a matching rule with
// MaxAge unset; 0 defaults to 5 minutes.
//
//	Example: DefaultMaxAge: 10 * time.Minute.
//
// MaxTotalBytes caps the cache's aggregate stored bytes, counting each entry's key,
// headers, bodies and bookkeeping; 0 defaults to 256 MiB.
// Exceeding it triggers eviction of the oldest entries down to 90% of the cap.
//
//	Example: MaxTotalBytes: 512 << 20.
//
// MaxEntries caps the number of stored entries; 0 defaults to 10000 and a negative
// value disables the cap.
//
//	Example: MaxEntries: 50000.
//
// StaleWhileRev extends how long an expired entry may still be served after its TTL
// elapses; 0 disables stale serving.
//
//	Example: StaleWhileRev: 30 * time.Second.
//
// PreCompress, when true, stores a gzip copy of cacheable responses alongside the
// original so clients that accept gzip skip runtime compression; the zero value is
// false (DefaultProxyCacheConfig sets it true).
//
//	Example: PreCompress: true.
//
// CompressLevel is the gzip level used when PreCompress is set; values outside 1-9 default to 2.
//
//	Example: CompressLevel: 9.
//
// CompressMinLen is the minimum response body size, in bytes, before pre-compression
// is applied; 0 defaults to 512. Smaller bodies are stored uncompressed.
//
//	Example: CompressMinLen: 1024.
type ProxyCacheConfig struct {
	Rules          []CacheRule
	MaxEntrySize   int64
	DefaultMaxAge  time.Duration
	MaxTotalBytes  int64
	MaxEntries     int64
	StaleWhileRev  time.Duration
	PreCompress    bool
	CompressLevel  int
	CompressMinLen int
}

const defaultProxyCacheMaxEntries = 10000

// DefaultProxyCacheConfig returns a ProxyCacheConfig with sensible defaults:
// 4 MB max entry, 5 minute TTL, 256 MB total, 10k entries, gzip compression
// at level 2 for responses >= 512 bytes.
func DefaultProxyCacheConfig() ProxyCacheConfig {
	return ProxyCacheConfig{
		MaxEntrySize:   4 << 20,
		DefaultMaxAge:  5 * time.Minute,
		MaxTotalBytes:  256 << 20,
		MaxEntries:     defaultProxyCacheMaxEntries,
		PreCompress:    true,
		CompressLevel:  defaultCompressLevel,
		CompressMinLen: 512,
	}
}

type cacheEntry struct {
	statusCode  int
	headers     [][2]string
	contentType string
	body        []byte
	gzipBody    []byte
	createdAt   int64
	expiresAt   int64
	manual      bool
	hits        atomic.Uint64
	maxHits     uint64
	bodyLen     int32
	gzipLen     int32
	cost        int64
	deleted     atomic.Bool
}

const (
	cacheEntryOverhead = int64(unsafe.Sizeof(cacheEntry{}) + unsafe.Sizeof(""))
	cacheFieldOverhead = int64(unsafe.Sizeof([2]string{}))
)

func cacheEntryCost(key string, entry *cacheEntry) int64 {
	cost := cacheEntryOverhead + int64(len(key)) + int64(len(entry.contentType)) +
		int64(cap(entry.body)) + int64(cap(entry.gzipBody)) + int64(cap(entry.headers))*cacheFieldOverhead
	for i := range entry.headers {
		cost += int64(len(entry.headers[i][0]) + len(entry.headers[i][1]))
	}
	return cost
}

func (pc *ProxyCache) removeEntry(key string, entry *cacheEntry) {
	if !pc.retireEntry(entry) {
		return
	}
	pc.entries.CompareAndDelete(key, entry)
}

func (pc *ProxyCache) retireEntry(entry *cacheEntry) bool {
	if !entry.deleted.CompareAndSwap(false, true) {
		return false
	}
	pc.totalBytes.Add(-entry.cost)
	pc.totalEntries.Add(-1)
	return true
}

// ProxyCache stores and serves cached upstream responses keyed by method, host, and
// path. It normalizes gzip/deflate/brotli-encoded backend bodies to raw form before
// storing, supports automatic TTL expiration and hit-count limits, and can pre-compress
// cacheable responses with gzip so gzip-accepting clients skip runtime compression.
// Create one with NewProxyCache, or let the server provision one automatically via
// Server.SetProxyCache.
type ProxyCache struct {
	entries      *alosmap.TypedMap[string, *cacheEntry]
	config       atomic.Pointer[ProxyCacheConfig]
	totalBytes   atomic.Int64
	totalEntries atomic.Int64
	totalHits    atomic.Uint64
	totalMisses  atomic.Uint64
	stopCh       chan struct{}
	stopOnce     sync.Once
	evicting     atomic.Bool
	transforms   atomic.Int32
	purges       atomic.Uint64
	widePurgedAt atomic.Uint64
	keyPurgedAt  [cachePurgeStripes]atomic.Uint64
	gzipLevel    int
}

// NewProxyCache creates a ProxyCache configured with cfg, normalizing zero-valued
// CompressLevel, CompressMinLen, DefaultMaxAge, MaxEntrySize, MaxTotalBytes, and
// MaxEntries to their defaults, and starts a background goroutine that periodically
// evicts expired entries.
func NewProxyCache(cfg ProxyCacheConfig) *ProxyCache {
	if cfg.CompressLevel < 1 || cfg.CompressLevel > 9 {
		cfg.CompressLevel = defaultCompressLevel
	}
	if cfg.CompressMinLen <= 0 {
		cfg.CompressMinLen = 512
	}
	if cfg.DefaultMaxAge <= 0 {
		cfg.DefaultMaxAge = 5 * time.Minute
	}
	if cfg.MaxEntrySize <= 0 {
		cfg.MaxEntrySize = 4 << 20
	}
	if cfg.MaxTotalBytes <= 0 {
		cfg.MaxTotalBytes = 256 << 20
	}
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = defaultProxyCacheMaxEntries
	}

	pc := &ProxyCache{
		entries:   alosmap.NewTypedSized[string, *cacheEntry](10000, 0).Prealloc(256),
		stopCh:    make(chan struct{}),
		gzipLevel: cfg.CompressLevel,
	}
	pc.config.Store(&cfg)
	go pc.evictLoop()
	return pc
}

// UpdateConfig atomically replaces the cache's active configuration with cfg,
// normalizing zero-valued CompressLevel, CompressMinLen, and DefaultMaxAge to their
// defaults. Unlike NewProxyCache, MaxEntrySize, MaxTotalBytes, and MaxEntries are stored as given.
// Existing entries are left as-is.
func (pc *ProxyCache) UpdateConfig(cfg ProxyCacheConfig) {
	if cfg.CompressLevel < 1 || cfg.CompressLevel > 9 {
		cfg.CompressLevel = defaultCompressLevel
	}
	if cfg.CompressMinLen <= 0 {
		cfg.CompressMinLen = 512
	}
	if cfg.DefaultMaxAge <= 0 {
		cfg.DefaultMaxAge = 5 * time.Minute
	}
	pc.config.Store(&cfg)
}

// Stop signals the cache's background eviction goroutine to exit. Safe to call
// multiple times; only the first call takes effect.
func (pc *ProxyCache) Stop() {
	pc.stopOnce.Do(func() { close(pc.stopCh) })
}

func (pc *ProxyCache) buildKey(method, host, path string) string {
	host = normalizeCertDomain(host)

	n := len(method) + 2 + len(host) + len(path)
	var stackBuf [256]byte
	var buf []byte
	if n <= len(stackBuf) {
		buf = stackBuf[:0]
	} else {
		bp := MediumBufPool.Get().(*[]byte)
		buf = (*bp)[:0]
		if cap(buf) < n {
			buf = make([]byte, 0, n)
		}
		defer func() {
			*bp = buf[:0]
			MediumBufPool.Put(bp)
		}()
	}
	buf = append(buf, method...)
	buf = append(buf, '|')
	buf = append(buf, host...)
	buf = append(buf, '|')
	buf = append(buf, path...)
	return string(buf)
}

func proxyCacheRequestAllowed(req *Request) bool {
	if req == nil {
		return false
	}
	if req.Header("authorization") != "" || req.Header("cookie") != "" {
		return false
	}
	if cacheControlDisablesLookup(req.Header("cache-control")) || containsTokenFold(req.Header("pragma"), "no-cache") {
		return false
	}
	return true
}

func proxyCacheResponseAllowed(headers [][2]string) bool {
	for i := range headers {
		name := headers[i][0]
		value := headers[i][1]
		if EqualFoldASCII(name, "set-cookie") {
			return false
		}
		if EqualFoldASCII(name, "cache-control") {
			if cacheControlDisablesStorage(value) {
				return false
			}
		}
		if EqualFoldASCII(name, "pragma") {
			if containsTokenFold(value, "no-cache") {
				return false
			}
		}
		if EqualFoldASCII(name, "vary") {
			if !cacheVarySupported(value) {
				return false
			}
		}
	}
	return true
}

func cacheControlDisablesLookup(value string) bool {
	for len(value) > 0 {
		end := indexByte(value, ',')
		var token string
		if end < 0 {
			token = value
			value = ""
		} else {
			token = value[:end]
			value = value[end+1:]
		}
		token = trimASCIISpace(token)
		if token == "" {
			continue
		}
		name, arg := splitHeaderDirective(token)
		if EqualFoldASCII(name, "no-cache") || EqualFoldASCII(name, "no-store") {
			return true
		}
		if EqualFoldASCII(name, "max-age") && arg == "0" {
			return true
		}
	}
	return false
}

func cacheControlDisablesStorage(value string) bool {
	for len(value) > 0 {
		end := indexByte(value, ',')
		var token string
		if end < 0 {
			token = value
			value = ""
		} else {
			token = value[:end]
			value = value[end+1:]
		}
		token = trimASCIISpace(token)
		if token == "" {
			continue
		}
		name, _ := splitHeaderDirective(token)
		if EqualFoldASCII(name, "no-cache") || EqualFoldASCII(name, "no-store") || EqualFoldASCII(name, "private") {
			return true
		}
	}
	return false
}

func cacheVarySupported(value string) bool {
	for len(value) > 0 {
		end := indexByte(value, ',')
		var token string
		if end < 0 {
			token = value
			value = ""
		} else {
			token = value[:end]
			value = value[end+1:]
		}
		token = trimASCIISpace(token)
		if token == "" {
			continue
		}
		if token == "*" {
			return false
		}
		if !EqualFoldASCII(token, "accept-encoding") {
			return false
		}
	}
	return true
}

func splitHeaderDirective(token string) (string, string) {
	if idx := indexByte(token, '='); idx >= 0 {
		return trimASCIISpace(token[:idx]), trimASCIISpace(token[idx+1:])
	}
	return trimASCIISpace(token), ""
}

func (pc *ProxyCache) shouldCache(cfg *ProxyCacheConfig, method, path string, statusCode int) (time.Duration, bool) {
	if method != "GET" && method != "HEAD" {
		return 0, false
	}
	if statusCode != 200 {
		return 0, false
	}

	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.PathPrefix != "" && !hasPrefix(path, r.PathPrefix) {
			continue
		}
		if len(r.Methods) > 0 {
			found := false
			for _, m := range r.Methods {
				if m == method {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if len(r.StatusOnly) > 0 {
			found := false
			for _, sc := range r.StatusOnly {
				if sc == statusCode {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		ttl := r.MaxAge
		if ttl <= 0 {
			ttl = cfg.DefaultMaxAge
		}
		return ttl, true
	}

	if len(cfg.Rules) == 0 {
		return cfg.DefaultMaxAge, true
	}
	return 0, false
}

// Get looks up the cache entry for method, host, and path. Automatically-cached
// entries are only returned when req's headers permit a cache lookup (no
// Authorization/Cookie, and no Cache-Control/Pragma no-cache); manually cached
// entries (see ProxyResponse.CacheThis) always qualify. It reports whether an entry
// was found, including entries served stale within StaleWhileRev after expiring.
func (pc *ProxyCache) Get(method, host, path string, req *Request) (*cacheEntry, bool) {
	return pc.lookupEntry(method, host, path, proxyCacheRequestAllowed(req))
}

// GetFP is like Get but takes a precomputed reqAllows flag instead of a *Request, for
// callers that have already evaluated the request's cache-eligibility headers.
func (pc *ProxyCache) GetFP(method, host, path string, reqAllows bool) (*cacheEntry, bool) {
	return pc.lookupEntry(method, host, path, reqAllows)
}

func (pc *ProxyCache) lookupEntry(method, host, path string, reqAllows bool) (*cacheEntry, bool) {
	key := pc.buildKey(method, host, path)
	entry, ok := pc.entries.Load(key)
	if !ok {
		pc.totalMisses.Add(1)
		return nil, false
	}
	if !entry.manual && !reqAllows {
		pc.totalMisses.Add(1)
		return nil, false
	}

	now := CoarseNanotime()
	if now > entry.expiresAt {
		cfg := pc.config.Load()
		if cfg.StaleWhileRev > 0 && now < entry.expiresAt+int64(cfg.StaleWhileRev) {
			entry.hits.Add(1)
			pc.totalHits.Add(1)
			return entry, true
		}
		pc.removeEntry(key, entry)
		pc.totalMisses.Add(1)
		return nil, false
	}

	entry.hits.Add(1)
	pc.totalHits.Add(1)

	if entry.maxHits > 0 && entry.hits.Load() >= entry.maxHits {
		pc.removeEntry(key, entry)
	}

	return entry, true
}

// Put stores body in the cache for method, host, and path if a matching CacheRule (or
// the default rule) permits it, subject to ProxyCacheConfig's size limits. It is a
// no-op when no rule allows caching for this method/path/status combination.
func (pc *ProxyCache) Put(method, host, path string, statusCode int, headers [][2]string, contentType string, body []byte) {
	pc.put(method, host, path, statusCode, headers, contentType, body, cachePutOptions{generation: pc.purgeGeneration()})
}

type cachePutOptions struct {
	generation uint64
	offload    bool
}

func (pc *ProxyCache) purgeGeneration() uint64 {
	if pc == nil {
		return 0
	}
	return pc.purges.Load()
}

const cachePurgeStripes = 256

var cachePurgeSeed = maphash.MakeSeed()

func (pc *ProxyCache) keyPurgeStripe(key string) *atomic.Uint64 {
	return &pc.keyPurgedAt[maphash.String(cachePurgeSeed, key)%cachePurgeStripes]
}

func (pc *ProxyCache) markPurged(stripe *atomic.Uint64) {
	seq := pc.purges.Add(1)
	for {
		cur := stripe.Load()
		if cur >= seq || stripe.CompareAndSwap(cur, seq) {
			return
		}
	}
}

func (pc *ProxyCache) purgedSince(key string, generation uint64) bool {
	return pc.widePurgedAt.Load() > generation || pc.keyPurgeStripe(key).Load() > generation
}

func (pc *ProxyCache) put(method, host, path string, statusCode int, headers [][2]string, contentType string, body []byte, opts cachePutOptions) {
	cfg := pc.config.Load()
	ttl, ok := pc.shouldCache(cfg, method, path, statusCode)
	if !ok {
		return
	}
	pc.putEntry(cfg, method, host, path, statusCode, headers, contentType, body, ttl, 0, cfg.PreCompress, -1, false, opts)
}

// PutManual stores body in the cache for method, host, and path with an explicit ttl,
// maxHits, and pre-compression policy, bypassing the automatic CacheRule matching
// used by Put. It backs ProxyResponse.CacheThis and is a no-op when body exceeds
// ProxyCacheConfig.MaxEntrySize.
func (pc *ProxyCache) PutManual(method, host, path string, statusCode int, headers [][2]string, contentType string, body []byte, ttl time.Duration, maxHits uint64, preCompress bool, compressMinLen int) {
	pc.putManual(method, host, path, statusCode, headers, contentType, body, ttl, maxHits, preCompress, compressMinLen, cachePutOptions{generation: pc.purgeGeneration()})
}

func (pc *ProxyCache) putManual(method, host, path string, statusCode int, headers [][2]string, contentType string, body []byte, ttl time.Duration, maxHits uint64, preCompress bool, compressMinLen int, opts cachePutOptions) {
	pc.putEntry(pc.config.Load(), method, host, path, statusCode, headers, contentType, body, ttl, maxHits, preCompress, compressMinLen, true, opts)
}

const (
	cacheMaxInflatedSize      = 64 << 20
	cacheInlineTransformLimit = 16 << 10
	cacheInflateChunk         = 8 << 10
	cacheTransformCPUShare    = 2
)

func cacheInflateLimit(cfg *ProxyCacheConfig) int64 {
	if cfg.MaxEntrySize > 0 && cfg.MaxEntrySize < cacheMaxInflatedSize {
		return cfg.MaxEntrySize
	}
	return cacheMaxInflatedSize
}

func (pc *ProxyCache) acquireTransform() bool {
	limit := max(1, runtime.GOMAXPROCS(0)/cacheTransformCPUShare)
	if pc.transforms.Add(1) > int32(limit) {
		pc.transforms.Add(-1)
		return false
	}
	return true
}

func (pc *ProxyCache) putEntry(cfg *ProxyCacheConfig, method, host, path string, statusCode int, headers [][2]string, contentType string, body []byte, ttl time.Duration, maxHits uint64, preCompress bool, compressMinLen int, manual bool, opts cachePutOptions) {
	if cfg.MaxEntrySize > 0 && int64(len(body)) > cfg.MaxEntrySize {
		return
	}
	key := pc.buildKey(method, host, path)
	if pc.purgedSince(key, opts.generation) {
		return
	}

	if cfg.MaxEntries > 0 && pc.totalEntries.Load() >= cfg.MaxEntries {
		if _, replacing := pc.entries.Load(key); !replacing {
			pc.requestEviction()
			return
		}
	}

	_, backendEncoding := detectBackendEncoding(headers)
	compress := preCompress && isCompressibleType(contentType)
	minLen := cfg.CompressMinLen
	if compressMinLen > 0 {
		minLen = compressMinLen
	}
	deferred := opts.offload && (backendEncoding != "" || compress && len(body) > cacheInlineTransformLimit)

	now := CoarseNanotime()

	bodyCopy := make([]byte, len(body))
	copy(bodyCopy, body)

	headersCopy := make([][2]string, len(headers))
	copy(headersCopy, headers)

	entry := &cacheEntry{
		statusCode:  statusCode,
		headers:     stripCacheUnsafeHeaders(headersCopy),
		contentType: contentType,
		body:        bodyCopy,
		createdAt:   now,
		expiresAt:   now + int64(ttl),
		manual:      manual,
		maxHits:     maxHits,
		bodyLen:     int32(len(bodyCopy)),
	}

	if deferred && backendEncoding != "" && len(body) <= cacheInlineTransformLimit &&
		inflateCacheEntry(entry, backendEncoding, min(cacheInflateLimit(cfg), cacheInlineTransformLimit)) == nil {
		backendEncoding, deferred = "", false
	}
	if deferred && !pc.acquireTransform() {
		return
	}
	if !deferred {
		pc.transformAndStore(cfg, key, entry, backendEncoding, compress, minLen, opts.generation)
		return
	}
	go func() {
		defer pc.transforms.Add(-1)
		pc.transformAndStore(cfg, key, entry, backendEncoding, compress, minLen, opts.generation)
	}()
}

func (pc *ProxyCache) transformAndStore(cfg *ProxyCacheConfig, key string, entry *cacheEntry, backendEncoding string, compress bool, minLen int, generation uint64) {
	if backendEncoding != "" && inflateCacheEntry(entry, backendEncoding, cacheInflateLimit(cfg)) == ErrBodyTooLarge {
		return
	}

	if compress && int(entry.bodyLen) >= minLen {
		gz := pc.compressGzip(entry.body)
		if len(gz) > 0 && len(gz) < len(entry.body) {
			entry.gzipBody = gz
			entry.gzipLen = int32(len(gz))
		}
	}
	entry.cost = cacheEntryCost(key, entry)
	pc.storeEntry(cfg, key, entry, generation)
}

func inflateCacheEntry(entry *cacheEntry, encoding string, limit int64) error {
	raw, err := decompressBody(entry.body, encoding, limit)
	if err != nil {
		return err
	}
	entry.body = raw
	entry.bodyLen = int32(len(raw))
	entry.headers = removeContentEncoding(entry.headers)
	return nil
}

func (pc *ProxyCache) storeEntry(cfg *ProxyCacheConfig, key string, entry *cacheEntry, generation uint64) {
	pc.totalEntries.Add(1)
	pc.totalBytes.Add(entry.cost)
	if prev, loaded := pc.entries.Swap(key, entry); loaded {
		pc.retireEntry(prev)
	}
	if pc.purgedSince(key, generation) {
		pc.removeEntry(key, entry)
		return
	}

	if pc.overCapacity(cfg) {
		pc.requestEviction()
	}
}

func (pc *ProxyCache) overCapacity(cfg *ProxyCacheConfig) bool {
	return cfg.MaxTotalBytes > 0 && pc.totalBytes.Load() > cfg.MaxTotalBytes ||
		cfg.MaxEntries > 0 && pc.totalEntries.Load() > cfg.MaxEntries
}

func (pc *ProxyCache) requestEviction() {
	if pc.evicting.CompareAndSwap(false, true) {
		go pc.evictOldest()
	}
}

// Purge removes the cached entry for method, host, and path, if present, and reports
// whether an entry was removed.
func (pc *ProxyCache) Purge(method, host, path string) bool {
	key := pc.buildKey(method, host, path)
	pc.markPurged(pc.keyPurgeStripe(key))
	if entry, ok := pc.entries.Load(key); ok {
		pc.removeEntry(key, entry)
		return true
	}
	return false
}

// PurgeAll removes every cached entry and resets the cache's byte and entry counters.
func (pc *ProxyCache) PurgeAll() {
	pc.markPurged(&pc.widePurgedAt)
	pc.entries.Range(func(key string, entry *cacheEntry) bool {
		pc.removeEntry(key, entry)
		return true
	})
}

// PurgeDomain removes every GET and HEAD entry cached for domain and returns the
// number of entries removed.
func (pc *ProxyCache) PurgeDomain(domain string) int64 {
	pc.markPurged(&pc.widePurgedAt)
	domain = normalizeCertDomain(domain)
	prefix1 := "GET|" + domain + "|"
	prefix2 := "HEAD|" + domain + "|"
	var purged int64
	pc.entries.Range(func(key string, entry *cacheEntry) bool {
		if hasPrefix(key, prefix1) || hasPrefix(key, prefix2) {
			pc.removeEntry(key, entry)
			purged++
		}
		return true
	})
	return purged
}

// Stats returns the current entry count, total stored bytes, and cumulative hit/miss counters.
func (pc *ProxyCache) Stats() (entries int64, totalBytes int64, hits uint64, misses uint64) {
	return pc.totalEntries.Load(), pc.totalBytes.Load(), pc.totalHits.Load(), pc.totalMisses.Load()
}

// ServeCached writes entry to resp, setting the status, headers, and X-Cache /
// X-Cache-Hits response headers, and serves the pre-compressed gzip body when req
// accepts gzip encoding.
func (pc *ProxyCache) ServeCached(entry *cacheEntry, req *Request, resp *Response) {
	resp.Status(entry.statusCode)
	if entry.contentType != "" {
		resp.ContentType = entry.contentType
	}
	for i := range entry.headers {
		resp.SetHeader(entry.headers[i][0], entry.headers[i][1])
	}
	resp.SetHeaderUnsafe("x-cache", "HIT")
	var hitBuf [20]byte
	resp.SetHeaderUnsafe("x-cache-hits", string(appendUint(hitBuf[:0], int64(entry.hits.Load()))))

	if entry.gzipLen == 0 {
		resp.referenceBody(entry.body)
		return
	}
	if negotiateEncoding(req.Header("accept-encoding"), offerGzip) == encodingGzip {
		resp.SetHeaderUnsafe("content-encoding", contentEncodingNames[encodingGzip])
		resp.referenceBody(entry.gzipBody)
	} else {
		resp.referenceBody(entry.body)
	}
	addVaryAcceptEncoding(resp)
}

func (pc *ProxyCache) compressGzip(data []byte) []byte {
	bp := LargeBufPool.Get().(*[]byte)
	buf := appendCompressed((*bp)[:0], data, encodingGzip, pc.gzipLevel)
	result := make([]byte, len(buf))
	copy(result, buf)
	*bp = buf
	putBoxedBufCapped(&LargeBufPool, bp, largeBufPoolMaxCap)
	return result
}

func (pc *ProxyCache) evictLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-pc.stopCh:
			return
		case <-ticker.C:
			pc.evictExpired()
		}
	}
}

func (pc *ProxyCache) evictExpired() {
	defer func() {
		if r := recover(); r != nil {
			Dbg("[proxy-cache evict] recovered panic: %v", r)
		}
	}()
	now := CoarseNanotime()
	pc.entries.Range(func(key string, entry *cacheEntry) bool {
		if now > entry.expiresAt {
			pc.removeEntry(key, entry)
		}
		return true
	})
}

func (pc *ProxyCache) evictOldest() {
	defer func() {
		pc.evicting.Store(false)
		if pc.overCapacity(pc.config.Load()) {
			pc.requestEviction()
		}
	}()

	cfg := pc.config.Load()
	byteTarget := int64(-1)
	if cfg.MaxTotalBytes > 0 {
		byteTarget = cfg.MaxTotalBytes * 90 / 100
	}
	entryTarget := int64(-1)
	if cfg.MaxEntries > 0 {
		headroom := cfg.MaxEntries / 10
		if headroom < 1 {
			headroom = 1
		}
		entryTarget = cfg.MaxEntries - headroom
	}

	type candidate struct {
		key       string
		createdAt int64
	}
	candidates := make([]candidate, 0, 64)
	pc.entries.Range(func(key string, entry *cacheEntry) bool {
		candidates = append(candidates, candidate{
			key:       key,
			createdAt: entry.createdAt,
		})
		return true
	})

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].createdAt < candidates[j].createdAt
	})

	for _, c := range candidates {
		overBytes := byteTarget >= 0 && pc.totalBytes.Load() > byteTarget
		overEntries := entryTarget >= 0 && pc.totalEntries.Load() > entryTarget
		if !overBytes && !overEntries {
			break
		}
		if entry, ok := pc.entries.Load(c.key); ok {
			pc.removeEntry(c.key, entry)
		}
	}
}

func detectBackendEncoding(headers [][2]string) (bool, string) {
	for i := range headers {
		if EqualFoldASCII(headers[i][0], "content-encoding") {
			enc := headers[i][1]
			if EqualFoldASCII(enc, "br") {
				return true, "br"
			}
			if EqualFoldASCII(enc, "gzip") {
				return true, "gzip"
			}
			if EqualFoldASCII(enc, "deflate") {
				return true, "deflate"
			}
		}
	}
	return false, ""
}

func decompressBody(data []byte, encoding string, limit int64) ([]byte, error) {
	switch encoding {
	case "gzip":
		r, err := gzip.NewReader(newBytesReader(data))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return inflateCapped(r, limit)
	case "deflate":
		r := flate.NewReader(newBytesReader(data))
		defer r.Close()
		return inflateCapped(r, limit)
	case "br":
		return inflateCapped(brotli.NewReader(newBytesReader(data)), limit)
	}
	return data, nil
}

func inflateCapped(r io.Reader, limit int64) ([]byte, error) {
	bp := LargeBufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	defer func() {
		*bp = buf
		putBoxedBufCapped(&LargeBufPool, bp, largeBufPoolMaxCap)
	}()
	tmp := make([]byte, cacheInflateChunk)
	for {
		n, rerr := r.Read(tmp)
		if n > 0 {
			if int64(len(buf)+n) > limit {
				return nil, ErrBodyTooLarge
			}
			buf = append(buf, tmp[:n]...)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}
	result := make([]byte, len(buf))
	copy(result, buf)
	return result, nil
}

func removeContentEncoding(headers [][2]string) [][2]string {
	n := 0
	for i := range headers {
		if !EqualFoldASCII(headers[i][0], "content-encoding") {
			headers[n] = headers[i]
			n++
		}
	}
	return headers[:n]
}

func stripCacheUnsafeHeaders(headers [][2]string) [][2]string {
	n := 0
	for i := range headers {
		k := headers[i][0]
		if EqualFoldASCII(k, "content-length") || EqualFoldASCII(k, "content-type") || EqualFoldASCII(k, "transfer-encoding") ||
			EqualFoldASCII(k, "set-cookie") || EqualFoldASCII(k, "www-authenticate") || EqualFoldASCII(k, "proxy-authenticate") {
			continue
		}
		headers[n] = headers[i]
		n++
	}
	return headers[:n]
}

func isCompressibleType(ct string) bool {
	if ct == "" {
		return false
	}
	if len(ct) >= 5 && asciiLower[ct[0]] == 't' && asciiLower[ct[1]] == 'e' && asciiLower[ct[2]] == 'x' && asciiLower[ct[3]] == 't' && ct[4] == '/' {
		return true
	}
	switch {
	case hasPrefixFold(ct, "application/json"),
		hasPrefixFold(ct, "application/javascript"),
		hasPrefixFold(ct, "application/xml"),
		hasPrefixFold(ct, "application/xhtml"),
		hasPrefixFold(ct, "image/svg"):
		return true
	}
	return false
}

type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// maxCacheableSize reports the largest body this cache will store, so the proxy
// can decide whether a response is worth buffering in order to cache it.
func (pc *ProxyCache) maxCacheableSize() int64 {
	if pc == nil {
		return 0
	}
	cfg := pc.config.Load()
	if cfg == nil {
		return 0
	}
	return cfg.MaxEntrySize
}
