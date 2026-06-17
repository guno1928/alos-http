package core

import (
	"compress/flate"
	"compress/gzip"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/guno1928/alosmap"
)

// CacheRule configures caching for a specific path prefix. If PathPrefix is empty
// it acts as a default rule. Methods defaults to ["GET"] if empty.
//
//	core.CacheRule{
//	    PathPrefix: "/api/",
//	    MaxAge:     10 * time.Minute,
//	    Methods:    []string{"GET"},
//	    MaxBytes:   1 << 20,         // 1 MB max per entry
//	    StatusOnly: []int{200, 301}, // only cache these status codes
//	}
type CacheRule struct {
	PathPrefix string
	MaxAge     time.Duration
	Methods    []string
	MaxBytes   int64
	StatusOnly []int
}

// ProxyCacheConfig controls how the reverse proxy caches backend responses.
//
//	cfg := core.DefaultProxyCacheConfig()
//	cfg.MaxTotalBytes = 512 << 20           // 512 MB total cache
//	cfg.MaxEntrySize = 8 << 20              // 8 MB max per entry
//	cfg.DefaultMaxAge = 10 * time.Minute
//	cfg.PreCompress = true                   // pre-gzip cached entries
//	cfg.Rules = []core.CacheRule{
//	    {PathPrefix: "/static/", MaxAge: time.Hour},
//	    {PathPrefix: "/api/", MaxAge: 30 * time.Second, StatusOnly: []int{200}},
//	}
//	srv.SetProxyCache(cfg)
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

// DefaultProxyCacheConfig returns a ProxyCacheConfig with sensible defaults:
// 4 MB max entry, 5 minute TTL, 256 MB total, 10k entries, gzip compression
// at level 6 for responses >= 512 bytes.
func DefaultProxyCacheConfig() ProxyCacheConfig {
	return ProxyCacheConfig{
		MaxEntrySize:   4 << 20,
		DefaultMaxAge:  5 * time.Minute,
		MaxTotalBytes:  256 << 20,
		MaxEntries:     10000,
		PreCompress:    true,
		CompressLevel:  6,
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
}

// ProxyCache stores and serves cached upstream responses keyed by method, host,
// and path. It supports automatic TTL expiration, hit-count limits, gzip/brotli
// pre-compression, and per-path cache rules. Create one with NewProxyCache or
// let the server provision one automatically via Server.SetProxyCache.
type ProxyCache struct {
	entries      *alosmap.Map
	config       atomic.Pointer[ProxyCacheConfig]
	totalBytes   atomic.Int64
	totalEntries atomic.Int64
	totalHits    atomic.Uint64
	totalMisses  atomic.Uint64
	stopCh       chan struct{}
	gzipPool     sync.Pool

	// evicting single-flights eviction: an over-limit insert only spawns an
	// eviction goroutine if no eviction is already running. Without this, a
	// burst of distinct over-limit inserts each spawns its own full
	// Range+sort pass (O(N log N)), piling concurrent CPU-bound goroutines
	// (DoS). The running pass loops until under all limits, and any inserts
	// landing mid-pass re-trigger once it clears the flag.
	evicting atomic.Bool

	// evictionPasses counts completed eviction goroutine launches. Under
	// single-flight this grows by at most one per drain cycle, not once per
	// over-limit insert; it is the observable invariant the H8 test asserts.
	evictionPasses atomic.Uint64
}

func NewProxyCache(cfg ProxyCacheConfig) *ProxyCache {
	if cfg.CompressLevel < 1 || cfg.CompressLevel > 9 {
		cfg.CompressLevel = 6
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

	pc := &ProxyCache{
		entries: alosmap.New(alosmap.WithCapacity(10000), alosmap.WithoutCleanup()),
		stopCh:  make(chan struct{}),
	}
	level := cfg.CompressLevel
	pc.gzipPool = sync.Pool{
		New: func() any {
			w, _ := gzip.NewWriterLevel(io.Discard, level)
			return w
		},
	}
	pc.config.Store(&cfg)
	go pc.evictLoop()
	return pc
}

func (pc *ProxyCache) UpdateConfig(cfg ProxyCacheConfig) {
	if cfg.CompressLevel < 1 || cfg.CompressLevel > 9 {
		cfg.CompressLevel = 6
	}
	if cfg.CompressMinLen <= 0 {
		cfg.CompressMinLen = 512
	}
	if cfg.DefaultMaxAge <= 0 {
		cfg.DefaultMaxAge = 5 * time.Minute
	}
	pc.config.Store(&cfg)
}

func (pc *ProxyCache) Stop() {
	select {
	case <-pc.stopCh:
	default:
		close(pc.stopCh)
	}
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

func splitHeaderTokens(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := parts[:0]
	for _, part := range parts {
		trimmed := ToLowerASCII(trimASCIISpace(part))
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
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
	if statusCode < 200 || statusCode >= 400 {
		if statusCode != 301 && statusCode != 308 {
			return 0, false
		}
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

func (pc *ProxyCache) Get(method, host, path string, req *Request) (*cacheEntry, bool) {
	key := pc.buildKey(method, host, path)
	v, ok := pc.entries.Load(alosmap.S(key))
	if !ok {
		pc.totalMisses.Add(1)
		return nil, false
	}
	entry := v.(*cacheEntry)
	if !entry.manual && !proxyCacheRequestAllowed(req) {
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
		pc.entries.Delete(alosmap.S(key))
		pc.totalBytes.Add(-int64(entry.bodyLen) - int64(entry.gzipLen))
		pc.totalEntries.Add(-1)
		pc.totalMisses.Add(1)
		return nil, false
	}

	entry.hits.Add(1)
	pc.totalHits.Add(1)

	if entry.maxHits > 0 && entry.hits.Load() >= entry.maxHits {
		pc.entries.Delete(alosmap.S(key))
		pc.totalBytes.Add(-int64(entry.bodyLen) - int64(entry.gzipLen))
		pc.totalEntries.Add(-1)
	}

	return entry, true
}

func (pc *ProxyCache) Put(method, host, path string, statusCode int, headers [][2]string, contentType string, body []byte) {
	cfg := pc.config.Load()
	ttl, ok := pc.shouldCache(cfg, method, path, statusCode)
	if !ok {
		return
	}
	pc.putEntry(cfg, method, host, path, statusCode, headers, contentType, body, ttl, 0, cfg.PreCompress, -1, false)
}

func (pc *ProxyCache) PutManual(method, host, path string, statusCode int, headers [][2]string, contentType string, body []byte, ttl time.Duration, maxHits uint64, preCompress bool, compressMinLen int) {
	cfg := pc.config.Load()
	if cfg.MaxEntrySize > 0 && int64(len(body)) > cfg.MaxEntrySize {
		return
	}
	pc.putEntry(cfg, method, host, path, statusCode, headers, contentType, body, ttl, maxHits, preCompress, compressMinLen, true)
}

func (pc *ProxyCache) putEntry(cfg *ProxyCacheConfig, method, host, path string, statusCode int, headers [][2]string, contentType string, body []byte, ttl time.Duration, maxHits uint64, preCompress bool, compressMinLen int, manual bool) {
	bodyLen := int64(len(body))
	if cfg.MaxEntrySize > 0 && bodyLen > cfg.MaxEntrySize {
		return
	}

	if cfg.MaxEntries > 0 && pc.totalEntries.Load() >= cfg.MaxEntries {
		pc.triggerEviction()
		return
	}

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

	needsDecompress, backendEncoding := detectBackendEncoding(headers)
	if needsDecompress {
		raw, err := decompressBody(bodyCopy, backendEncoding)
		if err == nil {
			entry.body = raw
			entry.bodyLen = int32(len(raw))
			bodyLen = int64(len(raw))
			entry.headers = removeContentEncoding(entry.headers)
		}
	}

	minLen := cfg.CompressMinLen
	if compressMinLen > 0 {
		minLen = compressMinLen
	}
	if preCompress && bodyLen >= int64(minLen) && isCompressibleType(contentType) {
		gz := pc.compressGzip(entry.body)
		if len(gz) > 0 && len(gz) < len(entry.body) {
			entry.gzipBody = gz
			entry.gzipLen = int32(len(gz))
			bodyLen += int64(len(gz))
		}
	}

	key := pc.buildKey(method, host, path)

	if v, exists := pc.entries.Load(alosmap.S(key)); exists {
		old := v.(*cacheEntry)
		pc.totalBytes.Add(-int64(old.bodyLen) - int64(old.gzipLen))
	} else {
		pc.totalEntries.Add(1)
	}

	pc.entries.Store(alosmap.S(key), entry)
	pc.totalBytes.Add(bodyLen)

	if cfg.MaxTotalBytes > 0 && pc.totalBytes.Load() > cfg.MaxTotalBytes {
		pc.triggerEviction()
	}
}

func (pc *ProxyCache) Purge(method, host, path string) bool {
	key := pc.buildKey(method, host, path)
	if v, ok := pc.entries.Load(alosmap.S(key)); ok {
		entry := v.(*cacheEntry)
		pc.entries.Delete(alosmap.S(key))
		pc.totalBytes.Add(-int64(entry.bodyLen) - int64(entry.gzipLen))
		pc.totalEntries.Add(-1)
		return true
	}
	return false
}

func (pc *ProxyCache) PurgeAll() {
	pc.entries.Clear()
	pc.totalBytes.Store(0)
	pc.totalEntries.Store(0)
}

func (pc *ProxyCache) PurgeDomain(domain string) int64 {
	domain = normalizeCertDomain(domain)
	prefix1 := "GET|" + domain + "|"
	prefix2 := "HEAD|" + domain + "|"
	var purged int64
	pc.entries.Range(func(key alosmap.Key, val any) bool {
		entry := val.(*cacheEntry)
		keyStr := key.StringVal()
		if hasPrefix(keyStr, prefix1) || hasPrefix(keyStr, prefix2) {
			pc.entries.Delete(key)
			pc.totalBytes.Add(-int64(entry.bodyLen) - int64(entry.gzipLen))
			pc.totalEntries.Add(-1)
			purged++
		}
		return true
	})
	return purged
}

func (pc *ProxyCache) Stats() (entries int64, totalBytes int64, hits uint64, misses uint64) {
	return pc.totalEntries.Load(), pc.totalBytes.Load(), pc.totalHits.Load(), pc.totalMisses.Load()
}

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

	if entry.gzipLen > 0 && acceptsGzip(req.Header("accept-encoding")) {
		resp.SetHeaderUnsafe("content-encoding", "gzip")
		resp.SetHeaderUnsafe("vary", "Accept-Encoding")
		resp.SetBody(entry.gzipBody)
		return
	}

	resp.SetBody(entry.body)
}

func (pc *ProxyCache) compressGzip(data []byte) []byte {
	bp := LargeBufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	w := newBytesWriter(&buf)
	gw := pc.gzipPool.Get().(*gzip.Writer)
	gw.Reset(w)
	gw.Write(data)
	gw.Close()
	pc.gzipPool.Put(gw)
	w.buf = nil
	bytesWriterPool.Put(w)
	result := make([]byte, len(buf))
	copy(result, buf)
	*bp = buf[:0]
	LargeBufPool.Put(bp)
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
	now := CoarseNanotime()
	pc.entries.Range(func(key alosmap.Key, val any) bool {
		entry := val.(*cacheEntry)
		if now > entry.expiresAt {
			pc.entries.Delete(key)
			pc.totalBytes.Add(-int64(entry.bodyLen) - int64(entry.gzipLen))
			pc.totalEntries.Add(-1)
		}
		return true
	})
}

// triggerEviction starts a single background eviction pass if one is not
// already running. The atomic CompareAndSwap guarantees at most one eviction
// goroutine exists at a time, so a burst of concurrent over-limit inserts can
// no longer amplify into a pile of concurrent O(N log N) passes. Inserts that
// race in while a pass runs are absorbed by that pass's drain loop, or
// re-trigger a fresh pass after the flag clears.
func (pc *ProxyCache) triggerEviction() {
	if !pc.evicting.CompareAndSwap(false, true) {
		return
	}
	go pc.evictOldest()
}

func (pc *ProxyCache) evictOldest() {
	defer pc.evicting.Store(false)
	pc.evictionPasses.Add(1)

	// Drain until the cache is under both limits. Looping inside the single
	// guarded pass means we converge even if more entries are inserted while
	// evicting, rather than relying on additional goroutines.
	for {
		cfg := pc.config.Load()

		overEntries := cfg.MaxEntries > 0 && pc.totalEntries.Load() > cfg.MaxEntries
		overBytes := cfg.MaxTotalBytes > 0 && pc.totalBytes.Load() > cfg.MaxTotalBytes
		if !overEntries && !overBytes {
			return
		}

		byteTarget := cfg.MaxTotalBytes * 90 / 100
		entryTarget := cfg.MaxEntries * 90 / 100

		type candidate struct {
			key       alosmap.Key
			createdAt int64
			size      int64
		}
		candidates := make([]candidate, 0, 64)
		pc.entries.Range(func(key alosmap.Key, val any) bool {
			entry := val.(*cacheEntry)
			candidates = append(candidates, candidate{
				key:       key,
				createdAt: entry.createdAt,
				size:      int64(entry.bodyLen) + int64(entry.gzipLen),
			})
			return true
		})

		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].createdAt < candidates[j].createdAt
		})

		for _, c := range candidates {
			bytesOK := cfg.MaxTotalBytes <= 0 || pc.totalBytes.Load() <= byteTarget
			entriesOK := cfg.MaxEntries <= 0 || pc.totalEntries.Load() <= entryTarget
			if bytesOK && entriesOK {
				break
			}
			if _, ok := pc.entries.Delete(c.key); ok {
				pc.totalBytes.Add(-c.size)
				pc.totalEntries.Add(-1)
			}
		}

		// Snapshot of candidates is stale once we loop; re-scan to converge
		// against concurrent inserts. Bounded by the under-limit check above.
		if len(candidates) == 0 {
			return
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

func decompressBody(data []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "gzip":
		return decompressGzip(data)
	case "deflate":
		return decompressDeflate(data)
	case "br":
		return decompressBrotli(data)
	}
	return data, nil
}

func decompressGzip(data []byte) ([]byte, error) {
	const maxDecompressedSize = 64 << 20
	r, err := gzip.NewReader(newBytesReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	bp := LargeBufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	tmp := make([]byte, 8192)
	for {
		n, rerr := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) > maxDecompressedSize {
				*bp = buf[:0]
				LargeBufPool.Put(bp)
				return nil, ErrBodyTooLarge
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			*bp = buf[:0]
			LargeBufPool.Put(bp)
			return nil, rerr
		}
	}
	result := make([]byte, len(buf))
	copy(result, buf)
	*bp = buf[:0]
	LargeBufPool.Put(bp)
	return result, nil
}

func decompressDeflate(data []byte) ([]byte, error) {
	const maxDecompressedSize = 64 << 20
	r := flate.NewReader(newBytesReader(data))
	defer r.Close()
	bp := LargeBufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	tmp := make([]byte, 8192)
	for {
		n, rerr := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) > maxDecompressedSize {
				*bp = buf[:0]
				LargeBufPool.Put(bp)
				return nil, ErrBodyTooLarge
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			*bp = buf[:0]
			LargeBufPool.Put(bp)
			return nil, rerr
		}
	}
	result := make([]byte, len(buf))
	copy(result, buf)
	*bp = buf[:0]
	LargeBufPool.Put(bp)
	return result, nil
}

func decompressBrotli(data []byte) ([]byte, error) {
	const maxDecompressedSize = 64 << 20
	r := brotli.NewReader(newBytesReader(data))
	bp := LargeBufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	tmp := make([]byte, 8192)
	for {
		n, rerr := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) > maxDecompressedSize {
				*bp = buf[:0]
				LargeBufPool.Put(bp)
				return nil, ErrBodyTooLarge
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			*bp = buf[:0]
			LargeBufPool.Put(bp)
			return nil, rerr
		}
	}
	result := make([]byte, len(buf))
	copy(result, buf)
	*bp = buf[:0]
	LargeBufPool.Put(bp)
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

func acceptsGzip(accept string) bool {
	if accept == "" {
		return false
	}
	for len(accept) > 0 {
		end := indexByte(accept, ',')
		var token string
		if end < 0 {
			token = accept
			accept = ""
		} else {
			token = accept[:end]
			accept = accept[end+1:]
		}
		token = trimASCIISpace(token)
		qDisabled := false
		if semi := indexByte(token, ';'); semi >= 0 {
			params := trimASCIISpace(token[semi+1:])
			token = token[:semi]
			if len(params) >= 3 && (params[0] == 'q' || params[0] == 'Q') && params[1] == '=' {
				qDisabled = params[2] == '0' && (len(params) == 3 || params[3] == ',' || params[3] == ' ')
			}
		}
		if trimASCIISpace(token) == "gzip" {
			return !qDisabled
		}
	}
	return false
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
