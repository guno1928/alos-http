package core

import (
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// LoadBalancerType selects the load balancing strategy used by the reverse
// proxy when distributing requests across multiple backends.
//
// Available strategies:
//   - LBRoundRobin: cycles through backends in order (default)
//   - LBWeightedRR: round-robin weighted by BackendConfig.Weight
//   - LBLeastConn: sends to the backend with the fewest active connections
//   - LBIPHash: hashes the client IP to a consistent backend
//   - LBRandom: picks a random healthy backend
type LoadBalancerType uint8

const (
	LBRoundRobin LoadBalancerType = iota
	LBWeightedRR
	LBLeastConn
	LBIPHash
	LBRandom
)

// BackendConfig defines a single upstream backend server that the reverse proxy
// will forward traffic to. Addr accepts bare host:port, or full URLs with
// http:// or https:// schemes. When an https:// URL is given, TLS is enabled
// automatically and defaults to port 443 if no port is specified. Weight controls
// the proportion of traffic this backend receives when using LBWeightedRR. If you
// need to connect to backends with self-signed certs (e.g. in development), set
// TLSSkipVerify to true.
//
//	// Plain HTTP backend on port 8080
//	core.BackendConfig{Addr: "10.0.0.10:8080", Weight: 1}
//
//	// HTTPS backend with auto-detected TLS
//	core.BackendConfig{Addr: "https://api-internal.example.com"}
//
//	// Dev backend with self-signed cert
//	core.BackendConfig{Addr: "https://localhost:9090", TLSSkipVerify: true}
type BackendConfig struct {
	Addr          string
	Weight        int
	TLS           bool
	TLSSkipVerify bool
}

// HealthCheckConfig configures active health checking for backends in a domain.
// When Enabled is true, the proxy periodically sends HTTP GET requests to Path on
// each backend and marks them healthy or unhealthy based on the response. Backends
// that fail FailThreshold consecutive checks are taken out of rotation. They are
// re-added after SuccessThreshold consecutive passing checks.
//
// All fields have sensible defaults when left at zero values:
//
//   - Interval defaults to 10s
//
//   - Timeout defaults to 5s
//
//   - FailThreshold defaults to 3
//
//   - SuccessThreshold defaults to 2
//
//     core.HealthCheckConfig{
//     Enabled:          true,
//     Path:             "/healthz",
//     Interval:         5 * time.Second,
//     Timeout:          2 * time.Second,
//     FailThreshold:    3,
//     SuccessThreshold: 2,
//     }
type HealthCheckConfig struct {
	Enabled          bool
	Path             string
	Interval         time.Duration
	Timeout          time.Duration
	FailThreshold    int
	SuccessThreshold int
}

// ProxyError holds context about a failed backend request. It is passed to
// the OnError callback registered with Server.OnProxyError. Domain and Backend
// identify which upstream was tried, Attempt indicates which retry this was
// (starting at 1), and Err contains the underlying network or timeout error.
//
//	srv.OnProxyError(func(pe core.ProxyError) {
//	    log.Printf("proxy error domain=%s backend=%s attempt=%d err=%v",
//	        pe.Domain, pe.Backend, pe.Attempt, pe.Err)
//	})
type ProxyError struct {
	Domain     string
	Backend    string
	ClientAddr string
	Method     string
	Path       string
	Attempt    int
	Err        error
}

type ProxyErrorFunc func(ProxyError)

// ProxyRequest is passed to the OnRequest callback before the request is
// forwarded to the backend. You can inspect or modify Headers, Host, and Path
// to rewrite the outgoing request. Returning false from the callback rejects
// the request with a 502 Bad Gateway.
//
// Common use cases:
//
//   - Inject authentication headers for internal backends
//
//   - Rewrite paths (e.g. strip a /api prefix)
//
//   - Block requests based on client IP or headers
//
//     srv.OnProxyRequest(func(pr *core.ProxyRequest) bool {
//     // Add internal auth header
//     pr.Headers = append(pr.Headers, [2]string{"X-Internal-Auth", "secret"})
//
//     // Strip /api prefix
//     if len(pr.Path) > 4 && pr.Path[:4] == "/api" {
//     pr.Path = pr.Path[4:]
//     }
//     return true
//     })
type ProxyRequest struct {
	Domain     string
	Backend    string
	ClientAddr string
	Method     string
	Path       string
	Headers    [][2]string
	Host       string
}

type ProxyInterceptFunc func(pr *ProxyRequest) bool

// ProxyResponse is passed to the OnResponse callback after the backend replies
// but before the response is sent to the client. You can modify Headers and
// StatusCode to transform what the client receives. Use CacheThis to opt this
// response into the proxy cache with a specific TTL and hit limit, or DontCache
// to explicitly skip caching even if a cache rule would match.
//
//	srv.OnProxyResponse(func(pr *core.ProxyResponse) {
//	    // Inject a custom header
//	    pr.Headers = append(pr.Headers, [2]string{"X-Proxy", "alos"})
//
//	    // Cache successful API responses for 5 minutes
//	    if pr.StatusCode == 200 && len(pr.Path) > 4 && pr.Path[:4] == "/api" {
//	        pr.CacheThis(5*time.Minute, 0)
//	    }
//
//	    // Never cache error responses
//	    if pr.StatusCode >= 400 {
//	        pr.DontCache()
//	    }
//	})
type ProxyResponse struct {
	Domain     string
	Backend    string
	ClientAddr string
	Method     string
	Path       string
	StatusCode int
	Headers    [][2]string

	cacheRequested   bool
	cacheTTL         time.Duration
	cacheMaxHits     uint64
	cacheCompress    bool
	cacheCompressMin int
}

type CacheOption func(*cacheOpts)

type cacheOpts struct {
	preCompress    bool
	compressMinLen int
}

// WithPreCompress controls whether a pre-compressed gzip copy of the response
// body is stored in the cache alongside the original. When enabled, clients that
// send Accept-Encoding: gzip receive the pre-compressed copy without any runtime
// compression overhead. Defaults to true.
//
//	pr.CacheThis(5*time.Minute, 0, core.WithPreCompress(false))
func WithPreCompress(on bool) CacheOption {
	return func(o *cacheOpts) { o.preCompress = on }
}

// WithCompressMinLen sets the minimum response body size in bytes before
// pre-compression kicks in. Responses smaller than this threshold are stored
// uncompressed even when WithPreCompress is true, since gzip overhead can make
// small payloads larger. Defaults to the value from ProxyCacheConfig.CompressMinLen
// (512 bytes with DefaultProxyCacheConfig).
//
//	pr.CacheThis(5*time.Minute, 0, core.WithCompressMinLen(1024))
func WithCompressMinLen(n int) CacheOption {
	return func(o *cacheOpts) { o.compressMinLen = n }
}

// CacheThis marks this response for caching with the given TTL. The entry is
// evicted after ttl elapses or after maxHits cache hits, whichever comes first.
// Pass 0 for maxHits to keep the entry alive until TTL expiration only.
//
// Optional CacheOption values control gzip pre-compression of the cached body.
// By default, a gzip copy is stored for responses >= 512 bytes.
//
//	// Cache for 10 minutes, unlimited hits
//	pr.CacheThis(10*time.Minute, 0)
//
//	// Cache for 1 hour, evict after 1000 hits
//	pr.CacheThis(time.Hour, 1000)
//
//	// Cache without pre-compression
//	pr.CacheThis(5*time.Minute, 0, core.WithPreCompress(false))
func (pr *ProxyResponse) CacheThis(ttl time.Duration, maxHits uint64, opts ...CacheOption) {
	o := cacheOpts{preCompress: true, compressMinLen: -1}
	for _, fn := range opts {
		fn(&o)
	}
	pr.cacheRequested = true
	pr.cacheTTL = ttl
	pr.cacheMaxHits = maxHits
	pr.cacheCompress = o.preCompress
	pr.cacheCompressMin = o.compressMinLen
}

// DontCache prevents this specific response from being cached, overriding any
// cache rules that would otherwise match. Call this in OnResponse for responses
// that should never be stored (e.g. user-specific data, error pages).
//
//	if pr.StatusCode >= 400 {
//	    pr.DontCache()
//	}
func (pr *ProxyResponse) DontCache() {
	pr.cacheRequested = false
	pr.cacheTTL = 0
}

type ProxyResponseFunc func(pr *ProxyResponse)

// DomainConfig holds the full configuration for a proxied domain, including its
// backends, load balancer strategy, timeouts, connection pooling, and health
// checks. Pass this to Server.AddProxyDomain to register a domain.
//
// Timeouts and pool sizes default to sensible values when left at zero:
//
//   - ConnectTimeout: 10s
//
//   - ReadTimeout: 30s
//
//   - WriteTimeout: 10s
//
//   - MaxRetries: 2
//
//   - MaxIdleConns: 32
//
//   - IdleTimeout: 90s
//
//   - Backend weights: 1
//
//     srv.AddProxyDomain(core.DomainConfig{
//     Domain: "api.example.com",
//     Backends: []core.BackendConfig{
//     {Addr: "10.0.0.10:8080", Weight: 3},
//     {Addr: "10.0.0.11:8080", Weight: 1},
//     },
//     LoadBalancer:   core.LBWeightedRR,
//     ConnectTimeout: 5 * time.Second,
//     ReadTimeout:    15 * time.Second,
//     MaxRetries:     3,
//     MaxIdleConns:   64,
//     HealthCheck: core.HealthCheckConfig{
//     Enabled:       true,
//     Path:          "/healthz",
//     Interval:      5 * time.Second,
//     FailThreshold: 3,
//     },
//     })
type DomainConfig struct {
	Domain         string
	Backends       []BackendConfig
	LoadBalancer   LoadBalancerType
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	MaxRetries     int
	MaxIdleConns   int
	IdleTimeout    time.Duration
	HealthCheck    HealthCheckConfig
	HostHeader     string
	PreserveHost   bool
}

func (dc *DomainConfig) normalize() {
	if dc.ConnectTimeout <= 0 {
		dc.ConnectTimeout = 10 * time.Second
	}
	if dc.ReadTimeout <= 0 {
		dc.ReadTimeout = 30 * time.Second
	}
	if dc.WriteTimeout <= 0 {
		dc.WriteTimeout = 10 * time.Second
	}
	if dc.MaxRetries <= 0 {
		dc.MaxRetries = 2
	}
	if dc.MaxIdleConns <= 0 {
		dc.MaxIdleConns = 32
	}
	if dc.IdleTimeout <= 0 {
		dc.IdleTimeout = 90 * time.Second
	}
	for i := range dc.Backends {
		if dc.Backends[i].Weight <= 0 {
			dc.Backends[i].Weight = 1
		}
		normalizeBackendAddr(&dc.Backends[i])
	}
	if dc.HealthCheck.Enabled {
		if dc.HealthCheck.Interval <= 0 {
			dc.HealthCheck.Interval = 10 * time.Second
		}
		if dc.HealthCheck.Timeout <= 0 {
			dc.HealthCheck.Timeout = 5 * time.Second
		}
		if dc.HealthCheck.FailThreshold <= 0 {
			dc.HealthCheck.FailThreshold = 3
		}
		if dc.HealthCheck.SuccessThreshold <= 0 {
			dc.HealthCheck.SuccessThreshold = 2
		}
	}
}

func normalizeBackendAddr(bc *BackendConfig) {
	addr := bc.Addr
	switch {
	case strings.HasPrefix(addr, "https://"):
		addr = strings.TrimPrefix(addr, "https://")
		if idx := strings.IndexByte(addr, '/'); idx >= 0 {
			addr = addr[:idx]
		}
		bc.TLS = true
		if !strings.Contains(addr, ":") {
			addr += ":443"
		}
	case strings.HasPrefix(addr, "http://"):
		addr = strings.TrimPrefix(addr, "http://")
		if idx := strings.IndexByte(addr, '/'); idx >= 0 {
			addr = addr[:idx]
		}
		if !strings.Contains(addr, ":") {
			addr += ":80"
		}
	default:
	}
	bc.Addr = addr
}

type backend struct {
	Addr          string
	Weight        int
	TLS           bool
	TLSSkipVerify bool
	Healthy       atomic.Bool
	ActiveConns   atomic.Int64
	pool          *connPool
}

type domainState struct {
	config   DomainConfig
	backends []*backend
	balancer loadBalancer
	health   *healthChecker
}

type proxySnapshot struct {
	domains map[string]*domainState
}

// ProxyEngine is the core reverse-proxy component that routes incoming TLS
// connections to upstream backends based on the SNI domain. It manages connection
// pools, load balancing, health checking, and optional response caching across
// all registered domains.
//
// Hook into the proxy lifecycle with:
//   - OnError: called when a backend request fails (connection error, timeout)
//   - OnRequest: called before forwarding; modify headers/path or reject
//   - OnResponse: called after the backend replies; modify headers/status or cache
//
// ProxyEngine is created internally by the Server. Use Server.OnProxyError,
// Server.OnProxyRequest, and Server.OnProxyResponse to register callbacks.
type ProxyEngine struct {
	snapshot   atomic.Pointer[proxySnapshot]
	mu         sync.Mutex
	stopCh     chan struct{}
	stopOnce   sync.Once
	OnError    ProxyErrorFunc
	OnRequest  ProxyInterceptFunc
	OnResponse ProxyResponseFunc
	Cache      *ProxyCache
}

// NewProxyEngine creates a ProxyEngine with an empty domain table. This is called
// internally by Server.New — you typically don't need to call it directly.
func NewProxyEngine() *ProxyEngine {
	pe := &ProxyEngine{
		stopCh: make(chan struct{}),
	}
	pe.snapshot.Store(&proxySnapshot{domains: make(map[string]*domainState)})
	return pe
}

// AddDomain registers or replaces a domain configuration. If a domain with the
// same name already exists, its health checkers and connection pools are shut down
// before the new config takes effect. Safe to call at runtime while the server is
// handling traffic — the swap is atomic.
//
//	pe.AddDomain(core.DomainConfig{
//	    Domain:   "api.example.com",
//	    Backends: []core.BackendConfig{{Addr: "10.0.0.10:8080"}},
//	})
func (pe *ProxyEngine) AddDomain(cfg DomainConfig) {
	cfg.Domain = normalizeCertDomain(cfg.Domain)
	if cfg.Domain == "" {
		log.Printf("[PROXY] AddDomain rejected: empty domain name")
		return
	}

	cfg.normalize()

	pe.mu.Lock()
	defer pe.mu.Unlock()

	old := pe.snapshot.Load()

	if prev, ok := old.domains[cfg.Domain]; ok {
		if prev.health != nil {
			prev.health.stop()
		}
		for _, b := range prev.backends {
			if b.pool != nil {
				b.pool.close()
			}
		}
	}

	backends := make([]*backend, len(cfg.Backends))
	for i, bc := range cfg.Backends {
		b := &backend{
			Addr:          bc.Addr,
			Weight:        bc.Weight,
			TLS:           bc.TLS,
			TLSSkipVerify: bc.TLSSkipVerify,
		}
		b.Healthy.Store(true)
		b.pool = newConnPool(bc.Addr, bc.TLS, bc.TLSSkipVerify, cfg.MaxIdleConns, cfg.IdleTimeout, cfg.ConnectTimeout)
		backends[i] = b
	}

	ds := &domainState{
		config:   cfg,
		backends: backends,
		balancer: newBalancer(cfg.LoadBalancer, backends),
	}

	if cfg.HealthCheck.Enabled && len(backends) > 0 {
		ds.health = newHealthChecker(backends, cfg.HealthCheck, pe.stopCh)
		ds.health.start()
	}

	newDomains := make(map[string]*domainState, len(old.domains)+1)
	for k, v := range old.domains {
		newDomains[k] = v
	}
	newDomains[cfg.Domain] = ds
	pe.snapshot.Store(&proxySnapshot{domains: newDomains})

	log.Printf("[PROXY] domain %s configured (%d backends, lb=%d)", cfg.Domain, len(backends), cfg.LoadBalancer)
}

// RemoveDomain removes a domain by name and gracefully shuts down its health
// checkers and connection pools. No-op if the domain doesn't exist. Safe to
// call at runtime.
func (pe *ProxyEngine) RemoveDomain(domain string) {
	domain = normalizeCertDomain(domain)
	pe.mu.Lock()
	defer pe.mu.Unlock()

	old := pe.snapshot.Load()
	prev, ok := old.domains[domain]
	if !ok {
		return
	}

	if prev.health != nil {
		prev.health.stop()
	}
	for _, b := range prev.backends {
		if b.pool != nil {
			b.pool.close()
		}
	}

	newDomains := make(map[string]*domainState, len(old.domains))
	for k, v := range old.domains {
		if k != domain {
			newDomains[k] = v
		}
	}
	pe.snapshot.Store(&proxySnapshot{domains: newDomains})
	log.Printf("[PROXY] domain %s removed", domain)
}

func (pe *ProxyEngine) Lookup(host string) *domainState {
	snap := pe.snapshot.Load()
	return snap.domains[normalizeCertDomain(host)]
}

// Stop shuts down all health checkers and closes all idle backend connections
// across every registered domain. Called automatically by Server.Shutdown.
func (pe *ProxyEngine) Stop() {
	pe.stopOnce.Do(func() {
		close(pe.stopCh)
		if pe.Cache != nil {
			pe.Cache.Stop()
		}
		snap := pe.snapshot.Load()
		for _, ds := range snap.domains {
			if ds.health != nil {
				ds.health.stop()
			}
			for _, b := range ds.backends {
				if b.pool != nil {
					b.pool.close()
				}
			}
		}
	})
}

// ListDomains returns the names of all currently registered proxy domains.
// The order is non-deterministic.
func (pe *ProxyEngine) ListDomains() []string {
	snap := pe.snapshot.Load()
	out := make([]string, 0, len(snap.domains))
	for k := range snap.domains {
		out = append(out, k)
	}
	return out
}
