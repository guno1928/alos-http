package core

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guno1928/alosmap"
)

var timeNow = time.Now

// Config controls every aspect of the ALOS server. Pass it to New; zero values use the defaults applied by New (see DefaultConfig).
//
// Addr is the HTTPS/HTTP listen address; defaults to ":8443".
//
//	Example: Addr: ":443" listens on the standard HTTPS port.
//	Example: Addr: "0.0.0.0:8443" listens on all interfaces.
//
// HTTPAddr is the listen address for the HTTP-to-HTTPS redirect (or plain HTTP routes); defaults to ":80" when Addr uses port 443, otherwise disabled.
//
//	Example: HTTPAddr: ":80" enables the redirect listener.
//	Example: HTTPAddr: "" disables it.
//
// ReadTimeout bounds how long a full request read may take; 0 disables it.
//
//	Example: ReadTimeout: 10 * time.Second.
//
// WriteTimeout bounds how long a response write may take; 0 disables it.
//
//	Example: WriteTimeout: 10 * time.Second.
//
// IdleTimeout is how long an idle keep-alive connection stays open; defaults to 120s.
//
//	Example: IdleTimeout: 30 * time.Second.
//
// HandshakeTimeout is the deadline for the TLS handshake; defaults to 30s.
//
//	Example: HandshakeTimeout: 5 * time.Second.
//
// MaxBodySize rejects request bodies larger than this many bytes; 0 means unlimited.
//
//	Example: MaxBodySize: 10 << 20 caps bodies at 10 MiB.
//	Example: MaxBodySize: 0 allows unlimited bodies.
//
// MaxReadSize caps total bytes read per connection; 0 means unlimited.
//
//	Example: MaxReadSize: 1 << 20.
//
// MaxWriteSize caps total response bytes per connection; 0 means unlimited. Oversized responses are replaced with 500.
//
//	Example: MaxWriteSize: 5 << 20.
//
// MaxHeaderSize is the maximum header block in bytes; defaults to 8192.
//
//	Example: MaxHeaderSize: 16384.
//
// MaxRequestsPerIP caps concurrent in-flight requests per client IP; 0 disables the per-IP limiter.
//
//	Example: MaxRequestsPerIP: 100.
//	Example: MaxRequestsPerIP: 0 disables per-IP limiting.
//
// MaxConcurrentReqs is a server-wide concurrency cap; 0 means unlimited. Excess requests get 503.
//
//	Example: MaxConcurrentReqs: 10000.
//
// TLSCertFile and TLSKeyFile point to a PEM certificate/key pair used when Certs and ACME are unset.
//
//	Example: TLSCertFile: "cert.pem", TLSKeyFile: "key.pem".
//	Example: TLSCertFile: "" generates a self-signed localhost certificate.
//
// Certs lists per-domain certificate configs (manual, self-signed, or ACME).
//
//	Example: Certs: []CertConfig{{Domain: "example.com", Source: CertManual, CertFile: "c.pem", KeyFile: "k.pem"}}.
//
// DefaultDomain selects which loaded certificate to use when SNI does not match.
//
//	Example: DefaultDomain: "example.com".
//
// ACME enables automatic Let's Encrypt certificates.
//
//	Example: ACME: &ACMEConfig{Email: "admin@example.com", Domains: []string{"example.com"}}.
//	Example: ACME: nil disables ACME.
//
// WorkerCount sets the number of I/O workers; 0 auto-sizes from GOMAXPROCS.
//
//	Example: WorkerCount: 8.
//	Example: WorkerCount: 0 auto-sizes.
//
// ConnBandwidth rate-limits each connection.
//
//	Example: ConnBandwidth: BandwidthConfig{MaxUploadRate: 1 << 20, MaxDownloadRate: 1 << 20}.
//
// GlobalBandwidth rate-limits all connections in aggregate.
//
//	Example: GlobalBandwidth: BandwidthConfig{MaxDownloadRate: 100 << 20}.
//
// Listeners is the number of SO_REUSEPORT listeners (Linux/amd64; 1 elsewhere); 0 auto-sizes.
//
//	Example: Listeners: 4.
//	Example: Listeners: 0 auto-sizes.
//
// ServerName is the value sent in the Server header; defaults to "ALOS".
//
//	Example: ServerName: "my-api".
//
// TrustedProxies lists peer IPs/CIDRs whose X-Forwarded-For / X-Real-IP headers are trusted; ignored when ProxyMode is true.
//
//	Example: TrustedProxies: []string{"10.0.0.0/8", "192.168.1.1"}.
//
// EnableCompress turns on automatic gzip/deflate response compression.
//
//	Example: EnableCompress: true.
//
// CompressLevel is the compression level 1–9 used when EnableCompress is set; defaults to 6.
//
//	Example: CompressLevel: 9.
//
// CompressMinSize is the minimum body size in bytes to compress; defaults to 256.
//
//	Example: CompressMinSize: 1024.
//
// Debug enables verbose internal logging.
//
//	Example: Debug: true.
//
// LogRequests logs every accepted and closed connection; defaults to true.
//
//	Example: LogRequests: false silences per-connection logs.
//
// ShutdownTimeout bounds graceful shutdown; defaults to 30s.
//
//	Example: ShutdownTimeout: 10 * time.Second.
//
// PlainHTTP serves plain HTTP/1.1 on Addr with no TLS.
//
//	Example: PlainHTTP: true.
//
// DisableHTTP2 serves only HTTP/1.1 over TLS, never negotiating HTTP/2.
//
//	Example: DisableHTTP2: true.
//
// ProxyMode trusts forwarding headers from all peers and rewrites RemoteAddr to the real client IP; only enable behind a trusted reverse proxy. When true, TrustedProxies is ignored.
//
//	Example: ProxyMode: true.
//
// WebSocketOriginMode controls Origin validation for WebSocket upgrades; defaults to WSOriginSameOrigin.
//
//	Example: WebSocketOriginMode: WSOriginAllowlist.
//
// WebSocketAllowedOrigins lists origins accepted when WebSocketOriginMode is WSOriginAllowlist.
//
//	Example: WebSocketAllowedOrigins: []string{"https://example.com"}.
type Config struct {
	Addr             string
	HTTPAddr         string
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	IdleTimeout      time.Duration
	HandshakeTimeout time.Duration

	MaxBodySize       int64
	MaxReadSize       int64
	MaxWriteSize      int64
	MaxHeaderSize     int
	MaxRequestsPerIP  int64
	MaxConcurrentReqs int64

	TLSCertFile   string
	TLSKeyFile    string
	Certs         []CertConfig
	DefaultDomain string
	ACME          *ACMEConfig
	WorkerCount   int

	ConnBandwidth   BandwidthConfig
	GlobalBandwidth BandwidthConfig
	Listeners       int

	ServerName      string
	TrustedProxies  []string
	EnableCompress  bool
	CompressLevel   int
	CompressMinSize int

	Debug           bool
	LogRequests     bool
	ShutdownTimeout time.Duration
	PlainHTTP       bool
	DisableHTTP2    bool
	ProxyMode       bool

	WebSocketOriginMode     WSOriginMode
	WebSocketAllowedOrigins []string
}

// DefaultConfig returns a Config with sensible defaults: it listens on ":8443" with a 120s idle timeout, 30s handshake and shutdown timeouts, an 8 KiB header limit, gzip level 6, and request logging enabled.
func DefaultConfig() Config {
	return Config{
		Addr:              ":8443",
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
		HandshakeTimeout:  30 * time.Second,
		MaxBodySize:       0,
		MaxReadSize:       0,
		MaxWriteSize:      0,
		MaxHeaderSize:     8192,
		MaxConcurrentReqs: 0,
		ServerName:        "ALOS",
		CompressLevel:     6,
		CompressMinSize:   256,
		WorkerCount:       0,
		Listeners:         1,
		Debug:             false,
		LogRequests:       true,
		ShutdownTimeout:   30 * time.Second,
	}
}

func newPerIPRequestLimiter() *perIPRequestLimiter {
	l := &perIPRequestLimiter{m: alosmap.New(alosmap.WithoutCleanup())}
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			func() {
				defer func() {
					if r := recover(); r != nil {
						Dbg("[iplimiter sweep] recovered panic: %v", r)
					}
				}()
				l.m.Range(func(key alosmap.Key, value any) bool {
					if c, ok := value.(*ipReqCounter); ok && c.n.Load() <= 0 {
						l.m.Delete(key)
					}
					return true
				})
			}()
		}
	}()
	return l
}

func (l *perIPRequestLimiter) acquire(ip string, limit int64) bool {
	if l == nil || ip == "" || limit <= 0 {
		return true
	}
	v, ok := l.m.Load(alosmap.S(ip))
	if !ok {
		v, _ = l.m.LoadOrStore(alosmap.S(ip), &ipReqCounter{})
	}
	c := v.(*ipReqCounter)
	for {
		cur := c.n.Load()
		if cur >= limit {
			return false
		}
		if c.n.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (l *perIPRequestLimiter) release(ip string) {
	if l == nil || ip == "" {
		return
	}
	if v, ok := l.m.Load(alosmap.S(ip)); ok {
		c := v.(*ipReqCounter)
		if c.n.Add(-1) < 0 {
			c.n.Add(1)
		}
	}
}

// Server is the main entry point. Create one with New, register routes on its Router, then call ListenAndServeTLS (or ListenAndServe). It manages its own TLS 1.3/1.2 stack, optional HTTP/2 and HTTP/3, connection pooling, reverse proxy, CORS, rate limiting, and ACME. All exported methods are safe for concurrent use.
//
// Router holds the route table; register handlers on it.
//
//	Example: s.Router.GET("/", handler)
//
// CORS is the active CORS engine, or nil until SetCORS is called.
// RateLimit is the active rate-limit engine, or nil until a rate-limit rule or callback is set.
type Server struct {
	debug       atomic.Bool
	logRequests atomic.Bool

	config          Config
	caps            Capabilities
	capsLogOnce     sync.Once
	Router          *Router
	CORS            *CORSEngine
	RateLimit       *RateLimitEngine
	certStore       *CertStore
	fallbackTLS     atomic.Pointer[tls.Config]
	proxy           atomic.Pointer[ProxyEngine]
	httpRouter      *HTTPRouter
	acme            *acmeIntegration
	listeners       []net.Listener
	done            chan struct{}
	tlsRuntimeOnce  sync.Once
	x25519Pool      *x25519KeyPool
	activeConns     atomic.Int64
	shuttingDown    atomic.Bool
	drainDone       chan struct{}
	drainOnce       sync.Once
	shutdownOnce    sync.Once
	connLimiter     *ConnectionLimiter
	globalLimiter   *GlobalLimiter
	activeReqs      atomic.Int64
	fastDispatch    atomic.Bool
	plainRootFast   plainRootFastResponse
	h2RootFast      h2RootFastResponse
	trustedProxies  trustedProxyMatcher
	perIPLimiter    *perIPRequestLimiter
	trackedConnMu   sync.Mutex
	trackedConns    map[*trackedHandoffConn]struct{}
	onRequestHooks  []func(*Request, *Response) bool
	onResponseHooks []func(*Request, *Response)
}

type trackedHandoffConn struct {
	net.Conn
	server    *Server
	closeOnce sync.Once
}

type ipReqCounter struct {
	n atomic.Int64
}

type perIPRequestLimiter struct {
	m *alosmap.Map
}

type plainRootFastResponse struct {
	enabled         bool
	getKeepAlive    []byte
	getClose        []byte
	getKeepAliveTLS []byte
	getCloseTLS     []byte
}

type h2RootFastResponse struct {
	enabled       bool
	headerPayload []byte
	body          []byte
	framed        []byte
	dataFrameOff  int
	tlsInner      []byte
	headerIDOff   int
	dataIDOff     int
}

// New creates a Server from the given Config, applying defaults to zero-valued fields; called with no arguments it uses DefaultConfig. The returned server is ready for route registration.
//
// Example: s := New()
// Example: s := New(Config{Addr: ":443", Listeners: 4})
// Example: s := New(Config{Addr: ":80", PlainHTTP: true})
func New(configs ...Config) *Server {
	var cfg Config
	if len(configs) > 0 {
		cfg = configs[0]
	} else {
		cfg = DefaultConfig()
	}
	if cfg.Addr == "" {
		cfg.Addr = ":8443"
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 120 * time.Second
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 30 * time.Second
	}
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = 30 * time.Second
	}
	if cfg.MaxHeaderSize == 0 {
		cfg.MaxHeaderSize = 8192
	}
	if cfg.ServerName == "" {
		cfg.ServerName = "ALOS"
	}
	if cfg.CompressLevel == 0 {
		cfg.CompressLevel = 6
	}
	if cfg.CompressMinSize == 0 {
		cfg.CompressMinSize = 256
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = autoWorkerCount()
	}
	if cfg.Listeners <= 0 {
		cfg.Listeners = autoListenerCount()
	}

	s := &Server{
		config:    cfg,
		caps:      DetectCapabilities(),
		Router:    NewRouter(),
		certStore: NewCertStore(),
		done:      make(chan struct{}),
		drainDone: make(chan struct{}),
	}
	s.Router.server = s
	if cfg.ProxyMode {
		s.trustedProxies = newTrustedProxyMatcher(nil, true)
	} else if len(cfg.TrustedProxies) > 0 {
		s.trustedProxies = newTrustedProxyMatcher(cfg.TrustedProxies, false)
	}
	if cfg.MaxRequestsPerIP > 0 {
		s.perIPLimiter = newPerIPRequestLimiter()
	}

	s.debug.Store(cfg.Debug)
	s.logRequests.Store(cfg.LogRequests)
	SetDebugFlag(cfg.Debug)

	if cfg.ConnBandwidth.MaxUploadRate > 0 || cfg.ConnBandwidth.MaxDownloadRate > 0 {
		s.connLimiter = NewConnectionLimiter(cfg.ConnBandwidth)
	}
	if cfg.GlobalBandwidth.MaxUploadRate > 0 || cfg.GlobalBandwidth.MaxDownloadRate > 0 {
		s.globalLimiter = NewGlobalLimiter(cfg.GlobalBandwidth)
	}

	return s
}

const autoWorkerCap = 128

func autoWorkerCount() int {
	n := runtime.GOMAXPROCS(0)
	if n < 1 {
		n = 1
	}
	if n > autoWorkerCap {
		n = autoWorkerCap
	}
	return n
}

func autoListenerCount() int {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return 1
	}
	return autoWorkerCount()
}

// NewServer creates a Server listening on addr with otherwise-default configuration; it is shorthand for New(Config{Addr: addr}).
//
// Example: s := NewServer(":443")
// Example: s := NewServer("0.0.0.0:8443")
func NewServer(addr string) *Server {
	return New(Config{Addr: addr})
}

func (s *Server) ensureTLSRuntime() {
	s.tlsRuntimeOnce.Do(func() {
		s.x25519Pool = newX25519KeyPool(x25519KeyPoolSize(s.config))
	})
}

func (s *Server) http2Enabled() bool {
	return !s.config.DisableHTTP2
}

func (s *Server) tlsNextProtos() []string {
	if s.http2Enabled() {
		return []string{"h2", "http/1.1"}
	}
	return []string{"http/1.1"}
}

func (s *Server) negotiateALPN(clientProtos []string) string {
	return NegotiateALPN(clientProtos, s.http2Enabled())
}

// SetDebug toggles verbose internal logging at runtime.
//
// Example: s.SetDebug(true)
// Example: s.SetDebug(false)
func (s *Server) SetDebug(on bool) {
	s.debug.Store(on)
	SetDebugFlag(on)
}

// SetLogRequests toggles per-connection request logging at runtime.
//
// Example: s.SetLogRequests(false)
// Example: s.SetLogRequests(true)
func (s *Server) SetLogRequests(on bool) {
	s.logRequests.Store(on)
}

// IsDebug reports whether verbose internal logging is enabled.
func (s *Server) IsDebug() bool {
	return s.debug.Load()
}

// ListenAndServeTLS starts the HTTPS server using ALOS's built-in TLS 1.3/1.2 stack: it loads certificates (self-signed, manual PEM, or ACME), opens the configured number of SO_REUSEPORT listeners, optionally advertises HTTP/2 (subject to Config.DisableHTTP2), starts the HTTP-to-HTTPS redirect listener, and blocks until Shutdown is called or an unrecoverable error occurs.
//
// Example: log.Fatal(s.ListenAndServeTLS())
func (s *Server) ListenAndServeTLS() error {
	s.logCapabilities()
	maybeRaiseProcessFileLimit()
	logIOUringStartupProbe()
	if err := s.loadCerts(); err != nil {
		return err
	}
	s.rebuildFallbackTLSConfig()

	s.Router.Build()
	s.computeFastDispatch()

	numListeners := s.config.Listeners
	if numListeners <= 0 {
		numListeners = 1
	}
	numListeners = ioUringListenerCount(numListeners)

	listeners, err := createListeners(s.config.Addr, numListeners)
	if err != nil {
		return err
	}
	s.listeners = listeners
	defer func() {
		for _, ln := range s.listeners {
			ln.Close()
		}
	}()

	protocols := "HTTP/1.1 + HTTP/2"
	if !s.http2Enabled() {
		protocols = "HTTP/1.1"
	}
	log.Printf("=== ALOS TLS Server (TLS 1.3 + 1.2 | %s) ===", protocols)
	log.Printf("Listening on https://%s (%d listener(s))", s.config.Addr, len(listeners))
	certs := s.certStore.ListCerts()
	for _, ci := range certs {
		label := "self-signed"
		switch ci.Source {
		case CertManual:
			label = "manual"
		case CertACME:
			label = "acme"
		}
		log.Printf("  cert: %s (%s)", ci.Domain, label)
	}
	if len(certs) == 0 {
		log.Printf("[WARN] no TLS certificates are loaded; incoming HTTPS handshakes will fail until a certificate becomes available")
	}
	backend, err := newTLSUringBackend(s, listeners)
	if err != nil {
		return err
	}
	defer backend.closeResources()
	if err := s.startHTTPRedirect(); err != nil {
		return err
	}
	s.primeTLSCertificates()

	if s.acme != nil {
		s.acme.Start()
	}
	log.Printf("[INFO] io_uring TLS worker mode active on Linux amd64: workers=%d accept-shards=%d initial-conn-pool=%d", len(backend.workers), minInt(len(listeners), len(backend.workers)), ioUringInitialConnsPerShard)
	backend.start()
	return backend.wait()
}

func (s *Server) Capabilities() Capabilities { return s.caps }

func (s *Server) logCapabilities() {
	s.capsLogOnce.Do(func() {
		c := s.caps
		log.Printf("[INFO] capabilities: %s/%s cpu=%d gomaxprocs=%d workers=%d aes-ni=%t ktls-ulp=%t nic=%s ktls-hw-offload=%t => use-ktls=%t",
			c.OS, c.Arch, c.NumCPU, c.GOMAXPROCS, s.config.WorkerCount, c.CPUHasAES, c.KTLSAvailable, c.NICIface, c.NICOffloadTX, c.UseKTLS())
	})
}

// ListenAndServe starts a plain HTTP/1.1 (and HTTP/2 prior-knowledge) server with no TLS. Use it when Config.PlainHTTP is true or TLS is terminated upstream; it blocks until Shutdown is called or an unrecoverable error occurs.
//
// Example: log.Fatal(s.ListenAndServe())
func (s *Server) ListenAndServe() error {
	s.logCapabilities()
	workers := s.config.WorkerCount
	if workers < 1 {
		workers = runtime.GOMAXPROCS(0) + runtime.GOMAXPROCS(0)/2
	}
	if workers < 1 {
		workers = 1
	}
	prevProcs := runtime.GOMAXPROCS(workers)
	defer runtime.GOMAXPROCS(prevProcs)
	maybeRaiseProcessFileLimit()
	logIOUringStartupProbe()
	s.Router.Build()
	s.computeFastDispatch()

	addr := s.config.Addr
	if addr == "" {
		addr = ":80"
	}

	numListeners := s.config.Listeners
	if numListeners <= 0 {
		numListeners = 1
	}
	numListeners = ioUringListenerCount(numListeners)

	listeners, err := createListeners(addr, numListeners)
	if err != nil {
		return err
	}
	s.listeners = listeners
	defer func() {
		for _, ln := range s.listeners {
			ln.Close()
		}
	}()

	log.Println("=== ALOS HTTP Server (Plain HTTP/1.1 + HTTP/2 prior knowledge) ===")
	log.Printf("Listening on http://%s (%d listener(s))", addr, len(listeners))

	if started, err := s.tryServeWithIOUringPlainWorkers(listeners); started || err != nil {
		return err
	}
	return ErrIOUringRequired
}

func (s *Server) tryTrackConn() bool {
	if s.shuttingDown.Load() {
		return false
	}
	s.activeConns.Add(1)
	if s.shuttingDown.Load() {
		s.releaseTrackedConn()
		return false
	}
	return true
}

func (s *Server) releaseTrackedConn() {
	if s.activeConns.Add(-1) <= 0 && s.shuttingDown.Load() {
		s.drainOnce.Do(func() { close(s.drainDone) })
	}
}

func (s *Server) trackHandoffConn(conn net.Conn) net.Conn {
	if conn == nil {
		return nil
	}
	if !s.tryTrackConn() {
		_ = conn.Close()
		return nil
	}
	tc := &trackedHandoffConn{Conn: conn, server: s}
	s.trackedConnMu.Lock()
	if s.trackedConns == nil {
		s.trackedConns = make(map[*trackedHandoffConn]struct{})
	}
	s.trackedConns[tc] = struct{}{}
	s.trackedConnMu.Unlock()
	Stats.ActiveConns.Add(1)
	return tc
}

func (s *Server) untrackHandoffConn(conn *trackedHandoffConn) {
	if s == nil || conn == nil {
		return
	}
	s.trackedConnMu.Lock()
	delete(s.trackedConns, conn)
	s.trackedConnMu.Unlock()
	Stats.ActiveConns.Add(-1)
	s.releaseTrackedConn()
}

func (s *Server) closeTrackedHandoffConns() {
	s.trackedConnMu.Lock()
	tracked := make([]*trackedHandoffConn, 0, len(s.trackedConns))
	for conn := range s.trackedConns {
		tracked = append(tracked, conn)
	}
	s.trackedConnMu.Unlock()
	for _, conn := range tracked {
		_ = conn.Close()
	}
}

func (c *trackedHandoffConn) Close() error {
	if c == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() {
		err = c.Conn.Close()
		if c.server != nil {
			c.server.untrackHandoffConn(c)
		}
	})
	return err
}

func (s *Server) loadCerts() error {
	var acmeDomains []string

	if len(s.config.Certs) > 0 {
		for _, cc := range s.config.Certs {
			switch cc.Source {
			case CertSelfSigned:
				der, priv, err := GenerateSelfSignedForDomain(cc.Domain)
				if err != nil {
					return err
				}
				s.certStore.AddCert(NewCertEntryFromDER(cc.Domain, der, priv, CertSelfSigned))
			case CertManual:
				certPEM, err := os.ReadFile(cc.CertFile)
				if err != nil {
					return err
				}
				keyPEM, err := os.ReadFile(cc.KeyFile)
				if err != nil {
					return err
				}
				entry, err := NewCertEntryFromPEM(cc.Domain, certPEM, keyPEM, CertManual)
				if err != nil {
					return err
				}
				s.certStore.AddCert(entry)
			case CertACME:
				acmeDomains = append(acmeDomains, cc.Domain)
			}
		}
	}

	if s.config.ACME != nil {
		cfg := *s.config.ACME
		seen := make(map[string]struct{}, len(cfg.Domains)+len(acmeDomains))
		for _, d := range cfg.Domains {
			seen[d] = struct{}{}
		}
		for _, d := range acmeDomains {
			if _, ok := seen[d]; !ok {
				cfg.Domains = append(cfg.Domains, d)
				seen[d] = struct{}{}
			}
		}
		s.acme = newACMEIntegration(cfg, s)
		if s.acme != nil {
			log.Printf("[ACME] enabled for domains: %v", cfg.Domains)
		}
	} else if len(acmeDomains) > 0 {
		cfg := ACMEConfig{Domains: acmeDomains}
		s.acme = newACMEIntegration(cfg, s)
		if s.acme != nil {
			log.Printf("[ACME] enabled for domains: %v", acmeDomains)
		}
	}

	if len(s.config.Certs) > 0 || s.acme != nil {
		if s.config.DefaultDomain != "" {
			s.certStore.SetDefault(s.config.DefaultDomain)
		}
		return nil
	}

	certDER, privKey, err := LoadOrGenerateCert(s.config.TLSCertFile, s.config.TLSKeyFile)
	if err != nil {
		return err
	}
	s.certStore.AddCert(NewCertEntryFromDER("localhost", certDER, privKey, CertSelfSigned))
	return nil
}

func (s *Server) primeTLSCertificates() {
	if s.acme == nil {
		return
	}
	before := len(s.certStore.ListCerts())
	if before == 0 {
		log.Printf("[ACME] priming initial TLS certificates before opening HTTPS listeners")
	}
	s.acme.primeInitial()
	after := len(s.certStore.ListCerts())
	if after == 0 {
		domains := s.acme.domainsSnapshot()
		if len(domains) == 0 {
			log.Printf("[WARN] ACME is enabled but no TLS certificates are loaded yet")
			return
		}
		log.Printf("[WARN] ACME has no usable certificate yet for %v; HTTPS handshakes will fail until one is obtained", domains)
		return
	}
	if before == 0 {
		log.Printf("[ACME] %d certificate(s) ready for HTTPS startup", after)
	}
}

func (s *Server) rebuildFallbackTLSConfig() {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		NextProtos: s.tlsNextProtos(),
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			entry := s.certStore.Lookup(hello.ServerName)
			if entry != nil {
				return &entry.TLSCert, nil
			}
			return nil, ErrNoCertForSNI
		},
	}
	s.fallbackTLS.Store(cfg)
}

// Shutdown gracefully drains in-flight connections and stops ACME renewal, rate-limit cleanup, the proxy, and listener goroutines. The provided context bounds how long the drain may take.
//
// Example: ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second); defer cancel(); s.Shutdown(ctx)
// Example: s.Shutdown(context.Background())
func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdownOnce.Do(func() {
		s.shuttingDown.Store(true)
		close(s.done)
		if s.acme != nil {
			s.acme.Stop()
		}
		if pe := s.proxy.Load(); pe != nil {
			pe.Stop()
		}
		if s.RateLimit != nil {
			s.RateLimit.Stop()
		}
		for _, ln := range s.listeners {
			ln.Close()
		}
		if s.activeConns.Load() <= 0 {
			s.drainOnce.Do(func() { close(s.drainDone) })
		}
	})

	select {
	case <-s.drainDone:
		if s.x25519Pool != nil {
			s.x25519Pool.Close()
		}
		return nil
	case <-ctx.Done():
		s.closeTrackedHandoffConns()
		return ctx.Err()
	}
}

type prefixConn struct {
	net.Conn
	reader io.Reader
}

func (c *prefixConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (s *Server) NewH2StreamWriter(streamID uint32, hc *H2Conn, streamWindow *atomic.Int64) *H2StreamWriter {
	w := H2StreamWriterPool.Get().(*H2StreamWriter)
	w.streamID = streamID
	w.writeCh = hc.writeCh
	w.done = hc.done
	w.window = streamWindow
	w.connWindow = &hc.connWindow
	w.maxFrame = &hc.maxFrameSize
	w.limiter = s.connLimiter
	w.global = s.globalLimiter
	w.method = ""
	w.headersSent = false
	w.suppressBody = false
	w.flowCond = hc.flowCond
	return w
}

func (s *Server) NewH1StreamWriter(conn net.Conn, writer *TrafficAEAD) *H1StreamWriter {
	w := H1StreamWriterPool.Get().(*H1StreamWriter)
	w.conn = conn
	w.writer = writer
	w.limiter = s.connLimiter
	w.global = s.globalLimiter
	w.method = ""
	w.headersSent = false
	w.chunked = true
	w.suppressBody = false
	w.closeAfter = false
	return w
}

func (s *Server) NewPlainH1StreamWriter(conn net.Conn) *PlainH1StreamWriter {
	w := PlainH1StreamWriterPool.Get().(*PlainH1StreamWriter)
	w.conn = conn
	w.limiter = s.connLimiter
	w.global = s.globalLimiter
	w.method = ""
	w.headersSent = false
	w.chunked = true
	w.suppressBody = false
	w.closeAfter = false
	return w
}

func (s *Server) rootFastEligible() bool {
	if s.RateLimit != nil ||
		s.CORS != nil ||
		s.config.EnableCompress ||
		s.perIPLimiter != nil ||
		s.trustedProxies.active {
		return false
	}
	if pe := s.proxy.Load(); pe != nil {
		return false
	}
	return true
}

func (s *Server) tryAcquireRequestSlot() bool {
	if s.config.MaxConcurrentReqs <= 0 {
		return true
	}
	current := s.activeReqs.Add(1)
	if current > s.config.MaxConcurrentReqs {
		s.activeReqs.Add(-1)
		return false
	}
	return true
}

func (s *Server) releaseRequestSlot() {
	if s.config.MaxConcurrentReqs > 0 {
		s.activeReqs.Add(-1)
	}
}

func (s *Server) computeFastDispatch() {
	rootFast := s.rootFastEligible()
	fast := rootFast && s.config.MaxConcurrentReqs <= 0
	s.fastDispatch.Store(fast)
	s.computePlainRootFastResponse(rootFast)
	s.computeH2RootFastResponse(rootFast)
}

func (s *Server) computePlainRootFastResponse(fast bool) {
	s.plainRootFast = plainRootFastResponse{}
	if !fast || len(s.Router.globalMiddleware) != 0 {
		return
	}
	handler := s.lookupStaticHandler(methodGET, "/")
	if handler == nil {
		return
	}
	req := Request{Method: "GET", Path: "/", Proto: "HTTP/1.1"}
	resp := Response{
		StatusCode: 200,
		Headers:    make([][2]string, 0, 8),
		body:       make([]byte, 0, 4096),
	}
	handler(&req, &resp)
	if req.hijacked || resp.IsStreamed() {
		return
	}
	if s.config.MaxWriteSize > 0 && int64(resp.transmittedBodyLen()) > s.config.MaxWriteSize {
		return
	}
	keepAlive := appendPlainResponseMode(&resp, make([]byte, 0, resp.BodyLen()+128), true, true)
	closeResp := appendPlainResponseMode(&resp, make([]byte, 0, len(keepAlive)), false, true)
	if len(keepAlive) == 0 || len(closeResp) == 0 {
		return
	}
	keepAliveTLS := make([]byte, len(keepAlive)+1)
	copy(keepAliveTLS, keepAlive)
	keepAliveTLS[len(keepAlive)] = 0x17
	closeTLS := make([]byte, len(closeResp)+1)
	copy(closeTLS, closeResp)
	closeTLS[len(closeResp)] = 0x17
	s.plainRootFast = plainRootFastResponse{
		enabled:         true,
		getKeepAlive:    keepAlive,
		getClose:        closeResp,
		getKeepAliveTLS: keepAliveTLS,
		getCloseTLS:     closeTLS,
	}
}

func (s *Server) computeH2RootFastResponse(fast bool) {
	s.h2RootFast = h2RootFastResponse{}
	if !fast || !s.http2Enabled() || len(s.Router.globalMiddleware) != 0 {
		return
	}
	handler := s.lookupStaticHandler(methodGET, "/")
	if handler == nil {
		return
	}
	req := Request{Method: "GET", Path: "/", Proto: "HTTP/2"}
	resp := Response{
		StatusCode: 200,
		Headers:    make([][2]string, 0, 8),
		body:       make([]byte, 0, 4096),
	}
	handler(&req, &resp)
	if req.hijacked || resp.IsStreamed() {
		return
	}
	if s.config.MaxWriteSize > 0 && int64(resp.transmittedBodyLen()) > s.config.MaxWriteSize {
		return
	}

	enc := HpackEncoder{}
	headerPayload := make([]byte, 0, resp.BodyLen()+128)
	enc.Reset(headerPayload)
	encodeH2ResponseHeaders(&enc, resp.StatusCode, resp.ContentType, int64(resp.headerContentLength()), resp.Headers)

	body := append([]byte(nil), resp.transmittedBodyBytes()...)
	fastResp := h2RootFastResponse{
		enabled:       true,
		headerPayload: append([]byte(nil), enc.Buf...),
		body:          body,
	}
	if len(body) <= int(H2DefaultMaxFrameSize) {
		framed := make([]byte, 0, len(fastResp.headerPayload)+len(body)+18)
		if len(body) == 0 {
			framed = appendH2Frame(framed, H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 0, fastResp.headerPayload)
			fastResp.dataFrameOff = -1
		} else {
			framed = appendH2Frame(framed, H2FrameHeaders, H2FlagEndHeaders, 0, fastResp.headerPayload)
			fastResp.dataFrameOff = len(framed)
			framed = appendH2Frame(framed, H2FrameData, H2FlagEndStream, 0, body)
		}
		fastResp.framed = framed
		if len(framed)+1 <= MaxRecordPayload {
			fastResp.tlsInner = make([]byte, len(framed)+1)
			copy(fastResp.tlsInner, framed)
			fastResp.tlsInner[len(framed)] = 0x17
			fastResp.headerIDOff = 5
			fastResp.dataIDOff = -1
			if fastResp.dataFrameOff >= 0 {
				fastResp.dataIDOff = fastResp.dataFrameOff + 5
			}
		}
	}
	s.h2RootFast = fastResp
}

func (s *Server) lookupStaticHandler(methodIdx int, path string) HandlerFunc {
	if methodIdx < 0 || methodIdx >= len(s.Router.staticPaths) {
		return nil
	}
	paths := s.Router.staticPaths[methodIdx]
	if len(paths) == 0 {
		return nil
	}
	hashes := s.Router.staticHashes[methodIdx]
	handlers := s.Router.staticHandlers[methodIdx]
	mask := s.Router.staticMask[methodIdx]
	h := pathQuickHash(path)
	idx := h & mask
	for hashes[idx] != 0 {
		if hashes[idx] == h && paths[idx] == path {
			return handlers[idx]
		}
		idx = (idx + 1) & mask
	}
	return nil
}

func tlsAlertName(desc byte) string {
	switch desc {
	case 0:
		return "close_notify"
	case 10:
		return "unexpected_message"
	case 20:
		return "bad_record_mac"
	case 22:
		return "record_overflow"
	case 40:
		return "handshake_failure"
	case 42:
		return "bad_certificate"
	case 43:
		return "unsupported_certificate"
	case 44:
		return "certificate_revoked"
	case 45:
		return "certificate_expired"
	case 46:
		return "certificate_unknown"
	case 47:
		return "illegal_parameter"
	case 48:
		return "unknown_ca"
	case 50:
		return "decode_error"
	case 51:
		return "decrypt_error"
	case 70:
		return "protocol_version"
	case 71:
		return "insufficient_security"
	case 80:
		return "internal_error"
	case 90:
		return "user_canceled"
	case 109:
		return "missing_extension"
	case 110:
		return "unsupported_extension"
	case 112:
		return "unrecognized_name"
	case 120:
		return "no_application_protocol"
	default:
		return "unknown"
	}
}

// SetProxy installs a reverse-proxy engine, replacing any existing one.
//
// Example: s.SetProxy(NewProxyEngine())
// Example: s.SetProxy(pe)
func (s *Server) SetProxy(pe *ProxyEngine) {
	s.proxy.Store(pe)
	s.computeFastDispatch()
}

// Proxy returns the server's reverse-proxy engine, or nil if none is configured.
func (s *Server) Proxy() *ProxyEngine {
	return s.proxy.Load()
}

// AddProxyDomain registers a reverse-proxy domain, creating the proxy engine if needed; safe to call at runtime. When a request host matches a proxy domain, the proxy runs before local router handlers.
//
// Example: s.AddProxyDomain(DomainConfig{Domain: "api.example.com", Backends: []BackendConfig{{Addr: "10.0.0.1:8080"}}})
// Example: s.AddProxyDomain(DomainConfig{Domain: "api.example.com", Backends: []BackendConfig{{Addr: "10.0.0.1:8080", Weight: 3}, {Addr: "10.0.0.2:8080", Weight: 1}}, Balancer: LBWeightedRR, MaxRetries: 2, HealthCheck: HealthCheckConfig{Path: "/health", Interval: 10 * time.Second, Timeout: 2 * time.Second}})
func (s *Server) AddProxyDomain(cfg DomainConfig) {
	pe := s.proxy.Load()
	if pe == nil {
		pe = NewProxyEngine()
		s.proxy.Store(pe)
	}
	pe.AddDomain(cfg)
	s.computeFastDispatch()
}

// RemoveProxyDomain removes a domain and cleans up health checkers and connection pools for all its backends.
//
// Example: s.RemoveProxyDomain("api.example.com")
// Example: s.RemoveProxyDomain("static.example.com")
func (s *Server) RemoveProxyDomain(domain string) {
	pe := s.proxy.Load()
	if pe != nil {
		pe.RemoveDomain(domain)
	}
	s.computeFastDispatch()
}

// OnProxyError registers a callback invoked whenever a backend request fails, e.g. for alerting or structured logging.
//
// Example: s.OnProxyError(func(pe ProxyError) { log.Printf("proxy error: domain=%s backend=%s err=%v", pe.Domain, pe.Backend, pe.Err) })
// Example: s.OnProxyError(func(pe ProxyError) { metrics.Inc("proxy_errors") })
func (s *Server) OnProxyError(fn ProxyErrorFunc) {
	pe := s.proxy.Load()
	if pe == nil {
		pe = NewProxyEngine()
		s.proxy.Store(pe)
	}
	pe.OnError = fn
	s.computeFastDispatch()
}

// OnProxyRequest registers a callback invoked before a request is forwarded to a backend; modify pr.Headers or pr.Host to alter the outgoing request, or return false to reject with 502.
//
// Example: s.OnProxyRequest(func(pr *ProxyRequest) bool { pr.Headers = append(pr.Headers, [2]string{"X-Forwarded-For", pr.ClientAddr}); return true })
// Example: s.OnProxyRequest(func(pr *ProxyRequest) bool { return pr.Host != "blocked.example.com" })
func (s *Server) OnProxyRequest(fn ProxyInterceptFunc) {
	pe := s.proxy.Load()
	if pe == nil {
		pe = NewProxyEngine()
		s.proxy.Store(pe)
	}
	pe.OnRequest = fn
	s.computeFastDispatch()
}

// OnProxyResponse registers a callback invoked after a backend responds (or a cache hit is served); modify pr.Headers or pr.StatusCode before they reach the client, or call pr.CacheThis to store the response.
//
// Example: s.OnProxyResponse(func(pr *ProxyResponse) { pr.Headers = append(pr.Headers, [2]string{"X-Proxy-By", "ALOS"}) })
// Example: s.OnProxyResponse(func(pr *ProxyResponse) { if pr.StatusCode == 200 { pr.CacheThis() } })
func (s *Server) OnProxyResponse(fn ProxyResponseFunc) {
	pe := s.proxy.Load()
	if pe == nil {
		pe = NewProxyEngine()
		s.proxy.Store(pe)
	}
	pe.OnResponse = fn
	s.computeFastDispatch()
}

// SetProxyCache enables proxy response caching, keyed by method + host + path (including the query string). See ProxyCacheConfig for per-path rules, total budget, entry-size limits, and pre-compression.
//
// Example: s.SetProxyCache(ProxyCacheConfig{MaxEntrySize: 4 << 20, MaxTotalBytes: 256 << 20, DefaultMaxAge: 5 * time.Minute})
// Example: s.SetProxyCache(ProxyCacheConfig{PreCompress: true, CompressLevel: 6, CompressMinLen: 512, Rules: []CacheRule{{PathPrefix: "/api/", MaxAge: 30 * time.Second}, {PathPrefix: "/static/", MaxAge: 24 * time.Hour}}})
func (s *Server) SetProxyCache(cfg ProxyCacheConfig) {
	pe := s.proxy.Load()
	if pe == nil {
		pe = NewProxyEngine()
		s.proxy.Store(pe)
	}
	if pe.Cache != nil {
		pe.Cache.Stop()
	}
	pe.Cache = NewProxyCache(cfg)
	s.computeFastDispatch()
}

// ProxyCacheStats returns current cache metrics: number of entries, total bytes used, cumulative hits, and cumulative misses.
func (s *Server) ProxyCacheStats() (entries int64, totalBytes int64, hits uint64, misses uint64) {
	pe := s.proxy.Load()
	if pe == nil || pe.Cache == nil {
		return 0, 0, 0, 0
	}
	return pe.Cache.Stats()
}

// PurgeProxyCache removes a single cached response by method, host, and path, reporting whether an entry was found and removed.
//
// Example: s.PurgeProxyCache("GET", "example.com", "/index.html")
// Example: s.PurgeProxyCache("GET", "api.example.com", "/v1/users")
func (s *Server) PurgeProxyCache(method, host, path string) bool {
	pe := s.proxy.Load()
	if pe == nil || pe.Cache == nil {
		return false
	}
	return pe.Cache.Purge(method, host, path)
}

// PurgeAllProxyCache drops every entry in the response cache.
func (s *Server) PurgeAllProxyCache() {
	pe := s.proxy.Load()
	if pe == nil || pe.Cache == nil {
		return
	}
	pe.Cache.PurgeAll()
}

// PurgeDomainCache removes all cached responses for the given domain and returns the number of entries purged.
//
// Example: s.PurgeDomainCache("example.com")
// Example: s.PurgeDomainCache("api.example.com")
func (s *Server) PurgeDomainCache(domain string) int64 {
	pe := s.proxy.Load()
	if pe == nil || pe.Cache == nil {
		return 0
	}
	return pe.Cache.PurgeDomain(domain)
}

// OnRequest registers a hook run before routing each request; returning false stops further processing of that request. Multiple hooks run in registration order.
//
// Example: s.OnRequest(func(req *Request, resp *Response) bool { return true })
// Example: s.OnRequest(func(req *Request, resp *Response) bool { if req.Path == "/blocked" { resp.Status(403); return false }; return true })
func (s *Server) OnRequest(fn func(*Request, *Response) bool) {
	s.onRequestHooks = append(s.onRequestHooks, fn)
}

// OnResponse registers a hook run after each handler completes. Multiple hooks run in registration order.
//
// Example: s.OnResponse(func(req *Request, resp *Response) { log.Printf("%s %d", req.Path, resp.StatusCode) })
// Example: s.OnResponse(func(req *Request, resp *Response) { resp.SetHeader("X-Served-By", "ALOS") })
func (s *Server) OnResponse(fn func(*Request, *Response)) {
	s.onResponseHooks = append(s.onResponseHooks, fn)
}

func (s *Server) dispatch(req *Request, resp *Response) {
	if !s.tryAcquireRequestSlot() {
		resp.Status(503).String("Service Unavailable")
		return
	}
	defer s.releaseRequestSlot()

	if s.trustedProxies.active {
		applyTrustedRealIP(req, s.trustedProxies)
	}

	clientIP := extractIP(req.RemoteAddr)
	if s.perIPLimiter != nil {
		if !s.perIPLimiter.acquire(clientIP, s.config.MaxRequestsPerIP) {
			resp.Status(429).String("Too Many Requests")
			return
		}
		defer s.perIPLimiter.release(clientIP)
	}

	for _, hook := range s.onRequestHooks {
		if !hook(req, resp) {
			return
		}
	}

	cors := s.CORS
	var corsSnap *corsSnapshot
	if cors != nil {
		corsSnap = cors.snapshot.Load()
	}
	defer func() {
		for _, hook := range s.onResponseHooks {
			hook(req, resp)
		}
		if s.config.EnableCompress && !req.hijacked {
			applyConfiguredCompression(req, resp, CompressConfig{
				Level:   s.config.CompressLevel,
				MinSize: s.config.CompressMinSize,
			})
		}
		if s.config.MaxWriteSize > 0 && int64(resp.transmittedBodyLen()) > s.config.MaxWriteSize {
			resp.Reset()
			resp.Status(500).String("Response Too Large")
		}
		if corsSnap != nil {
			cors.applyCORS(corsSnap, req, resp)
		}
	}()

	if corsSnap != nil && req.Method == "OPTIONS" {
		resp.Status(204)
		return
	}

	if s.RateLimit != nil {
		if clientIP != "" {
			allowed, cr, retryAfter := s.RateLimit.Check(clientIP, req.Path)
			if !allowed {
				event := RateLimitEvent{
					IP:         clientIP,
					Path:       req.Path,
					RetryAfter: retryAfter,
				}
				if cr != nil {
					event.Rule = cr.rule
				}

				if cr != nil && cr.rule.OnLimit != nil {
					if cr.rule.OnLimit(event, req, resp) {
						return
					}
				}
				if s.RateLimit.OnLimit != nil {
					if s.RateLimit.OnLimit(event, req, resp) {
						return
					}
				}

				var buf [20]byte
				secs := appendUint(buf[:0], int64(retryAfter.Seconds())+1)
				resp.Status(429).
					SetHeaderUnsafe("retry-after", string(secs)).
					String("Too Many Requests")
				return
			}
		}
	}

	if pe := s.proxy.Load(); pe != nil && req.Host != "" {
		if pe.Handle(req, resp) {
			return
		}
	}
	handler := s.Router.Lookup(req.Method, req.Path, req)
	handler(req, resp)
}

// SetHTTPRoutes configures port-80 HTTP routes that proxy plain HTTP traffic to backend servers instead of redirecting to HTTPS, replacing any existing HTTP routes.
//
// Example: s.SetHTTPRoutes([]HTTPRoute{{PathPrefix: "/api/", Backend: "10.0.0.5:3000"}})
// Example: s.SetHTTPRoutes([]HTTPRoute{{PathPrefix: "/", Backend: "10.0.0.6:8080", HostHeader: "backend.local"}})
func (s *Server) SetHTTPRoutes(routes []HTTPRoute) {
	if s.httpRouter == nil {
		s.httpRouter = newHTTPRouter()
	}
	s.httpRouter.SetRoutes(routes)
	if debugFlag.Load() {
		log.Printf("[HTTP-ROUTE] %d route(s) configured", len(routes))
	}
}

// AddHTTPRoute appends a single port-80 HTTP proxy route without replacing existing ones.
//
// Example: s.AddHTTPRoute(HTTPRoute{PathPrefix: "/api/", Backend: "10.0.0.5:3000"})
// Example: s.AddHTTPRoute(HTTPRoute{PathPrefix: "/", Backend: "10.0.0.6:8080", HostHeader: "backend.local"})
func (s *Server) AddHTTPRoute(route HTTPRoute) {
	if s.httpRouter == nil {
		s.httpRouter = newHTTPRouter()
	}
	s.httpRouter.AddRoute(route)
	if debugFlag.Load() {
		log.Printf("[HTTP-ROUTE] added: %s -> %s", route.PathPrefix, route.Backend)
	}
}

// RemoveHTTPRoute removes the port-80 HTTP proxy route with the given path prefix.
//
// Example: s.RemoveHTTPRoute("/api/")
// Example: s.RemoveHTTPRoute("/")
func (s *Server) RemoveHTTPRoute(pathPrefix string) {
	if s.httpRouter != nil {
		s.httpRouter.RemoveRoute(pathPrefix)
		if debugFlag.Load() {
			log.Printf("[HTTP-ROUTE] removed: %s", pathPrefix)
		}
	}
}

// SetCORS sets or replaces the server's CORS policy.
//
// Example: s.SetCORS(CORSConfig{AllowOrigins: []string{"*"}})
// Example: s.SetCORS(CORSConfig{AllowOrigins: []string{"https://example.com"}, AllowMethods: []string{"GET", "POST"}, AllowCredentials: true})
func (s *Server) SetCORS(cfg CORSConfig) {
	if s.CORS == nil {
		s.CORS = NewCORSEngine(cfg)
	} else {
		s.CORS.Update(cfg)
	}
	s.computeFastDispatch()
}

// UpdateCORS replaces the server's CORS policy; it is an alias for SetCORS.
//
// Example: s.UpdateCORS(CORSConfig{AllowOrigins: []string{"https://new.example.com"}})
// Example: s.UpdateCORS(CORSConfig{AllowOrigins: []string{"*"}})
func (s *Server) UpdateCORS(cfg CORSConfig) {
	s.SetCORS(cfg)
}

func (s *Server) ensureRateLimit() {
	if s.RateLimit == nil {
		s.RateLimit = NewRateLimitEngine()
		s.computeFastDispatch()
	}
}

// SetRateLimitRules replaces all rate-limit rules; each rule matches a path pattern and enforces a per-client-IP request budget.
//
// Example: s.SetRateLimitRules([]RateLimitRule{{Path: "/api/*", MaxReqs: 100, Window: 60 * time.Second, BlockFor: 5 * time.Minute}})
// Example: s.SetRateLimitRules([]RateLimitRule{{Path: "/*", MaxReqs: 300, Window: 60 * time.Second, BlockFor: 2 * time.Minute}})
func (s *Server) SetRateLimitRules(rules []RateLimitRule) {
	s.ensureRateLimit()
	s.RateLimit.SetRules(rules)
}

// AddRateLimitRule appends a single rate-limit rule without replacing existing ones.
//
// Example: s.AddRateLimitRule(RateLimitRule{Path: "/login", MaxReqs: 5, Window: time.Minute, BlockFor: 10 * time.Minute})
// Example: s.AddRateLimitRule(RateLimitRule{Path: "/api/*", MaxReqs: 100, Window: time.Minute})
func (s *Server) AddRateLimitRule(rule RateLimitRule) {
	s.ensureRateLimit()
	s.RateLimit.AddRule(rule)
}

// RemoveRateLimitRule removes the rule matching the given path pattern.
//
// Example: s.RemoveRateLimitRule("/api/*")
// Example: s.RemoveRateLimitRule("/login")
func (s *Server) RemoveRateLimitRule(path string) {
	if s.RateLimit == nil {
		return
	}
	s.RateLimit.RemoveRule(path)
}

// OnRateLimit registers a global callback invoked when a request is rate-limited; return true if the callback wrote the response, or false to fall through to the default 429.
//
// Example: s.OnRateLimit(func(event RateLimitEvent, req *Request, resp *Response) bool { resp.Status(429).JSON([]byte(`{"error":"too many requests"}`)); return true })
// Example: s.OnRateLimit(func(event RateLimitEvent, req *Request, resp *Response) bool { metrics.Inc("ratelimited"); return false })
func (s *Server) OnRateLimit(fn RateLimitFunc) {
	s.ensureRateLimit()
	s.RateLimit.OnLimit = fn
}
