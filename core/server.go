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
)

var timeNow = time.Now

// Config controls every aspect of the ALOS server. Pass it to New to
// create a Server. Zero values use sane defaults (see DefaultConfig).
//
//	s := core.New(core.Config{
//		Addr:        ":443",
//		IdleTimeout: 120 * time.Second,
//		Listeners:   4,
//		PlainHTTP:   false,
//		ServerName:  "ALOS",
//		ACME: &core.ACMEConfig{
//			Email:   "admin@example.com",
//			Domains: []string{"example.com"},
//		},
//	})
//
// Fields:
//   - Addr: listen address (":443", ":8443", "0.0.0.0:443", etc.)
//   - HTTPAddr: listen address for the HTTP-to-HTTPS redirect listener. Defaults
//     to ":80" when Addr uses port 443, otherwise disabled.
//   - PlainHTTP: when true the server speaks plain HTTP/1.1 on Addr, skipping
//     TLS entirely.
//   - DisableHTTP2: when true the server never negotiates HTTP/2 and only
//     serves HTTP/1.1 over TLS.
//   - ProxyMode: enable when the server runs behind a reverse proxy / load
//     balancer. The server then trusts the X-Forwarded-For / X-Real-IP headers
//     and rewrites RemoteAddr to the real client IP for every request (rate
//     limiting, logging, and handlers all see the client). Leave it off when the
//     server is internet-facing, otherwise clients can spoof their IP. When on,
//     TrustedProxies is ignored (all peers are trusted); leave ProxyMode off and
//     set TrustedProxies to trust forwarding headers only from specific peers.
//   - IdleTimeout: how long an idle keep-alive connection stays open.
//   - HandshakeTimeout: deadline for the TLS handshake.
//   - MaxBodySize: reject request bodies larger than this (0 = unlimited).
//   - MaxReadSize / MaxWriteSize: per-connection I/O caps.
//   - MaxHeaderSize: maximum header block in bytes.
//   - MaxConcurrentReqs: server-wide concurrency cap (0 = unlimited).
//   - Listeners: number of SO_REUSEPORT listeners (Linux only, 1 elsewhere).
//   - Certs: per-domain certificate configs (manual, self-signed, or ACME).
//   - ACME: automatic Let's Encrypt certificates.
//   - ConnBandwidth / GlobalBandwidth: per-connection and global rate limits.
//   - Debug: enable verbose internal logging.
//   - LogRequests: log every accepted and closed connection.
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
}

// DefaultConfig returns a Config with sensible defaults. It listens on
// :8443 with a 120s idle timeout, 30s handshake timeout, 8 KiB header
// limit, gzip level 6, and request logging enabled.
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
	l := &perIPRequestLimiter{}
	for i := range l.shards {
		l.shards[i].counts = make(map[string]int64)
	}
	return l
}

func (l *perIPRequestLimiter) acquire(ip string, limit int64) bool {
	if l == nil || ip == "" || limit <= 0 {
		return true
	}
	shard := &l.shards[StringHash(ip)%shardCount]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.counts[ip] >= limit {
		return false
	}
	shard.counts[ip]++
	return true
}

func (l *perIPRequestLimiter) release(ip string) {
	if l == nil || ip == "" {
		return
	}
	shard := &l.shards[StringHash(ip)%shardCount]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if current := shard.counts[ip] - 1; current > 0 {
		shard.counts[ip] = current
	} else {
		delete(shard.counts, ip)
	}
}

// Server is the main entry point. Create one with New, configure
// routes on its Router field, then call ListenAndServeTLS or ListenAndServe.
//
//	s := core.New(core.Config{Addr: ":443"})
//	s.Router.GET("/", handler)
//	log.Fatal(s.ListenAndServeTLS())
//
// The Server manages its own TLS 1.3 implementation, optional HTTP/2
// multiplexing, connection pooling, reverse proxy, CORS, rate limiting,
// and ACME.
// All public methods are safe for concurrent use.
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
	quicLiveConns   atomic.Int64
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

type perIPRequestShard struct {
	mu     sync.Mutex
	counts map[string]int64
}

type perIPRequestLimiter struct {
	shards [shardCount]perIPRequestShard
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

// New creates a Server with the given Config. When called without
// arguments it uses DefaultConfig. The returned server is ready
// for route registration; call ListenAndServeTLS or ListenAndServe
// to start accepting connections.
//
//	s := core.New(core.Config{
//		Addr:      ":443",
//		PlainHTTP: false,
//		Listeners: 4,
//	})
//	s.Router.GET("/hello", func(req *core.Request, resp *core.Response) {
//		resp.Status(200).String("hello")
//	})
//	log.Fatal(s.ListenAndServeTLS())
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

func (s *Server) SetDebug(on bool) {
	s.debug.Store(on)
	SetDebugFlag(on)
}

func (s *Server) SetLogRequests(on bool) {
	s.logRequests.Store(on)
}

func (s *Server) IsDebug() bool {
	return s.debug.Load()
}

// ListenAndServeTLS starts the HTTPS server with ALOS's built-in TLS 1.3
// stack. It loads certificates (self-signed, manual PEM, or ACME),
// opens the configured number of SO_REUSEPORT listeners, optionally
// advertises HTTP/2 depending on Config.DisableHTTP2, starts the
// HTTP-to-HTTPS redirect listener, and blocks until Shutdown is called
// or an unrecoverable error occurs.
//
//	log.Fatal(s.ListenAndServeTLS())
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

// ListenAndServe starts a plain HTTP/1.1 server (no TLS). Use this when
// Config.PlainHTTP is true or when TLS termination is handled upstream.
//
//	s := core.New(core.Config{Addr: ":80", PlainHTTP: true})
//	s.Router.GET("/", handler)
//	log.Fatal(s.ListenAndServe())
func (s *Server) Capabilities() Capabilities { return s.caps }

func (s *Server) logCapabilities() {
	s.capsLogOnce.Do(func() {
		c := s.caps
		log.Printf("[INFO] capabilities: %s/%s cpu=%d gomaxprocs=%d workers=%d aes-ni=%t ktls-ulp=%t nic=%s ktls-hw-offload=%t => use-ktls=%t",
			c.OS, c.Arch, c.NumCPU, c.GOMAXPROCS, s.config.WorkerCount, c.CPUHasAES, c.KTLSAvailable, c.NICIface, c.NICOffloadTX, c.UseKTLS())
	})
}

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
		MinVersion: tls.VersionTLS11,
		MaxVersion: tls.VersionTLS12,
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

// Shutdown gracefully drains in-flight connections and stops ACME
// renewal, rate-limit cleanup, and listener goroutines. Pass a context
// with a deadline to bound how long the drain may take.
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	if err := s.Shutdown(ctx); err != nil {
//		log.Printf("shutdown: %v", err)
//	}
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

func (s *Server) SetProxy(pe *ProxyEngine) {
	s.proxy.Store(pe)
	s.computeFastDispatch()
}

func (s *Server) Proxy() *ProxyEngine {
	return s.proxy.Load()
}

// AddProxyDomain registers a reverse-proxy domain. If the ProxyEngine
// does not exist yet it is created automatically. Safe to call at runtime.
// When a request host matches a proxy domain, the proxy runs before local
// router handlers.
//
//	s.AddProxyDomain(core.DomainConfig{
//		Domain: "api.example.com",
//		Backends: []core.BackendConfig{
//			{Addr: "10.0.0.1:8080", Weight: 3},
//			{Addr: "10.0.0.2:8080", Weight: 1},
//		},
//		Balancer:   core.LBWeightedRR,
//		MaxRetries: 2,
//		HealthCheck: core.HealthCheckConfig{
//			Path:     "/health",
//			Interval: 10 * time.Second,
//			Timeout:  2 * time.Second,
//		},
//	})
func (s *Server) AddProxyDomain(cfg DomainConfig) {
	pe := s.proxy.Load()
	if pe == nil {
		pe = NewProxyEngine()
		s.proxy.Store(pe)
	}
	pe.AddDomain(cfg)
	s.computeFastDispatch()
}

// RemoveProxyDomain removes a domain and cleans up health checkers
// and connection pools for all its backends.
func (s *Server) RemoveProxyDomain(domain string) {
	pe := s.proxy.Load()
	if pe != nil {
		pe.RemoveDomain(domain)
	}
	s.computeFastDispatch()
}

// OnProxyError registers a callback invoked whenever a backend request
// fails. Use it for alerting or structured logging.
//
//	s.OnProxyError(func(pe core.ProxyError) {
//		log.Printf("proxy error: domain=%s backend=%s err=%v",
//			pe.Domain, pe.Backend, pe.Err)
//	})
func (s *Server) OnProxyError(fn ProxyErrorFunc) {
	pe := s.proxy.Load()
	if pe == nil {
		pe = NewProxyEngine()
		s.proxy.Store(pe)
	}
	pe.OnError = fn
	s.computeFastDispatch()
}

// OnProxyRequest registers a callback invoked before the request is
// forwarded to a backend. Modify pr.Headers or pr.Host to alter the
// outgoing request. Return false to reject with 502.
//
//	s.OnProxyRequest(func(pr *core.ProxyRequest) bool {
//		pr.Headers = append(pr.Headers, [2]string{"X-Forwarded-For", pr.ClientAddr})
//		return true
//	})
func (s *Server) OnProxyRequest(fn ProxyInterceptFunc) {
	pe := s.proxy.Load()
	if pe == nil {
		pe = NewProxyEngine()
		s.proxy.Store(pe)
	}
	pe.OnRequest = fn
	s.computeFastDispatch()
}

// OnProxyResponse registers a callback invoked after a backend responds
// (or a cache hit is served). Modify pr.Headers or pr.StatusCode before
// they reach the client. Call pr.CacheThis() to store the response.
//
//	s.OnProxyResponse(func(pr *core.ProxyResponse) {
//		pr.Headers = append(pr.Headers, [2]string{"X-Proxy-By", "ALOS"})
//	})
func (s *Server) OnProxyResponse(fn ProxyResponseFunc) {
	pe := s.proxy.Load()
	if pe == nil {
		pe = NewProxyEngine()
		s.proxy.Store(pe)
	}
	pe.OnResponse = fn
	s.computeFastDispatch()
}

// SetProxyCache enables proxy response caching. Cached responses are
// matched by method + host + path (including the query string). Configure
// per-path rules, total budget, entry size limits, and pre-compression.
//
//	s.SetProxyCache(core.ProxyCacheConfig{
//		MaxEntrySize:   4 << 20,
//		MaxTotalBytes:  256 << 20,
//		DefaultMaxAge:  5 * time.Minute,
//		PreCompress:    true,
//		CompressLevel:  6,
//		CompressMinLen: 512,
//		Rules: []core.CacheRule{
//			{PathPrefix: "/api/", MaxAge: 30 * time.Second},
//			{PathPrefix: "/static/", MaxAge: 24 * time.Hour},
//		},
//	})
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

// ProxyCacheStats returns current cache metrics: number of entries,
// total bytes used, cumulative hits, and cumulative misses.
func (s *Server) ProxyCacheStats() (entries int64, totalBytes int64, hits uint64, misses uint64) {
	pe := s.proxy.Load()
	if pe == nil || pe.Cache == nil {
		return 0, 0, 0, 0
	}
	return pe.Cache.Stats()
}

// PurgeProxyCache removes a single cached response by method, host, and path.
// Returns true if an entry was found and removed.
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

// PurgeDomainCache removes all cached responses for the given domain.
// Returns the number of entries purged.
func (s *Server) PurgeDomainCache(domain string) int64 {
	pe := s.proxy.Load()
	if pe == nil || pe.Cache == nil {
		return 0
	}
	return pe.Cache.PurgeDomain(domain)
}

func (s *Server) OnRequest(fn func(*Request, *Response) bool) {
	s.onRequestHooks = append(s.onRequestHooks, fn)
}

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

// SetHTTPRoutes configures port-80 HTTP routes that proxy plain HTTP
// traffic to backend servers (instead of 301-redirecting to HTTPS).
//
//	s.SetHTTPRoutes([]core.HTTPRoute{
//		{PathPrefix: "/api/", Backend: "10.0.0.5:3000"},
//		{PathPrefix: "/",     Backend: "10.0.0.6:8080", HostHeader: "backend.local"},
//	})
func (s *Server) SetHTTPRoutes(routes []HTTPRoute) {
	if s.httpRouter == nil {
		s.httpRouter = newHTTPRouter()
	}
	s.httpRouter.SetRoutes(routes)
	if debugFlag.Load() {
		log.Printf("[HTTP-ROUTE] %d route(s) configured", len(routes))
	}
}

func (s *Server) AddHTTPRoute(route HTTPRoute) {
	if s.httpRouter == nil {
		s.httpRouter = newHTTPRouter()
	}
	s.httpRouter.AddRoute(route)
	if debugFlag.Load() {
		log.Printf("[HTTP-ROUTE] added: %s -> %s", route.PathPrefix, route.Backend)
	}
}

func (s *Server) RemoveHTTPRoute(pathPrefix string) {
	if s.httpRouter != nil {
		s.httpRouter.RemoveRoute(pathPrefix)
		if debugFlag.Load() {
			log.Printf("[HTTP-ROUTE] removed: %s", pathPrefix)
		}
	}
}

// SetCORS configures CORS policy for the server.
//
//	s.SetCORS(core.CORSConfig{
//		AllowOrigins:     []string{"https://example.com"},
//		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
//		AllowHeaders:     []string{"Content-Type", "Authorization"},
//		ExposeHeaders:    []string{"X-Request-ID"},
//		AllowCredentials: true,
//		MaxAge:           86400,
//	})
func (s *Server) SetCORS(cfg CORSConfig) {
	if s.CORS == nil {
		s.CORS = NewCORSEngine(cfg)
	} else {
		s.CORS.Update(cfg)
	}
	s.computeFastDispatch()
}

func (s *Server) UpdateCORS(cfg CORSConfig) {
	s.SetCORS(cfg)
}

func (s *Server) ensureRateLimit() {
	if s.RateLimit == nil {
		s.RateLimit = NewRateLimitEngine()
		s.computeFastDispatch()
	}
}

// SetRateLimitRules replaces all rate-limit rules. Each rule matches a
// path pattern and enforces a request budget per client IP.
//
//	s.SetRateLimitRules([]core.RateLimitRule{
//		{Path: "/api/*",  MaxReqs: 100, Window: 60 * time.Second, BlockFor: 5 * time.Minute},
//		{Path: "/*",      MaxReqs: 300, Window: 60 * time.Second, BlockFor: 2 * time.Minute},
//	})
func (s *Server) SetRateLimitRules(rules []RateLimitRule) {
	s.ensureRateLimit()
	s.RateLimit.SetRules(rules)
}

// AddRateLimitRule appends a single rule without replacing existing ones.
func (s *Server) AddRateLimitRule(rule RateLimitRule) {
	s.ensureRateLimit()
	s.RateLimit.AddRule(rule)
}

// RemoveRateLimitRule removes the rule matching the given path pattern.
func (s *Server) RemoveRateLimitRule(path string) {
	if s.RateLimit == nil {
		return
	}
	s.RateLimit.RemoveRule(path)
}

// OnRateLimit registers a global callback invoked when a request is
// rate-limited. Return true to indicate the response has been handled,
// or false to fall through to the default 429 response.
//
//	s.OnRateLimit(func(event core.RateLimitEvent, req *core.Request, resp *core.Response) bool {
//		resp.Status(429).JSON([]byte(`{"error":"too many requests"}`))
//		return true
//	})
func (s *Server) OnRateLimit(fn RateLimitFunc) {
	s.ensureRateLimit()
	s.RateLimit.OnLimit = fn
}
