package core

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
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
//   - HTTPAddr: listen address for the HTTP→HTTPS redirect listener. Defaults
//     to ":80" when Addr uses port 443, otherwise disabled.
//   - PlainHTTP: when true the server speaks plain HTTP/1.1 on Addr, skipping
//     TLS entirely.
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
		Listeners:         0,
		Debug:             false,
		LogRequests:       true,
		ShutdownTimeout:   30 * time.Second,
	}
}

// Server is the main entry point. Create one with New, configure
// routes on its Router field, then call ListenAndServeTLS or ListenAndServe.
//
//	s := core.New(core.Config{Addr: ":443"})
//	s.Router.GET("/", handler)
//	log.Fatal(s.ListenAndServeTLS())
//
// The Server manages its own TLS 1.3 implementation, HTTP/2 multiplexing,
// connection pooling, reverse proxy, CORS, rate limiting, and ACME.
// All public methods are safe for concurrent use.
type Server struct {
	debug       atomic.Bool
	logRequests atomic.Bool

	config        Config
	Router        *Router
	CORS          *CORSEngine
	RateLimit     *RateLimitEngine
	certStore     *CertStore
	fallbackTLS   atomic.Pointer[tls.Config]
	proxy         atomic.Pointer[ProxyEngine]
	httpRouter    *HTTPRouter
	acme          *acmeIntegration
	listeners     []net.Listener
	done          chan struct{}
	activeConns   sync.WaitGroup
	shutdownOnce  sync.Once
	connLimiter   *ConnectionLimiter
	globalLimiter *GlobalLimiter
	activeReqs    atomic.Int64
	fastDispatch  atomic.Bool
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

	s := &Server{
		config:    cfg,
		Router:    NewRouter(),
		CORS:      NewCORSEngine(CORSConfig{}),
		certStore: NewCertStore(),
		done:      make(chan struct{}),
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

func NewServer(addr string) *Server {
	return New(Config{Addr: addr})
}

func (s *Server) SetDebug(on bool) {
	s.debug.Store(on)
	SetDebugFlag(on)
}

func (s *Server) SetLogRequests(on bool) {
	s.logRequests.Store(on)
}

func (s *Server) connLog(format string, args ...any) {
	if s.debug.Load() {
		log.Printf(format, args...)
	}
}

func (s *Server) IsDebug() bool {
	return s.debug.Load()
}

// ListenAndServeTLS starts the HTTPS server with ALOS's built-in TLS 1.3
// stack. It loads certificates (self-signed, manual PEM, or ACME),
// opens the configured number of SO_REUSEPORT listeners, starts the
// HTTP→HTTPS redirect listener, and blocks until Shutdown is called
// or an unrecoverable error occurs.
//
//	log.Fatal(s.ListenAndServeTLS())
func (s *Server) ListenAndServeTLS() error {
	if err := s.loadCerts(); err != nil {
		return err
	}
	s.rebuildFallbackTLSConfig()

	s.startHTTPRedirect()

	if s.acme != nil {
		s.acme.Start()
	}

	s.Router.Build()
	s.computeFastDispatch()

	numListeners := s.config.Listeners
	if numListeners <= 0 {
		numListeners = 1
	}

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

	log.Println("=== ALOS TLS Server (TLS 1.3/1.2/1.1 | HTTP/1.1 + HTTP/2) ===")
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

	errCh := make(chan error, len(listeners))
	for _, ln := range listeners {
		go s.acceptLoop(ln, errCh)
	}

	select {
	case <-s.done:
		return nil
	case err := <-errCh:
		return err
	}
}

// ListenAndServe starts a plain HTTP/1.1 server (no TLS). Use this when
// Config.PlainHTTP is true or when TLS termination is handled upstream.
//
//	s := core.New(core.Config{Addr: ":80", PlainHTTP: true})
//	s.Router.GET("/", handler)
//	log.Fatal(s.ListenAndServe())
func (s *Server) ListenAndServe() error {
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

	log.Println("=== ALOS HTTP Server (Plain HTTP/1.1) ===")
	log.Printf("Listening on http://%s (%d listener(s))", addr, len(listeners))

	errCh := make(chan error, len(listeners))
	for _, ln := range listeners {
		go s.acceptLoopPlain(ln, errCh)
	}

	select {
	case <-s.done:
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) acceptLoopPlain(ln net.Listener, errCh chan<- error) {
	for {
		select {
		case <-s.done:
			return
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				log.Printf("accept: %v", err)
				continue
			}
		}
		s.activeConns.Add(1)
		go s.servePlainConn(conn)
	}
}

func (s *Server) handlePlainConn(conn net.Conn) {
	Stats.ActiveConns.Add(1)
	Stats.TotalConns.Add(1)
	Stats.H1Conns.Add(1)
	logReqs := s.logRequests.Load()
	var addr string
	if logReqs || s.debug.Load() {
		addr = conn.RemoteAddr().String()
	}
	if logReqs {
		log.Printf("[CONN] %s connected (plain HTTP)", addr)
	}
	defer func() {
		conn.Close()
		Stats.ActiveConns.Add(-1)
		if logReqs {
			log.Printf("[CONN] %s disconnected", addr)
		}
	}()

	s.ServeH1Plain(conn)
}

func (s *Server) serveTLSConn(conn net.Conn) {
	var hdrBuf [5]byte
	s.handleConn(conn, hdrBuf[:])
	s.activeConns.Done()
}

func (s *Server) servePlainConn(conn net.Conn) {
	s.handlePlainConn(conn)
	s.activeConns.Done()
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
		if s.config.DefaultDomain != "" {
			s.certStore.SetDefault(s.config.DefaultDomain)
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
		return nil
	}

	certDER, privKey, err := LoadOrGenerateCert(s.config.TLSCertFile, s.config.TLSKeyFile)
	if err != nil {
		return err
	}
	s.certStore.AddCert(NewCertEntryFromDER("localhost", certDER, privKey, CertSelfSigned))
	return nil
}

func (s *Server) rebuildFallbackTLSConfig() {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
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

func (s *Server) acceptLoop(ln net.Listener, errCh chan<- error) {
	for {
		select {
		case <-s.done:
			return
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				log.Printf("accept: %v", err)
				continue
			}
		}
		s.activeConns.Add(1)
		go s.serveTLSConn(conn)
	}
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
		close(s.done)
		if s.acme != nil {
			s.acme.Stop()
		}
		if s.RateLimit != nil {
			s.RateLimit.Stop()
		}
		for _, ln := range s.listeners {
			ln.Close()
		}
	})

	waitDone := make(chan struct{})
	go func() {
		s.activeConns.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) handleConn(conn net.Conn, hdrBuf []byte) {
	Stats.ActiveConns.Add(1)
	Stats.TotalConns.Add(1)
	logReqs := s.logRequests.Load()
	var addr string
	if logReqs || s.debug.Load() {
		addr = conn.RemoteAddr().String()
	}
	if logReqs {
		log.Printf("[CONN] %s connected", addr)
	}
	defer func() {
		conn.Close()
		Stats.ActiveConns.Add(-1)
		if logReqs {
			log.Printf("[CONN] %s disconnected", addr)
		}
	}()

	conn.SetDeadline(timeNow().Add(s.config.HandshakeTimeout))

	ct, chRaw, chBP, err := ReadRecord(conn, hdrBuf)
	if err != nil {
		s.connLog("[%s] read ClientHello: %v", addr, err)
		return
	}

	if ct != 0x16 {
		s.connLog("[%s] expected handshake (0x16), got 0x%02x", addr, ct)
		ReleaseRecordBuf(chBP)
		return
	}

	ch, err := ParseClientHello(chRaw)
	if err != nil {
		s.connLog("[%s] parse ClientHello: %v", addr, err)
		ReleaseRecordBuf(chBP)
		return
	}
	Dbg("[%s] ClientHello: %d suites, ALPN: %v, SNI: %s, versions: %v",
		addr, len(ch.CipherSuites), ch.ALPNProtos, ch.ServerName, ch.SupportedVersions)

	certEntry := s.certStore.Lookup(ch.ServerName)
	if certEntry == nil {
		s.connLog("[%s] no certificate for SNI=%q", addr, ch.ServerName)
		ReleaseRecordBuf(chBP)
		return
	}

	if ch.SupportsTLS13() && certEntry.PrivKey != nil && ch.X25519PubKey != nil {
		s.handleTLS13(conn, hdrBuf, ch, chRaw, chBP, certEntry, addr)
	} else {
		s.handleTLSFallback(conn, hdrBuf, chRaw, chBP, addr)
	}
}

func (s *Server) handleTLS13(conn net.Conn, hdrBuf []byte, ch *ParsedClientHello, chRaw []byte, chBP *[]byte, certEntry *CertEntry, addr string) {
	defer ReleaseRecordBuf(chBP)

	cs := NegotiateSuite(ch.CipherSuites)
	if cs == nil {
		s.connLog("[%s] no common cipher suite", addr)
		return
	}
	Dbg("[%s] selected suite: 0x%04x", addr, cs.ID)

	selectedALPN := NegotiateALPN(ch.ALPNProtos)
	Dbg("[%s] ALPN: %q", addr, selectedALPN)

	transcript := cs.HashFn()
	transcript.Write(chRaw)

	var serverPriv [32]byte
	if _, err := rand.Read(serverPriv[:]); err != nil {
		s.connLog("[%s] rand.Read server private key: %v", addr, err)
		return
	}
	defer func() {
		for i := range serverPriv {
			serverPriv[i] = 0
		}
	}()
	serverPub, err := curve25519.X25519(serverPriv[:], curve25519.Basepoint)
	if err != nil {
		s.connLog("[%s] x25519 public: %v", addr, err)
		return
	}
	shared, err := curve25519.X25519(serverPriv[:], ch.X25519PubKey)
	if err != nil {
		s.connLog("[%s] x25519 shared: %v", addr, err)
		return
	}
	defer func() {
		for i := range shared {
			shared[i] = 0
		}
	}()
	DbgHex("Shared secret", shared)

	var srvRandom [32]byte
	if _, err := rand.Read(srvRandom[:]); err != nil {
		s.connLog("[%s] rand.Read server random: %v", addr, err)
		return
	}
	shMsg := BuildServerHello(srvRandom[:], ch.SessionID, cs.ID, serverPub)
	transcript.Write(shMsg)

	h := cs.HashFn
	hLen := cs.HashLen
	var zeroIKM [48]byte
	zeroSlice := zeroIKM[:hLen]
	emptyH := EmptyTranscriptHash(h)

	earlySecret := TLSExtract(h, zeroSlice, zeroSlice)
	derivedFromEarly := TLSDeriveSecret(h, hLen, earlySecret, "derived", emptyH)
	handshakeSecret := TLSExtract(h, derivedFromEarly, shared)

	hsHash := transcript.Sum(nil)
	DbgHex("Transcript hash (CH+SH)", hsHash)
	clientHSSecret := TLSDeriveSecret(h, hLen, handshakeSecret, "c hs traffic", hsHash)
	serverHSSecret := TLSDeriveSecret(h, hLen, handshakeSecret, "s hs traffic", hsHash)

	serverHSWriter, err := NewTrafficAEAD(h, serverHSSecret, cs)
	if err != nil {
		s.connLog("[%s] server HS AEAD: %v", addr, err)
		return
	}
	Dbg("[%s] Handshake keys derived", addr)

	ee := certEntry.CachedEE(selectedALPN)
	DbgHex("EncryptedExtensions", ee)
	certMsg := certEntry.cachedCertMsg
	transcript.Write(ee)
	transcript.Write(certMsg)

	sig, err := SignCertificateVerify(certEntry.PrivKey, transcript.Sum(nil))
	if err != nil {
		s.connLog("[%s] sign CertificateVerify: %v", addr, err)
		return
	}
	cv := BuildCertificateVerify(sig)
	transcript.Write(cv)

	srvVerifyData := ComputeFinished(h, hLen, serverHSSecret, transcript.Sum(nil))
	fin := BuildFinished(srvVerifyData)
	transcript.Write(fin)

	bp := LargeBufPool.Get().(*[]byte)
	inner := (*bp)[:0]
	inner = append(inner, ee...)
	inner = append(inner, certMsg...)
	inner = append(inner, cv...)
	inner = append(inner, fin...)
	inner = append(inner, 0x16)

	ciphertext := serverHSWriter.EncryptAppend(nil, inner)
	*bp = inner[:0]
	LargeBufPool.Put(bp)

	flightBP := LargeBufPool.Get().(*[]byte)
	flight := (*flightBP)[:0]
	flight = AppendRecord(flight, 0x16, shMsg)
	flight = AppendRecord(flight, 0x14, []byte{0x01})
	flight = AppendRecord(flight, 0x17, ciphertext)
	if _, err := conn.Write(flight); err != nil {
		*flightBP = flight[:0]
		LargeBufPool.Put(flightBP)
		s.connLog("[%s] write handshake flight: %v", addr, err)
		return
	}
	*flightBP = flight[:0]
	LargeBufPool.Put(flightBP)
	Dbg("[%s] Encrypted handshake flight sent (ALPN=%s)", addr, selectedALPN)

	derivedFromHS := TLSDeriveSecret(h, hLen, handshakeSecret, "derived", emptyH)
	masterSecret := TLSExtract(h, derivedFromHS, zeroSlice)
	appHash := transcript.Sum(nil)
	DbgHex("Transcript hash (CH..sFin)", appHash)

	clientAppSecret := TLSDeriveSecret(h, hLen, masterSecret, "c ap traffic", appHash)
	serverAppSecret := TLSDeriveSecret(h, hLen, masterSecret, "s ap traffic", appHash)
	Dbg("[%s] Application keys derived", addr)

	clientHSReader, err := NewTrafficAEAD(h, clientHSSecret, cs)
	if err != nil {
		s.connLog("[%s] client HS AEAD: %v", addr, err)
		return
	}

	finRecCT, finRec, finBP, err := ReadRecordSkipCCS(conn, hdrBuf)
	if err != nil {
		s.connLog("[%s] read client Finished: %v", addr, err)
		return
	}

	if finRecCT == 0x15 {
		if len(finRec) >= 2 {
			desc := finRec[1]
			reason := tlsAlertName(desc)
			s.connLog("[%s] TLS alert from client: %s (level=%d desc=%d)", addr, reason, finRec[0], desc)
		} else {
			s.connLog("[%s] TLS alert from client (truncated, len=%d)", addr, len(finRec))
		}
		ReleaseRecordBuf(finBP)
		return
	}

	if finRecCT != 0x17 {
		s.connLog("[%s] unexpected record type 0x%02x, expected application data (0x17)", addr, finRecCT)
		ReleaseRecordBuf(finBP)
		return
	}

	finPt, err := clientHSReader.Decrypt(finRec)
	if err != nil {
		s.connLog("[%s] decrypt client Finished: %v", addr, err)
		ReleaseRecordBuf(finBP)
		return
	}

	finContent, finCT, err := StripInnerPlaintext(finPt)
	if err != nil || finCT != 0x16 {
		if finCT == 0x15 && len(finContent) >= 2 {
			desc := finContent[1]
			reason := tlsAlertName(desc)
			s.connLog("[%s] TLS alert from client: %s (level=%d desc=%d)", addr, reason, finContent[0], desc)
		} else {
			s.connLog("[%s] bad inner type for Finished: 0x%02x err=%v", addr, finCT, err)
		}
		ReleaseRecordBuf(finBP)
		return
	}

	if len(finContent) < 4 || finContent[0] != 0x14 {
		s.connLog("[%s] not a Finished message", addr)
		ReleaseRecordBuf(finBP)
		return
	}
	clientVerify := finContent[4:]
	expectedVerify := ComputeFinished(h, hLen, clientHSSecret, appHash)
	if !hmac.Equal(clientVerify, expectedVerify) {
		s.connLog("[%s] client Finished verification FAILED", addr)
		ReleaseRecordBuf(finBP)
		return
	}
	ReleaseRecordBuf(finBP)
	Dbg("[%s] TLS 1.3 handshake complete!", addr)

	clientAppReader, err := NewTrafficAEAD(h, clientAppSecret, cs)
	if err != nil {
		s.connLog("[%s] client app AEAD: %v", addr, err)
		return
	}
	serverAppWriter, err := NewTrafficAEAD(h, serverAppSecret, cs)
	if err != nil {
		s.connLog("[%s] server app AEAD: %v", addr, err)
		return
	}

	conn.SetDeadline(time.Time{})
	if s.config.IdleTimeout > 0 {
		conn.SetDeadline(timeNow().Add(s.config.IdleTimeout))
	}

	if selectedALPN == "h2" {
		Stats.H2Conns.Add(1)
		if s.logRequests.Load() {
			log.Printf("[%s] serving HTTP/2 (TLS 1.3)", addr)
		}
		s.ServeH2(conn, clientAppReader, serverAppWriter, hdrBuf)
	} else {
		Stats.H1Conns.Add(1)
		if s.logRequests.Load() {
			log.Printf("[%s] serving HTTP/1.1 (TLS 1.3)", addr)
		}
		s.ServeH1(conn, clientAppReader, serverAppWriter, hdrBuf)
	}
}

func (s *Server) handleTLSFallback(conn net.Conn, hdrBuf []byte, chRaw []byte, chBP *[]byte, addr string) {
	fullRecord := make([]byte, 5+len(chRaw))
	copy(fullRecord[:5], hdrBuf[:5])
	copy(fullRecord[5:], chRaw)
	ReleaseRecordBuf(chBP)

	pc := &prefixConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(fullRecord), conn),
	}

	tlsCfg := s.fallbackTLS.Load()
	if tlsCfg == nil {
		s.connLog("[%s] no fallback TLS config", addr)
		return
	}

	tlsConn := tls.Server(pc, tlsCfg)
	defer tlsConn.Close()

	tlsConn.SetDeadline(timeNow().Add(s.config.HandshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		s.connLog("[%s] TLS fallback handshake: %v", addr, err)
		return
	}

	state := tlsConn.ConnectionState()
	ver := "TLS ?"
	switch state.Version {
	case tls.VersionTLS11:
		ver = "TLS 1.1"
	case tls.VersionTLS12:
		ver = "TLS 1.2"
	case tls.VersionTLS13:
		ver = "TLS 1.3"
	}

	tlsConn.SetDeadline(time.Time{})
	if s.config.IdleTimeout > 0 {
		tlsConn.SetDeadline(timeNow().Add(s.config.IdleTimeout))
	}

	if state.NegotiatedProtocol == "h2" {
		Stats.H2Conns.Add(1)
		if s.logRequests.Load() {
			log.Printf("[%s] serving HTTP/2 (%s fallback)", addr, ver)
		}
		s.ServeH2Plain(tlsConn)
	} else {
		Stats.H1Conns.Add(1)
		if s.logRequests.Load() {
			log.Printf("[%s] serving HTTP/1.1 (%s fallback)", addr, ver)
		}
		s.ServeH1Plain(tlsConn)
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
	w.headersSent = false
	w.flowCond = hc.flowCond
	return w
}

func (s *Server) NewH1StreamWriter(conn net.Conn, writer *TrafficAEAD) *H1StreamWriter {
	w := H1StreamWriterPool.Get().(*H1StreamWriter)
	w.conn = conn
	w.writer = writer
	w.limiter = s.connLimiter
	w.global = s.globalLimiter
	w.headersSent = false
	return w
}

func (s *Server) NewPlainH1StreamWriter(conn net.Conn) *PlainH1StreamWriter {
	w := PlainH1StreamWriterPool.Get().(*PlainH1StreamWriter)
	w.conn = conn
	w.limiter = s.connLimiter
	w.global = s.globalLimiter
	w.headersSent = false
	return w
}

func (s *Server) computeFastDispatch() {
	fast := s.RateLimit == nil &&
		s.config.MaxConcurrentReqs <= 0
	if pe := s.proxy.Load(); pe != nil {
		fast = false
	}
	s.fastDispatch.Store(fast)
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
}

func (s *Server) Proxy() *ProxyEngine {
	return s.proxy.Load()
}

// AddProxyDomain registers a reverse-proxy domain. If the ProxyEngine
// does not exist yet it is created automatically. Safe to call at runtime.
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
}

// RemoveProxyDomain removes a domain and cleans up health checkers
// and connection pools for all its backends.
func (s *Server) RemoveProxyDomain(domain string) {
	pe := s.proxy.Load()
	if pe != nil {
		pe.RemoveDomain(domain)
	}
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
}

// SetProxyCache enables proxy response caching. Cached responses are
// matched by method + host + path (query string stripped). Configure
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

func (s *Server) dispatch(req *Request, resp *Response) {
	limited := s.config.MaxConcurrentReqs > 0
	if limited {
		current := s.activeReqs.Add(1)
		if current > s.config.MaxConcurrentReqs {
			s.activeReqs.Add(-1)
			resp.Status(503).String("Service Unavailable")
			return
		}
	}

	if s.RateLimit != nil {
		ip := extractIP(req.RemoteAddr)
		if ip != "" {
			allowed, cr, retryAfter := s.RateLimit.Check(ip, req.Path)
			if !allowed {
				event := RateLimitEvent{
					IP:         ip,
					Path:       req.Path,
					RetryAfter: retryAfter,
				}
				if cr != nil {
					event.Rule = cr.rule
				}

				if cr != nil && cr.rule.OnLimit != nil {
					if cr.rule.OnLimit(event, req, resp) {
						if limited {
							s.activeReqs.Add(-1)
						}
						return
					}
				}
				if s.RateLimit.OnLimit != nil {
					if s.RateLimit.OnLimit(event, req, resp) {
						if limited {
							s.activeReqs.Add(-1)
						}
						return
					}
				}

				var buf [20]byte
				secs := appendUint(buf[:0], int64(retryAfter.Seconds())+1)
				resp.Status(429).
					SetHeaderUnsafe("retry-after", string(secs)).
					String("Too Many Requests")
				if limited {
					s.activeReqs.Add(-1)
				}
				return
			}
		}
	}

	pe := s.proxy.Load()
	if pe != nil && req.Host != "" {
		if !s.Router.Match(req.Method, req.Path) {
			if pe.Handle(req, resp) {
				if limited {
					s.activeReqs.Add(-1)
				}
				return
			}
		}
	}
	handler := s.Router.Lookup(req.Method, req.Path, req)
	handler(req, resp)

	if s.config.MaxWriteSize > 0 && int64(resp.BodyLen()) > s.config.MaxWriteSize {
		resp.Reset()
		resp.Status(500).String("Response Too Large")
	}
	if limited {
		s.activeReqs.Add(-1)
	}
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
	log.Printf("[HTTP-ROUTE] %d route(s) configured", len(routes))
}

func (s *Server) AddHTTPRoute(route HTTPRoute) {
	if s.httpRouter == nil {
		s.httpRouter = newHTTPRouter()
	}
	s.httpRouter.AddRoute(route)
	log.Printf("[HTTP-ROUTE] added: %s -> %s", route.PathPrefix, route.Backend)
}

func (s *Server) RemoveHTTPRoute(pathPrefix string) {
	if s.httpRouter != nil {
		s.httpRouter.RemoveRoute(pathPrefix)
		log.Printf("[HTTP-ROUTE] removed: %s", pathPrefix)
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
}

func (s *Server) UpdateCORS(cfg CORSConfig) {
	s.SetCORS(cfg)
}

func (s *Server) ensureRateLimit() {
	if s.RateLimit == nil {
		s.RateLimit = NewRateLimitEngine()
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
