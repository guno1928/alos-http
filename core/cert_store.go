package core

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/guno1928/alosmap"
)

// CertSource identifies how a TLS certificate was obtained.
type CertSource uint8

const (
	// CertSelfSigned indicates the certificate was auto-generated for development.
	CertSelfSigned CertSource = iota
	// CertManual indicates the certificate was loaded from PEM files.
	CertManual
	// CertACME indicates the certificate was provisioned via ACME (Let's Encrypt).
	CertACME
)

// CertConfig specifies a TLS certificate to load for a domain, passed via
// Config.Certs.
//
// Domain is the SNI hostname the certificate serves.
//
//	Example: Domain: "example.com".
//
// CertFile is the path to a PEM-encoded certificate (or chain); used when
// Source is CertManual.
//
//	Example: CertFile: "/etc/ssl/example.com.pem".
//
// KeyFile is the path to the PEM-encoded private key matching CertFile; used
// when Source is CertManual.
//
//	Example: KeyFile: "/etc/ssl/example.com-key.pem".
//
// Source selects how the certificate is obtained: CertManual reads CertFile
// and KeyFile, CertSelfSigned generates a self-signed certificate for Domain
// (CertFile and KeyFile are ignored), and CertACME provisions the certificate
// through ACME.
//
//	Example: Source: core.CertManual.
//	Example: Source: core.CertSelfSigned.
type CertConfig struct {
	Domain   string
	CertFile string
	KeyFile  string
	Source   CertSource
}

// CertEntry holds a loaded TLS certificate and its private key, along with
// pre-serialized TLS 1.3 handshake messages cached per ALPN protocol. Build
// one with NewCertEntryFromPEM or NewCertEntryFromDER.
type CertEntry struct {
	Domain   string
	ChainDER [][]byte
	PrivKey  crypto.Signer
	TLSCert  tls.Certificate
	Source   CertSource

	cachedCertMsg     []byte
	cachedEEH1        []byte
	cachedEEH2        []byte
	cachedEEEmpty     []byte
	cachedEECertH1    []byte
	cachedEECertH2    []byte
	cachedEECertEmpty []byte
}

// CertInfo is a read-only summary of a loaded certificate returned by
// Server.ListCerts. Domain is the SNI hostname and Source indicates how
// the certificate was obtained.
type CertInfo struct {
	Domain string
	Source CertSource
}

// CertStore is a concurrent registry of CertEntry values keyed by domain,
// used to resolve the certificate for a TLS ClientHello via SNI. Create one
// with NewCertStore.
type CertStore struct {
	certs    *alosmap.TypedMap[string, *CertEntry]
	defEntry atomic.Pointer[CertEntry]
	mu       sync.Mutex
}

// NewCertStore returns an empty CertStore.
func NewCertStore() *CertStore {
	cs := &CertStore{
		certs: alosmap.NewTypedSized[string, *CertEntry](32, 0).Prealloc(256),
	}
	return cs
}

func normalizeCertDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")
	return strings.ToLower(domain)
}

// Lookup returns the CertEntry registered for serverName (case-insensitively,
// with any trailing dot trimmed), falling back to the store's default entry
// when serverName is empty or unregistered. It returns nil if the store has
// no entries at all.
//
// Example: entry := certStore.Lookup(hello.ServerName)
func (cs *CertStore) Lookup(serverName string) *CertEntry {
	serverName = normalizeCertDomain(serverName)
	if serverName != "" {
		if v, ok := cs.certs.Load(serverName); ok {
			return v
		}
	}
	return cs.defEntry.Load()
}

func (entry *CertEntry) initCachedHandshake() {
	if entry.cachedCertMsg == nil && len(entry.ChainDER) > 0 {
		entry.cachedCertMsg = BuildCertificate(entry.ChainDER)
	}
	if entry.cachedEEH1 == nil {
		entry.cachedEEH1 = BuildEncryptedExtensions("http/1.1")
		entry.cachedEEH2 = BuildEncryptedExtensions("h2")
		entry.cachedEEEmpty = BuildEncryptedExtensions("")
	}
	if entry.cachedEECertH1 == nil {
		entry.cachedEECertH1 = append(append(make([]byte, 0, len(entry.cachedEEH1)+len(entry.cachedCertMsg)), entry.cachedEEH1...), entry.cachedCertMsg...)
		entry.cachedEECertH2 = append(append(make([]byte, 0, len(entry.cachedEEH2)+len(entry.cachedCertMsg)), entry.cachedEEH2...), entry.cachedCertMsg...)
		entry.cachedEECertEmpty = append(append(make([]byte, 0, len(entry.cachedEEEmpty)+len(entry.cachedCertMsg)), entry.cachedEEEmpty...), entry.cachedCertMsg...)
	}
}

// CachedEE returns the pre-serialized TLS 1.3 EncryptedExtensions message for
// the negotiated ALPN protocol ("h2" or "http/1.1"), or the ALPN-less variant
// for any other value.
//
// Example: ee := entry.CachedEE("h2")
func (entry *CertEntry) CachedEE(alpn string) []byte {
	switch alpn {
	case "h2":
		return entry.cachedEEH2
	case "http/1.1":
		return entry.cachedEEH1
	default:
		return entry.cachedEEEmpty
	}
}

// CachedEECert returns the pre-serialized EncryptedExtensions and Certificate
// messages concatenated for the negotiated ALPN protocol ("h2" or
// "http/1.1"), or the ALPN-less variant for any other value.
//
// Example: eeCert := entry.CachedEECert("http/1.1")
func (entry *CertEntry) CachedEECert(alpn string) []byte {
	switch alpn {
	case "h2":
		return entry.cachedEECertH2
	case "http/1.1":
		return entry.cachedEECertH1
	default:
		return entry.cachedEECertEmpty
	}
}

// AddCert registers entry under its (normalized) Domain, precomputing its
// cached TLS handshake messages, and makes it the store's default
// certificate if none is set yet.
//
// Example: certStore.AddCert(entry)
func (cs *CertStore) AddCert(entry *CertEntry) {
	entry.Domain = normalizeCertDomain(entry.Domain)
	entry.initCachedHandshake()
	cs.certs.Store(entry.Domain, entry)
	if cs.defEntry.Load() == nil {
		cs.defEntry.CompareAndSwap(nil, entry)
	}
}

// RemoveCert removes the certificate registered for domain; if it was the
// store's default, an arbitrary remaining certificate (if any) becomes the
// new default.
//
// Example: certStore.RemoveCert("old.example.com")
func (cs *CertStore) RemoveCert(domain string) {
	domain = normalizeCertDomain(domain)
	cs.mu.Lock()
	cs.certs.Delete(domain)
	if def := cs.defEntry.Load(); def != nil && def.Domain == domain {
		cs.defEntry.Store(nil)
		cs.certs.Range(func(_ string, v *CertEntry) bool {
			cs.defEntry.Store(v)
			return false
		})
	}
	cs.mu.Unlock()
}

// SetDefault makes the certificate registered for domain the store's default
// entry, used when a ClientHello's SNI has no exact match. It is a no-op if
// domain is not registered.
//
// Example: certStore.SetDefault("example.com")
func (cs *CertStore) SetDefault(domain string) {
	domain = normalizeCertDomain(domain)
	v, ok := cs.certs.Load(domain)
	if !ok {
		return
	}
	cs.defEntry.Store(v)
}

// ListCerts returns a snapshot of every registered certificate's domain and
// source.
func (cs *CertStore) ListCerts() []CertInfo {
	var out []CertInfo
	cs.certs.Range(func(_ string, e *CertEntry) bool {
		out = append(out, CertInfo{Domain: e.Domain, Source: e.Source})
		return true
	})
	return out
}

// NewCertEntryFromPEM builds a CertEntry for domain from a PEM-encoded
// certificate chain and private key, recording source as how the certificate
// was obtained. It returns an error if certPEM and keyPEM do not form a
// valid key pair or certPEM contains no certificate.
//
// Example: entry, err := NewCertEntryFromPEM("example.com", certPEM, keyPEM, CertManual)
func NewCertEntryFromPEM(domain string, certPEM, keyPEM []byte, source CertSource) (*CertEntry, error) {
	domain = normalizeCertDomain(domain)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	var chainDER [][]byte
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chainDER = append(chainDER, block.Bytes)
		}
	}
	if len(chainDER) == 0 {
		return nil, &staticError{"invalid cert PEM"}
	}

	var privKey crypto.Signer
	if k, ok := tlsCert.PrivateKey.(crypto.Signer); ok {
		privKey = k
	}

	return &CertEntry{
		Domain:   domain,
		ChainDER: chainDER,
		PrivKey:  privKey,
		TLSCert:  tlsCert,
		Source:   source,
	}, nil
}

// NewCertEntryFromDER builds a CertEntry for domain from a single
// DER-encoded certificate and its private key, recording source as how the
// certificate was obtained. If the key cannot be marshaled or paired with
// the certificate, it logs the failure and returns an entry with an unset
// TLSCert.
//
// Example: entry := NewCertEntryFromDER("example.com", certDER, privKey, CertSelfSigned)
func NewCertEntryFromDER(domain string, certDER []byte, privKey crypto.Signer, source CertSource) *CertEntry {
	domain = normalizeCertDomain(domain)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		log.Printf("[CERT] failed to marshal private key for %s: %v", domain, err)
		return &CertEntry{
			Domain:   domain,
			ChainDER: [][]byte{certDER},
			PrivKey:  privKey,
			Source:   source,
		}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Printf("[CERT] failed to create TLS cert for %s: %v", domain, err)
	}

	return &CertEntry{
		Domain:   domain,
		ChainDER: [][]byte{certDER},
		PrivKey:  privKey,
		TLSCert:  tlsCert,
		Source:   source,
	}
}

// AddCert loads a certificate and private key from PEM-encoded bytes,
// registers it for domain (source CertManual), and rebuilds the server's TLS
// configuration.
//
// Example: err := srv.AddCert("example.com", certPEM, keyPEM)
func (s *Server) AddCert(domain string, certPEM, keyPEM []byte) error {
	entry, err := NewCertEntryFromPEM(domain, certPEM, keyPEM, CertManual)
	if err != nil {
		return err
	}
	s.certStore.AddCert(entry)
	s.rebuildFallbackTLSConfig()
	log.Printf("[CERT] added cert for %s (manual)", domain)
	return nil
}

// AddCertFromFiles reads certFile and keyFile from disk and registers them
// for domain via AddCert.
//
// Example: err := srv.AddCertFromFiles("example.com", "cert.pem", "key.pem")
func (s *Server) AddCertFromFiles(domain, certFile, keyFile string) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	return s.AddCert(domain, certPEM, keyPEM)
}

// AddSelfSignedCert generates and registers a self-signed certificate for
// domain, rebuilding the server's TLS configuration. It is intended for
// local development.
//
// Example: err := srv.AddSelfSignedCert("localhost")
func (s *Server) AddSelfSignedCert(domain string) error {
	der, priv, err := GenerateSelfSignedForDomain(domain)
	if err != nil {
		return err
	}
	s.certStore.AddCert(NewCertEntryFromDER(domain, der, priv, CertSelfSigned))
	s.rebuildFallbackTLSConfig()
	log.Printf("[CERT] added self-signed cert for %s", domain)
	return nil
}

// RemoveCert removes the certificate registered for domain and rebuilds the
// server's TLS configuration.
//
// Example: srv.RemoveCert("old.example.com")
func (s *Server) RemoveCert(domain string) {
	s.certStore.RemoveCert(domain)
	s.rebuildFallbackTLSConfig()
	log.Printf("[CERT] removed cert for %s", domain)
}

// SetDefaultCert makes the certificate registered for domain the server's
// default, used when a TLS ClientHello carries no matching SNI.
//
// Example: srv.SetDefaultCert("example.com")
func (s *Server) SetDefaultCert(domain string) {
	s.certStore.SetDefault(domain)
	log.Printf("[CERT] default cert set to %s", domain)
}

// ListCerts returns a snapshot of every certificate registered on the
// server.
func (s *Server) ListCerts() []CertInfo {
	return s.certStore.ListCerts()
}

// ReloadCert reads certFile and keyFile from disk and re-registers the
// certificate for domain, rebuilding the server's TLS configuration.
//
// Example: err := srv.ReloadCert("example.com", "cert.pem", "key.pem")
func (s *Server) ReloadCert(domain, certFile, keyFile string) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	entry, err := NewCertEntryFromPEM(domain, certPEM, keyPEM, CertManual)
	if err != nil {
		return err
	}
	s.certStore.AddCert(entry)
	s.rebuildFallbackTLSConfig()
	log.Printf("[CERT] reloaded cert for %s", domain)
	return nil
}

// UpdateCert replaces the certificate registered for domain with the given
// PEM-encoded certificate and key, rebuilding the server's TLS
// configuration.
//
// Example: err := srv.UpdateCert("example.com", newCertPEM, newKeyPEM)
func (s *Server) UpdateCert(domain string, certPEM, keyPEM []byte) error {
	entry, err := NewCertEntryFromPEM(domain, certPEM, keyPEM, CertManual)
	if err != nil {
		return err
	}
	s.certStore.AddCert(entry)
	s.rebuildFallbackTLSConfig()
	log.Printf("[CERT] updated cert for %s", domain)
	return nil
}

// AddCerts is an alias for AddCert.
//
// Example: err := srv.AddCerts("example.com", certPEM, keyPEM)
func (s *Server) AddCerts(domain string, certPEM, keyPEM []byte) error {
	return s.AddCert(domain, certPEM, keyPEM)
}
