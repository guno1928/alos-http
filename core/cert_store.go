package core

import (
	"crypto/ecdsa"
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

// CertConfig specifies a TLS certificate to load for a domain. Used with manual
// certificate management instead of ACME.
//
//	cfg := core.Config{
//	    Certs: []core.CertConfig{
//	        {
//	            Domain:   "example.com",
//	            CertFile: "/etc/ssl/example.com.pem",
//	            KeyFile:  "/etc/ssl/example.com-key.pem",
//	            Source:   core.CertManual,
//	        },
//	    },
//	}
type CertConfig struct {
	Domain   string
	CertFile string
	KeyFile  string
	Source   CertSource
}

type CertEntry struct {
	Domain   string
	ChainDER [][]byte
	PrivKey  *ecdsa.PrivateKey
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

type CertStore struct {
	certs    *alosmap.Map
	defEntry atomic.Pointer[CertEntry]
	mu       sync.Mutex
}

func NewCertStore() *CertStore {
	cs := &CertStore{
		certs: alosmap.New(alosmap.WithCapacity(32), alosmap.WithoutCleanup()),
	}
	return cs
}

func normalizeCertDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")
	return strings.ToLower(domain)
}

func (cs *CertStore) Lookup(serverName string) *CertEntry {
	serverName = normalizeCertDomain(serverName)
	if serverName != "" {
		if v, ok := cs.certs.Load(alosmap.S(serverName)); ok {
			return v.(*CertEntry)
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

func (cs *CertStore) AddCert(entry *CertEntry) {
	entry.Domain = normalizeCertDomain(entry.Domain)
	entry.initCachedHandshake()
	cs.certs.Store(alosmap.S(entry.Domain), entry)
	if cs.defEntry.Load() == nil {
		cs.defEntry.CompareAndSwap(nil, entry)
	}
}

func (cs *CertStore) RemoveCert(domain string) {
	domain = normalizeCertDomain(domain)
	cs.mu.Lock()
	cs.certs.Delete(alosmap.S(domain))
	if def := cs.defEntry.Load(); def != nil && def.Domain == domain {
		cs.defEntry.Store(nil)
		cs.certs.Range(func(_ alosmap.Key, v any) bool {
			cs.defEntry.Store(v.(*CertEntry))
			return false
		})
	}
	cs.mu.Unlock()
}

func (cs *CertStore) SetDefault(domain string) {
	domain = normalizeCertDomain(domain)
	v, ok := cs.certs.Load(alosmap.S(domain))
	if !ok {
		return
	}
	cs.defEntry.Store(v.(*CertEntry))
}

func (cs *CertStore) ListCerts() []CertInfo {
	var out []CertInfo
	cs.certs.Range(func(_ alosmap.Key, v any) bool {
		e := v.(*CertEntry)
		out = append(out, CertInfo{Domain: e.Domain, Source: e.Source})
		return true
	})
	return out
}

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

	var privKey *ecdsa.PrivateKey
	if k, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey); ok {
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

func NewCertEntryFromDER(domain string, certDER []byte, privKey *ecdsa.PrivateKey, source CertSource) *CertEntry {
	domain = normalizeCertDomain(domain)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		log.Printf("[CERT] failed to marshal EC private key for %s: %v", domain, err)
		return &CertEntry{
			Domain:   domain,
			ChainDER: [][]byte{certDER},
			PrivKey:  privKey,
			Source:   source,
		}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
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

func (s *Server) RemoveCert(domain string) {
	s.certStore.RemoveCert(domain)
	s.rebuildFallbackTLSConfig()
	log.Printf("[CERT] removed cert for %s", domain)
}

func (s *Server) SetDefaultCert(domain string) {
	s.certStore.SetDefault(domain)
	log.Printf("[CERT] default cert set to %s", domain)
}

func (s *Server) ListCerts() []CertInfo {
	return s.certStore.ListCerts()
}

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

func (s *Server) AddCerts(domain string, certPEM, keyPEM []byte) error {
	return s.AddCert(domain, certPEM, keyPEM)
}
