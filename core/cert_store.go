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
)

type CertSource uint8

const (
	CertSelfSigned CertSource = iota
	CertManual
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

type CertInfo struct {
	Domain string
	Source CertSource
}

type certSnapshot struct {
	byDomain map[string]*CertEntry
	defEntry *CertEntry
}

type CertStore struct {
	snapshot atomic.Pointer[certSnapshot]
	mu       sync.Mutex
}

func NewCertStore() *CertStore {
	cs := &CertStore{}
	snap := &certSnapshot{byDomain: make(map[string]*CertEntry, 4)}
	cs.snapshot.Store(snap)
	return cs
}

func normalizeCertDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")
	return strings.ToLower(domain)
}

func (cs *CertStore) Lookup(serverName string) *CertEntry {
	snap := cs.snapshot.Load()
	serverName = normalizeCertDomain(serverName)
	if serverName != "" {
		if entry, ok := snap.byDomain[serverName]; ok {
			return entry
		}
	}
	return snap.defEntry
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
	cs.mu.Lock()
	old := cs.snapshot.Load()
	newMap := make(map[string]*CertEntry, len(old.byDomain)+1)
	for k, v := range old.byDomain {
		newMap[k] = v
	}
	newMap[entry.Domain] = entry
	snap := &certSnapshot{byDomain: newMap, defEntry: old.defEntry}
	if snap.defEntry == nil {
		snap.defEntry = entry
	}
	cs.snapshot.Store(snap)
	cs.mu.Unlock()
}

func (cs *CertStore) RemoveCert(domain string) {
	domain = normalizeCertDomain(domain)
	cs.mu.Lock()
	old := cs.snapshot.Load()
	newMap := make(map[string]*CertEntry, len(old.byDomain))
	for k, v := range old.byDomain {
		if k != domain {
			newMap[k] = v
		}
	}
	snap := &certSnapshot{byDomain: newMap, defEntry: old.defEntry}
	if snap.defEntry != nil && snap.defEntry.Domain == domain {
		snap.defEntry = nil
		for _, v := range newMap {
			snap.defEntry = v
			break
		}
	}
	cs.snapshot.Store(snap)
	cs.mu.Unlock()
}

func (cs *CertStore) SetDefault(domain string) {
	domain = normalizeCertDomain(domain)
	cs.mu.Lock()
	old := cs.snapshot.Load()
	entry, ok := old.byDomain[domain]
	if !ok {
		cs.mu.Unlock()
		return
	}
	snap := &certSnapshot{byDomain: old.byDomain, defEntry: entry}
	cs.snapshot.Store(snap)
	cs.mu.Unlock()
}

func (cs *CertStore) ListCerts() []CertInfo {
	snap := cs.snapshot.Load()
	out := make([]CertInfo, 0, len(snap.byDomain))
	for _, e := range snap.byDomain {
		out = append(out, CertInfo{Domain: e.Domain, Source: e.Source})
	}
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
