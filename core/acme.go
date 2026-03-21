package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
)

// ACMEConfig configures automatic TLS certificate provisioning through Let's
// Encrypt (or any ACME-compatible CA). Pass this in the server Config to enable
// automatic certificate management.
//
//	cfg := core.Config{
//	    ACME: &core.ACMEConfig{
//	        Email:    "admin@example.com",
//	        CacheDir: "/var/certs",
//	        Domains:  []string{"example.com", "www.example.com"},
//	    },
//	}
type ACMEConfig struct {
	Email    string
	CacheDir string
	Domains  []string
	ACMENode string
}

const (
	acmeRetryInterval   = 5 * time.Minute
	acmeRetryMax        = 3
	acmeLongWait        = 24 * time.Hour
	acmeRenewBefore     = 30 * 24 * time.Hour
	acmeRenewCheckEvery = 6 * time.Hour
)

type acmeIntegration struct {
	server   *Server
	client   *acme.Client
	email    string
	cacheDir string
	acmeNode string

	challengeDir string

	domains     []string
	domainMu    sync.Mutex
	initialOnce sync.Once

	challenges sync.Map

	localIPs atomic.Pointer[[]net.IP]
	stop     chan struct{}
}

type acmeChallenge struct {
	token string
	auth  string
}

func acmePrintf(format string, args ...any) {
	if debugFlag.Load() {
		log.Printf(format, args...)
		return
	}
	lower := strings.ToLower(format)
	if strings.Contains(lower, "failed") || strings.Contains(lower, "warning") || strings.Contains(lower, "obtained cert") || strings.Contains(lower, "renewal failed") || strings.Contains(lower, "renewal succeeded") {
		log.Printf(format, args...)
	}
}

func newACMEIntegration(cfg ACMEConfig, s *Server) *acmeIntegration {
	if cfg.CacheDir == "" {
		cfg.CacheDir = "/etc/letsencrypt"
	}
	directoryURL := acme.LetsEncryptURL
	if cfg.ACMENode != "" {
		directoryURL = cfg.ACMENode
	}

	for _, sub := range []string{"live", "archive", "renewal"} {
		dir := filepath.Join(cfg.CacheDir, sub)
		if err := os.MkdirAll(dir, 0700); err != nil {
			acmePrintf("[ACME] failed to create dir %s: %v", dir, err)
		}
	}

	challengeDir := filepath.Join(cfg.CacheDir, ".well-known", "acme-challenge")
	if err := os.MkdirAll(challengeDir, 0700); err != nil {
		acmePrintf("[ACME] failed to create challenge dir %s: %v", challengeDir, err)
	}
	acmePrintf("[ACME] challenge dir: %s", challengeDir)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		acmePrintf("[ACME] account key generation failed: %v", err)
		return nil
	}

	ai := &acmeIntegration{
		server:       s,
		email:        cfg.Email,
		cacheDir:     cfg.CacheDir,
		acmeNode:     cfg.ACMENode,
		challengeDir: challengeDir,
		domains:      cfg.Domains,
		stop:         make(chan struct{}),
		client: &acme.Client{
			Key:          key,
			DirectoryURL: directoryURL,
		},
	}

	acmePrintf("[ACME] account email: %s", cfg.Email)
	acmePrintf("[ACME] LE directory: %s", directoryURL)
	ai.refreshLocalIPs()
	return ai
}

func (ai *acmeIntegration) refreshLocalIPs() {
	ips := gatherPublicIPv4()
	ai.localIPs.Store(&ips)
	if len(ips) == 0 {
		acmePrintf("[ACME] WARNING: no public IPv4 addresses detected on this machine")
		acmePrintf("[ACME] listing all interface addresses for debugging:")
		logAllInterfaces()
	} else {
		strs := make([]string, 0, len(ips))
		for _, ip := range ips {
			strs = append(strs, ip.String())
		}
		acmePrintf("[ACME] detected public IPs: %s", strings.Join(strs, ", "))
	}
}

func logAllInterfaces() {
	ifaces, err := net.Interfaces()
	if err != nil {
		acmePrintf("[ACME]   interfaces error: %v", err)
		return
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			acmePrintf("[ACME]   %s: %s (flags: %v)", iface.Name, a.String(), iface.Flags)
		}
	}
}

func gatherPublicIPv4() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]net.IP, 0, 4)
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagUp == 0 || ifaces[i].Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			if isPrivateIPv4(ip4) {
				continue
			}
			out = append(out, ip4)
		}
	}
	return out
}

func isPrivateIPv4(ip net.IP) bool {
	return ip[0] == 10 ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168) ||
		(ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127)
}

func (ai *acmeIntegration) domainPointsHere(domain string) bool {
	addrs, err := net.LookupHost(domain)
	if err != nil {
		acmePrintf("[ACME] DNS lookup for %s failed: %v", domain, err)
		return false
	}
	if len(addrs) == 0 {
		acmePrintf("[ACME] DNS lookup for %s returned no records", domain)
		return false
	}

	acmePrintf("[ACME] DNS lookup for %s returned: %v", domain, addrs)

	localIPs := ai.localIPs.Load()
	if localIPs == nil || len(*localIPs) == 0 {
		acmePrintf("[ACME] no local IPs detected, cannot verify domain %s", domain)
		return false
	}

	for _, a := range addrs {
		resolved := net.ParseIP(a)
		if resolved == nil {
			continue
		}
		resolved4 := resolved.To4()
		if resolved4 == nil {
			continue
		}
		for _, lip := range *localIPs {
			if lip.Equal(resolved4) {
				acmePrintf("[ACME] %s -> %s matches local IP %s", domain, a, lip.String())
				return true
			}
		}
	}

	localStrs := make([]string, 0, len(*localIPs))
	for _, lip := range *localIPs {
		localStrs = append(localStrs, lip.String())
	}
	acmePrintf("[ACME] %s does not resolve to any local IP (domain: %v, local: %v)", domain, addrs, localStrs)
	return false
}

func (ai *acmeIntegration) HandleHTTP01(path string) ([]byte, bool) {
	const prefix = "/.well-known/acme-challenge/"
	if len(path) <= len(prefix) || path[:len(prefix)] != prefix {
		return nil, false
	}
	token := path[len(prefix):]

	for i := 0; i < len(token); i++ {
		if token[i] == '/' || token[i] == '\\' || token[i] == '.' || token[i] == 0 {
			acmePrintf("[ACME] HTTP-01 challenge rejected: invalid token characters")
			return nil, false
		}
	}
	if token == "" {
		return nil, false
	}

	acmePrintf("[ACME] HTTP-01 challenge request: token=%s", token)

	var found *acmeChallenge
	ai.challenges.Range(func(_, val any) bool {
		ch := val.(*acmeChallenge)
		if ch.token == token {
			found = ch
			return false
		}
		return true
	})
	if found != nil {
		acmePrintf("[ACME] HTTP-01 challenge served from memory: token=%s len=%d", token, len(found.auth))
		return UnsafeBytes(found.auth), true
	}

	filePath := filepath.Join(ai.challengeDir, token)
	data, err := os.ReadFile(filePath)
	if err == nil && len(data) > 0 {
		acmePrintf("[ACME] HTTP-01 challenge served from disk: %s len=%d", filePath, len(data))
		return data, true
	}

	acmePrintf("[ACME] HTTP-01 challenge NOT FOUND: token=%s (checked memory + disk at %s)", token, filePath)
	return nil, false
}

func (ai *acmeIntegration) Start() {
	go ai.runLoop()
}

func (ai *acmeIntegration) Stop() {
	close(ai.stop)
}

func (ai *acmeIntegration) runLoop() {
	ai.primeInitial()

	ticker := time.NewTicker(acmeRenewCheckEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ai.stop:
			return
		case <-ticker.C:
			ai.refreshLocalIPs()
			ai.renewAll()
		}
	}
}

func (ai *acmeIntegration) primeInitial() {
	if ai == nil {
		return
	}
	ai.initialOnce.Do(func() {
		ai.initialObtainAll()
	})
}

func (ai *acmeIntegration) domainsSnapshot() []string {
	if ai == nil {
		return nil
	}
	ai.domainMu.Lock()
	defer ai.domainMu.Unlock()
	out := make([]string, len(ai.domains))
	copy(out, ai.domains)
	return out
}

func (ai *acmeIntegration) initialObtainAll() {
	ai.domainMu.Lock()
	domains := make([]string, len(ai.domains))
	copy(domains, ai.domains)
	ai.domainMu.Unlock()

	for _, domain := range domains {
		if ai.tryLoadCached(domain) {
			continue
		}
		ai.obtainWithRetry(domain)
	}
}

func (ai *acmeIntegration) tryLoadCached(domain string) bool {
	certPath := filepath.Join(ai.cacheDir, "live", domain, "fullchain.pem")
	keyPath := filepath.Join(ai.cacheDir, "live", domain, "privkey.pem")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		acmePrintf("[ACME] no cached cert for %s at %s", domain, certPath)
		return false
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		acmePrintf("[ACME] no cached key for %s at %s", domain, keyPath)
		return false
	}

	entry, err := NewCertEntryFromPEM(domain, certPEM, keyPEM, CertACME)
	if err != nil {
		acmePrintf("[ACME] cached cert for %s failed to parse: %v", domain, err)
		return false
	}

	leaf, err := x509.ParseCertificate(entry.ChainDER[0])
	if err != nil {
		acmePrintf("[ACME] cached cert for %s failed to parse leaf: %v", domain, err)
		return false
	}
	if time.Until(leaf.NotAfter) < 0 {
		acmePrintf("[ACME] cached cert for %s expired on %s, will re-obtain", domain, leaf.NotAfter.Format("2006-01-02"))
		return false
	}

	ai.server.certStore.AddCert(entry)
	if ai.server.config.DefaultDomain != "" {
		ai.server.certStore.SetDefault(ai.server.config.DefaultDomain)
	}
	ai.server.rebuildFallbackTLSConfig()
	daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
	acmePrintf("[ACME] loaded cached cert for %s (%d days remaining, expires %s)", domain, daysLeft, leaf.NotAfter.Format("2006-01-02"))
	return true
}

func (ai *acmeIntegration) obtainWithRetry(domain string) {
	if !ai.domainPointsHere(domain) {
		acmePrintf("[ACME] %s does not point to this machine, will retry in 24h", domain)
		go ai.deferredObtain(domain)
		return
	}

	for attempt := 1; attempt <= acmeRetryMax; attempt++ {
		acmePrintf("[ACME] obtaining cert for %s (attempt %d/%d)", domain, attempt, acmeRetryMax)
		err := ai.obtain(domain)
		if err == nil {
			return
		}
		acmePrintf("[ACME] attempt %d/%d for %s FAILED: %v", attempt, acmeRetryMax, domain, err)
		if attempt < acmeRetryMax {
			acmePrintf("[ACME] waiting 5 minutes before retry...")
			select {
			case <-ai.stop:
				return
			case <-time.After(acmeRetryInterval):
			}
		}
	}
	acmePrintf("[ACME] all %d attempts exhausted for %s, will retry in 24h", acmeRetryMax, domain)
	go ai.deferredObtain(domain)
}

func (ai *acmeIntegration) deferredObtain(domain string) {
	select {
	case <-ai.stop:
		return
	case <-time.After(acmeLongWait):
	}
	ai.refreshLocalIPs()
	ai.obtainWithRetry(domain)
}

func (ai *acmeIntegration) obtain(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	acct := &acme.Account{}
	if ai.email != "" {
		acct.Contact = []string{"mailto:" + ai.email}
	}
	acmePrintf("[ACME] registering account with Let's Encrypt...")
	_, err := ai.client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "already") || strings.Contains(errStr, "existing") || strings.Contains(errStr, "conflict") {
			acmePrintf("[ACME] account already registered (ok)")
		} else {
			if acmeErr, ok := err.(*acme.Error); ok && acmeErr.StatusCode == 409 {
				acmePrintf("[ACME] account already registered (409, ok)")
			} else {
				acmePrintf("[ACME] registration failed: %v", err)
				return err
			}
		}
	} else {
		acmePrintf("[ACME] account registered successfully")
	}

	acmePrintf("[ACME] creating order for %s...", domain)
	order, err := ai.client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		acmePrintf("[ACME] authorize order failed for %s: %v", domain, err)
		return err
	}
	acmePrintf("[ACME] order created, %d authorization(s)", len(order.AuthzURLs))

	for i, authzURL := range order.AuthzURLs {
		acmePrintf("[ACME] processing authorization %d/%d: %s", i+1, len(order.AuthzURLs), authzURL)
		authz, err := ai.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			acmePrintf("[ACME] get authorization failed: %v", err)
			return err
		}
		acmePrintf("[ACME] authorization status: %s", authz.Status)
		if authz.Status == acme.StatusValid {
			acmePrintf("[ACME] authorization already valid, skipping")
			continue
		}

		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			acmePrintf("[ACME]   available challenge: type=%s status=%s", c.Type, c.Status)
			if c.Type == "http-01" {
				chal = c
			}
		}
		if chal == nil {
			acmePrintf("[ACME] no http-01 challenge offered for %s", domain)
			return &staticError{"no http-01 challenge offered for " + domain}
		}

		keyAuth, err := ai.client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			acmePrintf("[ACME] computing challenge response failed: %v", err)
			return err
		}
		acmePrintf("[ACME] challenge token: %s", chal.Token)
		acmePrintf("[ACME] key authorization length: %d", len(keyAuth))

		ai.challenges.Store(domain, &acmeChallenge{
			token: chal.Token,
			auth:  keyAuth,
		})

		tokenFile := filepath.Join(ai.challengeDir, chal.Token)
		if err := os.WriteFile(tokenFile, []byte(keyAuth), 0600); err != nil {
			acmePrintf("[ACME] WARNING: failed to write challenge file %s: %v", tokenFile, err)
		} else {
			acmePrintf("[ACME] wrote challenge file: %s", tokenFile)
		}

		acmePrintf("[ACME] challenge ready at http://%s/.well-known/acme-challenge/%s", domain, chal.Token)
		acmePrintf("[ACME] accepting challenge, telling LE to validate...")

		if _, err := ai.client.Accept(ctx, chal); err != nil {
			acmePrintf("[ACME] accept challenge failed: %v", err)
			ai.cleanupChallenge(domain, chal.Token)
			return err
		}

		acmePrintf("[ACME] waiting for LE validation...")
		finalAuthz, err := ai.client.WaitAuthorization(ctx, authzURL)
		if err != nil {
			acmePrintf("[ACME] authorization FAILED for %s: %v", domain, err)
			ai.cleanupChallenge(domain, chal.Token)
			return err
		}
		acmePrintf("[ACME] authorization succeeded: status=%s", finalAuthz.Status)
		ai.cleanupChallenge(domain, chal.Token)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{domain},
	}, certKey)
	if err != nil {
		return err
	}

	acmePrintf("[ACME] finalizing order for %s...", domain)
	der, _, err := ai.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		acmePrintf("[ACME] finalize order failed for %s: %v", domain, err)
		return err
	}
	acmePrintf("[ACME] received %d certificate(s) in chain", len(der))

	var certBuf []byte
	for _, d := range der {
		certBuf = append(certBuf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}

	keyBytes, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	entry, err := NewCertEntryFromPEM(domain, certBuf, keyPEM, CertACME)
	if err != nil {
		acmePrintf("[ACME] failed to parse obtained cert for %s: %v", domain, err)
		return err
	}
	ai.server.certStore.AddCert(entry)
	if ai.server.config.DefaultDomain != "" {
		ai.server.certStore.SetDefault(ai.server.config.DefaultDomain)
	}
	ai.server.rebuildFallbackTLSConfig()

	liveDir := filepath.Join(ai.cacheDir, "live", domain)
	archiveDir := filepath.Join(ai.cacheDir, "archive", domain)
	for _, d := range []string{liveDir, archiveDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			acmePrintf("[ACME] WARNING: failed to create dir %s: %v", d, err)
		}
	}

	archiveCert := filepath.Join(archiveDir, "fullchain1.pem")
	archiveKey := filepath.Join(archiveDir, "privkey1.pem")
	if err := os.WriteFile(archiveCert, certBuf, 0644); err != nil {
		acmePrintf("[ACME] WARNING: failed to save archived cert to %s: %v", archiveCert, err)
	}
	if err := os.WriteFile(archiveKey, keyPEM, 0600); err != nil {
		acmePrintf("[ACME] WARNING: failed to save archived key to %s: %v", archiveKey, err)
	}

	certPath := filepath.Join(liveDir, "fullchain.pem")
	keyPath := filepath.Join(liveDir, "privkey.pem")
	chainPath := filepath.Join(liveDir, "chain.pem")
	certOnlyPath := filepath.Join(liveDir, "cert.pem")

	if err := os.WriteFile(certPath, certBuf, 0644); err != nil {
		acmePrintf("[ACME] WARNING: failed to save cert to %s: %v", certPath, err)
	} else {
		acmePrintf("[ACME] saved cert to %s", certPath)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		acmePrintf("[ACME] WARNING: failed to save key to %s: %v", keyPath, err)
	} else {
		acmePrintf("[ACME] saved key to %s", keyPath)
	}

	var leafPEM, chainPEMData []byte
	rest := certBuf
	first := true
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		encoded := pem.EncodeToMemory(block)
		if first {
			leafPEM = encoded
			first = false
		} else {
			chainPEMData = append(chainPEMData, encoded...)
		}
	}
	if err := os.WriteFile(certOnlyPath, leafPEM, 0644); err != nil {
		acmePrintf("[ACME] WARNING: failed to save leaf cert to %s: %v", certOnlyPath, err)
	}
	if err := os.WriteFile(chainPath, chainPEMData, 0644); err != nil {
		acmePrintf("[ACME] WARNING: failed to save chain cert to %s: %v", chainPath, err)
	}

	renewalConf := filepath.Join(ai.cacheDir, "renewal", domain+".conf")
	renewalData := "# ALOS auto-generated renewal config\n" +
		"[renewalparams]\n" +
		"account = alos-managed\n" +
		"authenticator = http-01\n" +
		"server = " + ai.client.DirectoryURL + "\n" +
		"\n[[ webroot ]]\n" +
		"[[webroot_map]]\n" +
		domain + " = " + ai.challengeDir + "\n"
	if err := os.WriteFile(renewalConf, []byte(renewalData), 0644); err != nil {
		acmePrintf("[ACME] WARNING: failed to write renewal config to %s: %v", renewalConf, err)
	} else {
		acmePrintf("[ACME] wrote renewal config to %s", renewalConf)
	}

	leaf, _ := x509.ParseCertificate(der[0])
	if leaf != nil {
		acmePrintf("[ACME] OBTAINED cert for %s (expires %s, issuer: %s)", domain, leaf.NotAfter.Format("2006-01-02 15:04:05"), leaf.Issuer.CommonName)
	} else {
		acmePrintf("[ACME] OBTAINED cert for %s", domain)
	}
	return nil
}

func (ai *acmeIntegration) cleanupChallenge(domain, token string) {
	ai.challenges.Delete(domain)
	tokenFile := filepath.Join(ai.challengeDir, token)
	if err := os.Remove(tokenFile); err != nil && !os.IsNotExist(err) {
		acmePrintf("[ACME] WARNING: failed to remove challenge file %s: %v", tokenFile, err)
	}
}

func (ai *acmeIntegration) renewAll() {
	acmePrintf("[ACME] renewal check started")
	snap := ai.server.certStore.snapshot.Load()
	for domain, entry := range snap.byDomain {
		if entry.Source != CertACME {
			continue
		}
		leaf, err := x509.ParseCertificate(entry.ChainDER[0])
		if err != nil {
			acmePrintf("[ACME] failed to parse cert for %s during renewal check: %v", domain, err)
			continue
		}
		remaining := time.Until(leaf.NotAfter)
		daysLeft := int(remaining.Hours() / 24)
		if remaining > acmeRenewBefore {
			acmePrintf("[ACME] cert for %s OK (%d days remaining, expires %s)", domain, daysLeft, leaf.NotAfter.Format("2006-01-02"))
			continue
		}
		acmePrintf("[ACME] cert for %s NEEDS RENEWAL (%d days remaining, expires %s)", domain, daysLeft, leaf.NotAfter.Format("2006-01-02"))
		if err := ai.obtain(domain); err != nil {
			acmePrintf("[ACME] renewal FAILED for %s: %v", domain, err)
		} else {
			acmePrintf("[ACME] renewal SUCCEEDED for %s", domain)
		}
	}
	acmePrintf("[ACME] renewal check complete")
}

func (ai *acmeIntegration) addDomain(domain string) {
	ai.domainMu.Lock()
	for _, d := range ai.domains {
		if d == domain {
			ai.domainMu.Unlock()
			acmePrintf("[ACME] domain %s already managed", domain)
			return
		}
	}
	ai.domains = append(ai.domains, domain)
	ai.domainMu.Unlock()

	acmePrintf("[ACME] added domain %s for ACME management", domain)
	go func() {
		if ai.tryLoadCached(domain) {
			return
		}
		ai.obtainWithRetry(domain)
	}()
}

func (ai *acmeIntegration) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	entry := ai.server.certStore.Lookup(hello.ServerName)
	if entry != nil {
		return &entry.TLSCert, nil
	}
	return nil, ErrNoCertForSNI
}

func (s *Server) AddDomainCert(domain string, certPEM, keyPEM []byte) error {
	return s.AddCert(domain, certPEM, keyPEM)
}

func (s *Server) AddACMEDomain(domain string, email ...string) {
	if s.acme == nil {
		e := ""
		if len(email) > 0 {
			e = email[0]
		}
		ai := newACMEIntegration(ACMEConfig{Email: e, Domains: []string{domain}}, s)
		if ai == nil {
			return
		}
		s.acme = ai
		ai.Start()
		return
	}
	s.acme.addDomain(domain)
}

func (s *Server) EnableACME(cfg ACMEConfig) {
	ai := newACMEIntegration(cfg, s)
	if ai == nil {
		return
	}
	s.acme = ai
	ai.Start()
}

func (s *Server) LocalIPs() []net.IP {
	if s.acme == nil {
		return gatherPublicIPv4()
	}
	p := s.acme.localIPs.Load()
	if p == nil {
		return nil
	}
	return *p
}
