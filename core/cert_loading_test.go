//go:build linux && amd64

package core

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfiguredCertificateSourceRejectsUnsupportedValues(t *testing.T) {
	for _, source := range []CertSource{3, 255} {
		for _, withFiles := range []bool{false, true} {
			cc := CertConfig{Domain: "unsupported-source.test", Source: source}
			if withFiles {
				dir := t.TempDir()
				cc.CertFile, cc.KeyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			}
			server := &Server{config: Config{Certs: []CertConfig{cc}}, certStore: NewCertStore()}
			err := server.loadCerts()
			if err == nil {
				t.Errorf("unsupported certificate source %d withFiles=%t was accepted", source, withFiles)
				continue
			}
			if !strings.Contains(err.Error(), cc.Domain) {
				t.Errorf("unsupported source error omitted the configured domain: %v", err)
			}
			if server.certStore.Lookup("") != nil {
				t.Error("unsupported source installed a replacement certificate")
			}
		}
	}
}

func TestConfiguredCertificateFilesLoadManualChain(t *testing.T) {
	fixture := newOCSPFixture(t, false)
	certFile, keyFile := fixture.writeFiles(t)
	stapleFile := filepath.Join(t.TempDir(), "staple.der")
	staple := fixture.goodResponse(t)
	if err := os.WriteFile(stapleFile, staple, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []CertSource{CertSelfSigned, CertManual} {
		t.Run(map[CertSource]string{CertSelfSigned: "inferred", CertManual: "explicit"}[source], func(t *testing.T) {
			server := &Server{config: Config{Certs: []CertConfig{{Domain: ocspTestDomain, CertFile: certFile, KeyFile: keyFile, Source: source, OCSPStapleFile: stapleFile}}}, certStore: NewCertStore()}
			if err := server.loadCerts(); err != nil {
				t.Fatal(err)
			}
			entry := server.certStore.Lookup(ocspTestDomain)
			if entry == nil || entry.Source != CertManual {
				t.Fatal("configured files were not registered as a manual certificate")
			}
			requireConfiguredChain(t, entry.ChainDER, fixture)
			requireConfiguredChain(t, entry.TLSCert.Certificate, fixture)
			if !bytes.Equal(entry.OCSPStaple(), staple) {
				t.Fatal("configured OCSP staple was not loaded")
			}
		})
	}
}

func TestLegacyCertificateFilesLoadManualChain(t *testing.T) {
	fixture := newOCSPFixture(t, false)
	certFile, keyFile := fixture.writeFiles(t)
	server := &Server{config: Config{TLSCertFile: certFile, TLSKeyFile: keyFile}, certStore: NewCertStore()}
	if err := server.loadCerts(); err != nil {
		t.Fatal(err)
	}
	entry := server.certStore.Lookup("")
	if entry == nil {
		t.Fatal("configured certificate was not registered")
	}
	requireConfiguredChain(t, entry.ChainDER, fixture)
	requireConfiguredChain(t, entry.TLSCert.Certificate, fixture)
	if entry.Source != CertManual {
		t.Fatal("configured files were not registered as a manual certificate")
	}
	leaf, _, err := LoadOrGenerateCert(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leaf, fixture.leafCert.Raw) {
		t.Fatal("LoadOrGenerateCert did not return the configured leaf certificate")
	}
}

func TestConfiguredCertificateFilesRejectInvalidPairsWithoutReplacement(t *testing.T) {
	fixture := newOCSPFixture(t, false)
	other := newOCSPFixture(t, false)
	for _, mode := range []string{"inferred", "manual", "legacy", "exported"} {
		for _, invalid := range []string{"missing certificate", "missing key", "malformed certificate", "malformed key", "mismatched key", "certificate only", "key only"} {
			t.Run(mode+"/"+invalid, func(t *testing.T) {
				t.Chdir(t.TempDir())
				certFile, keyFile := fixture.writeFiles(t)
				switch invalid {
				case "missing certificate":
					if err := os.Remove(certFile); err != nil {
						t.Fatal(err)
					}
				case "missing key":
					if err := os.Remove(keyFile); err != nil {
						t.Fatal(err)
					}
				case "malformed certificate":
					if err := os.WriteFile(certFile, []byte("invalid certificate"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "malformed key":
					if err := os.WriteFile(keyFile, []byte("invalid key"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "mismatched key":
					if err := os.WriteFile(keyFile, other.keyPEM, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				for _, file := range []string{certFile, keyFile, defaultCertFile, defaultKeyFile} {
					before, beforeErr := os.ReadFile(file)
					t.Cleanup(func() {
						after, afterErr := os.ReadFile(file)
						if (beforeErr == nil) != (afterErr == nil) || !bytes.Equal(before, after) {
							t.Errorf("certificate file %s was created, removed, or replaced", file)
						}
					})
				}
				if invalid == "certificate only" {
					keyFile = ""
				}
				if invalid == "key only" {
					certFile = ""
				}
				if mode == "exported" {
					if _, _, err := LoadOrGenerateCert(certFile, keyFile); err == nil {
						t.Error("invalid configured certificate pair was accepted")
					}
					return
				}
				var cfg Config
				if mode == "legacy" {
					cfg.TLSCertFile, cfg.TLSKeyFile = certFile, keyFile
				} else {
					cc := CertConfig{Domain: ocspTestDomain, CertFile: certFile, KeyFile: keyFile}
					if mode == "manual" {
						cc.Source = CertManual
					}
					cfg.Certs = []CertConfig{cc}
				}
				server := &Server{config: cfg, certStore: NewCertStore()}
				if err := server.loadCerts(); err == nil {
					t.Error("invalid configured certificate pair was accepted")
				}
				if server.certStore.Lookup("") != nil {
					t.Error("invalid configured pair installed a replacement certificate")
				}
			})
		}
	}
}

func TestLegacyCertificateFilesRejectExpiredWithoutReplacement(t *testing.T) {
	fixture := newOCSPFixture(t, false)
	pair, err := tls.X509KeyPair(fixture.chainPEM, fixture.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	expired := fixture.ca.issue(t, leafSpec{
		cn: ocspTestDomain, dnsNames: []string{ocspTestDomain}, usage: x509.ExtKeyUsageServerAuth,
		notBefore: wallNow().Add(-2 * time.Hour), notAfter: wallNow().Add(-time.Hour), key: pair.PrivateKey.(crypto.Signer),
	})
	fixture.chainPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expired.Certificate[0]}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.ca.cert.Raw})...)
	certFile, keyFile := fixture.writeFiles(t)
	server := &Server{config: Config{TLSCertFile: certFile, TLSKeyFile: keyFile}, certStore: NewCertStore()}
	if err := server.loadCerts(); err == nil {
		t.Error("expired legacy certificate was accepted")
	}
	if server.certStore.Lookup("") != nil {
		t.Error("expired legacy certificate installed a replacement")
	}
	if _, _, err := LoadOrGenerateCert(certFile, keyFile); err == nil {
		t.Error("LoadOrGenerateCert accepted an expired configured certificate")
	}
	for file, expected := range map[string][]byte{certFile: fixture.chainPEM, keyFile: fixture.keyPEM} {
		actual, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Error("expired configured pair was removed or replaced")
		}
	}
}

func TestCertificateConfigTakesPriorityOverLegacyFiles(t *testing.T) {
	unusedCertFile := filepath.Join(t.TempDir(), "unused-cert.pem")
	unusedKeyFile := filepath.Join(t.TempDir(), "unused-key.pem")
	for _, cfg := range []Config{
		{TLSCertFile: unusedCertFile, Certs: []CertConfig{{Domain: "localhost"}}},
		{TLSKeyFile: unusedKeyFile, Certs: []CertConfig{{Domain: "localhost"}}},
	} {
		server := &Server{config: cfg, certStore: NewCertStore()}
		if err := server.loadCerts(); err != nil {
			t.Fatalf("unused legacy configuration prevented per-domain loading: %v", err)
		}
		if server.certStore.Lookup("localhost") == nil {
			t.Fatal("per-domain certificate not installed")
		}
	}
}

func TestCertificateLoadingWithoutFilesKeepsSelfSignedBehavior(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, cfg := range []Config{{}, {Certs: []CertConfig{{Domain: "localhost"}}}} {
		server := &Server{config: cfg, certStore: NewCertStore()}
		if err := server.loadCerts(); err != nil {
			t.Fatal(err)
		}
		entry := server.certStore.Lookup("localhost")
		if entry == nil || entry.Source != CertSelfSigned || len(entry.ChainDER) != 1 {
			t.Fatal("no-file development configuration did not install a self-signed certificate")
		}
		cert, err := x509.ParseCertificate(entry.ChainDER[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := cert.VerifyHostname("localhost"); err != nil {
			t.Fatal(err)
		}
	}
	generated, err := os.ReadFile(defaultCertFile)
	if err != nil {
		t.Fatalf("development certificate was not saved: %v", err)
	}
	server := &Server{certStore: NewCertStore()}
	if err := server.loadCerts(); err != nil {
		t.Fatal(err)
	}
	if entry := server.certStore.Lookup("localhost"); entry == nil || !bytes.Equal(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: entry.ChainDER[0]}), generated) {
		t.Fatal("saved development certificate was not reused")
	}
	certFile, keyFile := filepath.Join(t.TempDir(), "absent-cert.pem"), filepath.Join(t.TempDir(), "absent-key.pem")
	if _, _, err := LoadOrGenerateCert(certFile, keyFile); err == nil {
		t.Fatal("exported API generated a certificate for configured paths that do not exist")
	}
	for _, file := range []string{certFile, keyFile} {
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Fatalf("configured path %s was written: %v", file, err)
		}
	}
}

func TestConfiguredCertificateChainServedByTLS(t *testing.T) {
	fixture := newOCSPFixture(t, false)
	certFile, keyFile := fixture.writeFiles(t)
	for _, mode := range []string{"inferred", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			server := newTestServer(t, testServerOptions{
				TLS: true, Domain: ocspTestDomain,
				Config: func(cfg *Config) {
					cfg.DisableOCSPStapling = true
					if mode == "legacy" {
						cfg.Certs = nil
						cfg.TLSCertFile, cfg.TLSKeyFile = certFile, keyFile
					} else {
						cfg.Certs = []CertConfig{{Domain: ocspTestDomain, CertFile: certFile, KeyFile: keyFile}}
					}
				},
				Routes: func(router *Router) {
					router.GET("/", func(req *Request, resp *Response) { resp.Status(200).String("configured certificate") })
				},
			})
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				t.Run(tls.VersionName(version), func(t *testing.T) {
					state := ocspHandshake(t, server, fixture.clientConfig(version, nil))
					var chain [][]byte
					for _, cert := range state.PeerCertificates {
						chain = append(chain, cert.Raw)
					}
					requireConfiguredChain(t, chain, fixture)
				})
			}
		})
	}
}

func requireConfiguredChain(t *testing.T, chain [][]byte, fixture *ocspFixture) {
	t.Helper()
	if len(chain) != 2 {
		t.Fatalf("configured chain contains %d certificates, want leaf and issuer", len(chain))
	}
	if !bytes.Equal(chain[0], fixture.leafCert.Raw) || !bytes.Equal(chain[1], fixture.ca.cert.Raw) {
		t.Fatal("configured certificate chain identity or order changed")
	}
}

func TestLegacyCertificateKeyFileFormsMatchConfiguredCertificates(t *testing.T) {
	fixture := newOCSPFixture(t, false)
	parameters := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}})
	for name, keyPEM := range map[string][]byte{
		"parameters before key":  append(bytes.Clone(parameters), fixture.keyPEM...),
		"certificate before key": append(bytes.Clone(fixture.chainPEM), fixture.keyPEM...),
	} {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			certFile, keyFile := fixture.writeFiles(t)
			if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
				t.Fatal(err)
			}
			server := &Server{certStore: NewCertStore()}
			server.config.TLSCertFile, server.config.TLSKeyFile = certFile, keyFile
			if err := server.loadCerts(); err != nil {
				t.Fatalf("legacy certificate files rejected: %v", err)
			}
			if entry := server.certStore.Lookup("localhost"); entry == nil || entry.Source != CertManual {
				t.Fatal("legacy certificate files did not install a manual certificate")
			}
		})
	}
	t.Run("no key block", func(t *testing.T) {
		t.Chdir(t.TempDir())
		certFile, keyFile := fixture.writeFiles(t)
		if err := os.WriteFile(keyFile, append(bytes.Clone(parameters), fixture.chainPEM...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadOrGenerateCert(certFile, keyFile); err == nil {
			t.Fatal("key file without a private key block was accepted")
		}
	})
}

func TestLegacyCertificateKeyFilesAcceptTypedPrivateKeyBlocks(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	parameters := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}})
	for _, tc := range []struct {
		name   string
		signer crypto.Signer
		keyPEM []byte
	}{
		{"sec1 after parameters", ecKey, append(parameters, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})...)},
		{"pkcs1", rsaKey, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
			certDER, err := x509.CreateCertificate(rand.Reader, template, template, tc.signer.Public(), tc.signer)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyFile, tc.keyPEM, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := LoadOrGenerateCert(certFile, keyFile); err != nil {
				t.Fatalf("typed private key block rejected: %v", err)
			}
		})
	}
}
