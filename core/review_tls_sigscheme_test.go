//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func selfSignedPEM(t *testing.T, key crypto.Signer, domain string) (certPEM, keyPEM []byte) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestCertificateVerifySchemeMatchesKey(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	transcript := sha256.Sum256([]byte("transcript"))
	cases := []struct {
		name   string
		key    crypto.Signer
		scheme uint16
	}{
		{"p256", p256, 0x0403},
		{"p384", p384, 0x0503},
		{"p521", p521, 0x0603},
		{"ed25519", ed, 0x0807},
		{"rsa", rsaKey, 0x0804},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scheme, sig, err := SignCertificateVerify(tc.key, transcript[:], nil)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if scheme != tc.scheme {
				t.Fatalf("scheme = %#x, want %#x for this key", scheme, tc.scheme)
			}
			content := append(append(append(append([]byte{}, cvPrefix[:]...), cvContext...), 0), transcript[:]...)
			switch k := tc.key.(type) {
			case *ecdsa.PrivateKey:
				var digest []byte
				switch scheme {
				case 0x0403:
					d := sha256.Sum256(content)
					digest = d[:]
				case 0x0503:
					d := sha512.Sum384(content)
					digest = d[:]
				case 0x0603:
					d := sha512.Sum512(content)
					digest = d[:]
				}
				if !ecdsa.VerifyASN1(&k.PublicKey, digest, sig) {
					t.Fatal("signature does not verify with the hash the scheme names")
				}
			case ed25519.PrivateKey:
				if !ed25519.Verify(k.Public().(ed25519.PublicKey), content, sig) {
					t.Fatal("ed25519 signature does not verify")
				}
			}
		})
	}
	if _, _, err := SignCertificateVerify(p256, transcript[:], []uint16{0x0804}); err == nil {
		t.Fatal("client offering only RSA-PSS must not be answered with an ECDSA scheme")
	}
}

func TestTLSHandshakeWithNonP256Certificates(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := []struct {
		name string
		key  crypto.Signer
	}{{"p384", p384}, {"ed25519", ed}, {"rsa", rsaKey}}
	for _, k := range keys {
		for _, version := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
			t.Run(fmt.Sprintf("%s/%#x", k.name, version), func(t *testing.T) {
				testHandshakeWithKey(t, k.name, k.key, version)
			})
		}
	}
}

func testHandshakeWithKey(t *testing.T, name string, key crypto.Signer, version uint16) {
	t.Helper()
	addr := reserveLocalAddr(t)
	srv := New(Config{Addr: addr, HTTPAddr: "-", LogRequests: false, MaxConnsPerIP: -1, Listeners: 1})
	certPEM, keyPEM := selfSignedPEM(t, key, "sig.test")
	if err := srv.AddCert("sig.test", certPEM, keyPEM); err != nil {
		t.Fatalf("AddCert: %v", err)
	}
	srv.Router.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	go func() { _ = srv.ListenAndServeTLS() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	var conn *tls.Conn
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 300 * time.Millisecond}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true, ServerName: "sig.test", MinVersion: version, MaxVersion: version})
		if err == nil || !isDialError(err) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("TLS %#x handshake with a %s certificate failed: %v", version, name, err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET /ok HTTP/1.1\r\nHost: sig.test\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("request over %s cert: %v", name, err)
	}
	resp.Body.Close()
}

func isDialError(err error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		return opErr.Op == "dial"
	}
	return false
}
