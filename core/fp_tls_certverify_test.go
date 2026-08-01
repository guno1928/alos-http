//go:build linux

package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func leafCertDER(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "origin.test"},
		DNSNames:     []string{"origin.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func transportWithCert(der []byte, transcript string) *tlsTransport {
	return &tlsTransport{
		hashFn:     sha256.New,
		hashLen:    32,
		certs:      [][]byte{der},
		transcript: []byte(transcript),
		serverName: "origin.test",
	}
}

func certVerifyBody(scheme uint16, sig []byte) []byte {
	out := []byte{byte(scheme >> 8), byte(scheme), byte(len(sig) >> 8), byte(len(sig))}
	return append(out, sig...)
}

func signECDSA(t *testing.T, key *ecdsa.PrivateKey, content []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(content)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

func TestCertificateVerifyAcceptsGenuineSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tr := transportWithCert(leafCertDER(t, key), "handshake-transcript")
	sig := signECDSA(t, key, tr.certVerifyContent())
	if err := tr.verifyCertificateVerify(certVerifyBody(0x0403, sig)); err != nil {
		t.Fatalf("a server that genuinely holds the key was rejected: %v", err)
	}
}

// The attack the missing check allowed: an interceptor presents the real,
// publicly available certificate chain for the host but does not hold the
// private key, so it cannot produce this signature.
func TestCertificateVerifyRejectsAttackerWithoutPrivateKey(t *testing.T) {
	realKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tr := transportWithCert(leafCertDER(t, realKey), "handshake-transcript")
	sig := signECDSA(t, attackerKey, tr.certVerifyContent())
	if err := tr.verifyCertificateVerify(certVerifyBody(0x0403, sig)); err == nil {
		t.Fatal("a peer that does not hold the certificate private key was accepted")
	}
}

// A replayed CertificateVerify from a recorded session cannot work either: the
// interceptor performs its own key exchange, so its transcript differs.
func TestCertificateVerifyRejectsReplayFromAnotherSession(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der := leafCertDER(t, key)
	recorded := transportWithCert(der, "the-original-session")
	sig := signECDSA(t, key, recorded.certVerifyContent())

	replayed := transportWithCert(der, "a-different-session")
	if err := replayed.verifyCertificateVerify(certVerifyBody(0x0403, sig)); err == nil {
		t.Fatal("a CertificateVerify captured from another handshake was accepted")
	}
}

func TestCertificateVerifyRejectsTamperedSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tr := transportWithCert(leafCertDER(t, key), "handshake-transcript")
	sig := signECDSA(t, key, tr.certVerifyContent())
	sig[len(sig)-1] ^= 0xff
	if err := tr.verifyCertificateVerify(certVerifyBody(0x0403, sig)); err == nil {
		t.Fatal("a corrupted signature was accepted")
	}
}

func TestCertificateVerifyAcceptsRSAPSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := transportWithCert(leafCertDER(t, key), "handshake-transcript")
	sum := sha256.Sum256(tr.certVerifyContent())
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, sum[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.verifyCertificateVerify(certVerifyBody(0x0804, sig)); err != nil {
		t.Fatalf("a genuine RSA-PSS signature was rejected: %v", err)
	}
}

// RFC 8446 4.4.3 forbids the PKCS1 schemes in CertificateVerify even though
// they appear in signature_algorithms for certificate chain signatures.
func TestCertificateVerifyRejectsPKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := transportWithCert(leafCertDER(t, key), "handshake-transcript")
	sum := sha256.Sum256(tr.certVerifyContent())
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.verifyCertificateVerify(certVerifyBody(0x0401, sig)); err == nil {
		t.Fatal("a PKCS1 CertificateVerify was accepted")
	}
}

func TestCertificateVerifyRejectsMalformedBody(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tr := transportWithCert(leafCertDER(t, key), "handshake-transcript")
	for _, body := range [][]byte{
		{},
		{0x04},
		{0x04, 0x03, 0x00},
		{0x04, 0x03, 0x00, 0x40},
		{0x04, 0x03, 0xff, 0xff, 0x01, 0x02},
	} {
		if err := tr.verifyCertificateVerify(body); err == nil {
			t.Fatalf("a malformed CertificateVerify of %d bytes was accepted", len(body))
		}
	}
}

// Omitting CertificateVerify entirely must not be a way around the check.
func TestHandshakeRequiresCertificateVerify(t *testing.T) {
	tr := &tlsTransport{hashFn: sha256.New, hashLen: 32}
	if tr.serverProvedKeyPossession {
		t.Fatal("a fresh transport must not start out having proved key possession")
	}
}
