package protocols_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net"
	"testing"

	"github.com/guno1928/alos-http/core"
)

func TestTLSALPNMatrix(t *testing.T) {
	cases := []struct {
		protocols []string
		allowH2   bool
		want      string
	}{
		{[]string{"h2", "http/1.1"}, true, "h2"},
		{[]string{"http/1.1", "h2"}, true, "h2"},
		{[]string{"h2", "http/1.1"}, false, "http/1.1"},
		{[]string{"h2"}, false, ""},
		{[]string{"http/1.1"}, true, "http/1.1"},
		{[]string{"h3", "http/1.1"}, true, "http/1.1"},
		{[]string{"h3"}, true, ""},
		{nil, true, ""},
	}
	for repeat := 0; repeat < 4; repeat++ {
		for i, tc := range cases {
			tc := tc
			t.Run(fmt.Sprintf("alpn_%02d_%d", repeat, i), func(t *testing.T) {
				if got := core.NegotiateALPN(tc.protocols, tc.allowH2); got != tc.want {
					t.Fatalf("NegotiateALPN(%v, %v) = %q, want %q", tc.protocols, tc.allowH2, got, tc.want)
				}
			})
		}
	}
}

func TestTLSCipherSuiteNegotiation(t *testing.T) {
	for i, suite := range core.SupportedSuites {
		suite := suite
		t.Run(fmt.Sprintf("suite_%04x", suite.ID), func(t *testing.T) {
			found := core.FindSuiteByID(suite.ID)
			if found == nil || found.ID != suite.ID || found.KeyLen != suite.KeyLen || found.HashLen != suite.HashLen {
				t.Fatalf("suite mismatch: %#v", found)
			}
			client := []uint16{0xffff, suite.ID, 0x0000}
			if got := core.NegotiateSuite(client); got == nil || got.ID != suite.ID {
				t.Fatalf("negotiated suite = %#v", got)
			}
			key := make([]byte, suite.KeyLen)
			if _, err := suite.MakeAEAD(key); err != nil {
				t.Fatalf("AEAD creation failed: %v", err)
			}
		})
		_ = i
	}
	if core.FindSuiteByID(0xffff) != nil || core.NegotiateSuite([]uint16{0xffff, 0}) != nil {
		t.Fatal("unsupported suite accepted")
	}
}

func TestTLSKeyScheduleMatrix(t *testing.T) {
	for i := 1; i <= 32; i++ {
		t.Run(fmt.Sprintf("derive_%02d", i), func(t *testing.T) {
			secret := bytes.Repeat([]byte{byte(i)}, sha256.Size)
			context := bytes.Repeat([]byte{byte(255 - i)}, i)
			first := core.TLSExpandLabel(sha256.New, secret, "test", context, i)
			second := core.TLSExpandLabel(sha256.New, secret, "test", context, i)
			if len(first) != i || !bytes.Equal(first, second) {
				t.Fatalf("non-deterministic derivation: %x %x", first, second)
			}
			changed := core.TLSExpandLabel(sha256.New, secret, "other", context, i)
			if bytes.Equal(first, changed) {
				t.Fatal("label did not domain-separate output")
			}
			extracted := core.TLSExtract(sha256.New, context, secret)
			if len(extracted) != sha256.Size {
				t.Fatalf("extract length = %d", len(extracted))
			}
		})
	}
}

func TestTLSSelfSignedCertificates(t *testing.T) {
	domains := []string{"localhost", "example.test", "api.internal", "127.0.0.1", "::1", "192.0.2.20"}
	for _, domain := range domains {
		domain := domain
		t.Run(domain, func(t *testing.T) {
			der, key, err := core.GenerateSelfSignedForDomain(domain)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if key == nil || cert.PublicKey == nil {
				t.Fatal("certificate or key missing")
			}
			if ip := net.ParseIP(domain); ip != nil {
				if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(ip) {
					t.Fatalf("IP SAN = %v, want %v", cert.IPAddresses, ip)
				}
			} else if len(cert.DNSNames) != 1 || cert.DNSNames[0] != domain {
				t.Fatalf("DNS SAN = %v, want %q", cert.DNSNames, domain)
			}
			if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
				t.Fatalf("self-signature failed: %v", err)
			}
		})
	}
}
