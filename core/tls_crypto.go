//go:build linux && amd64

package core

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/ericlagergren/aegis"
	"golang.org/x/crypto/chacha20poly1305"
)

// CipherSuiteConfig describes a supported TLS 1.3 cipher suite: its wire ID, key/IV/hash
// sizes, and AEAD constructor, plus precomputed internal HKDF state. Obtain one via
// NegotiateSuite or FindSuiteByID rather than constructing it directly.
type CipherSuiteConfig struct {
	ID       uint16
	KeyLen   int
	IVLen    int
	HashFn   func() hash.Hash
	HashLen  int
	MakeAEAD func(key []byte) (cipher.AEAD, error)

	noQUICHeaderProtection bool

	emptyTranscriptHash []byte
	zeroHashInput       []byte
	earlySecret         []byte
	derivedFromEarly    []byte

	labelDerived          hkdfLabelTemplate
	labelFinished         hkdfLabelTemplate
	labelKey              hkdfLabelTemplate
	labelIV               hkdfLabelTemplate
	labelClientHSTraffic  hkdfLabelTemplate
	labelServerHSTraffic  hkdfLabelTemplate
	labelClientAppTraffic hkdfLabelTemplate
	labelServerAppTraffic hkdfLabelTemplate
	labelResBinder        hkdfLabelTemplate
	labelResMaster        hkdfLabelTemplate
	labelResumption       hkdfLabelTemplate
	labelTrafficUpdate    hkdfLabelTemplate
}

// SupportedSuites lists, in negotiation-preference order, the TLS 1.3 cipher suites
// this server supports: TLS_AEGIS_128L_SHA256 (ID 0x1307, TLS over TCP only), followed by the
// standard suites TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302),
// and TLS_CHACHA20_POLY1305_SHA256 (0x1303).
var SupportedSuites = [4]CipherSuiteConfig{
	{
		ID: tlsAEGIS128LSHA256, KeyLen: 16, IVLen: 16,
		HashFn: sha256.New, HashLen: 32,
		MakeAEAD: func(key []byte) (cipher.AEAD, error) {
			return aegis.New(key)
		},
		noQUICHeaderProtection: true,
	},
	{
		ID: 0x1301, KeyLen: 16, IVLen: 12,
		HashFn: sha256.New, HashLen: 32,
		MakeAEAD: func(key []byte) (cipher.AEAD, error) {
			b, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(b)
		},
	},
	{
		ID: 0x1302, KeyLen: 32, IVLen: 12,
		HashFn: sha512.New384, HashLen: 48,
		MakeAEAD: func(key []byte) (cipher.AEAD, error) {
			b, err := aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(b)
		},
	},
	{
		ID: 0x1303, KeyLen: 32, IVLen: 12,
		HashFn: sha256.New, HashLen: 32,
		MakeAEAD: func(key []byte) (cipher.AEAD, error) {
			return chacha20poly1305.New(key)
		},
	},
}

// NegotiateSuite returns the first entry in SupportedSuites, in server preference
// order, whose ID appears in clientIDs, or nil if none match.
func NegotiateSuite(clientIDs []uint16) *CipherSuiteConfig {
	return negotiateSuite(clientIDs, false)
}

func negotiateQUICSuite(clientIDs []uint16) *CipherSuiteConfig {
	return negotiateSuite(clientIDs, true)
}

func negotiateSuite(clientIDs []uint16, forQUIC bool) *CipherSuiteConfig {
	for i := range SupportedSuites {
		if forQUIC && SupportedSuites[i].noQUICHeaderProtection {
			continue
		}
		for _, cid := range clientIDs {
			if SupportedSuites[i].ID == cid {
				return &SupportedSuites[i]
			}
		}
	}
	return nil
}

// FindSuiteByID returns the SupportedSuites entry with the given wire ID, or nil if none match.
func FindSuiteByID(id uint16) *CipherSuiteConfig {
	for i := range SupportedSuites {
		if SupportedSuites[i].ID == id {
			return &SupportedSuites[i]
		}
	}
	return nil
}

// TrafficAEAD wraps a TLS 1.3 traffic secret's AEAD cipher, encrypting and decrypting
// records with a per-record nonce derived from a fixed IV XORed with an incrementing
// sequence number.
type TrafficAEAD struct {
	aead      cipher.AEAD
	iv        [16]byte
	ivLow     uint64
	oh        int
	seq       uint64
	nonceSize int
	staticLen int
	scratch   trafficAEADScratch
	suite     *CipherSuiteConfig
	secret    [maxTrafficSecretLen]byte
}

const (
	tlsAEGIS128LSHA256  = 0x1307
	maxTrafficSecretLen = sha512.Size384
)

type trafficAEADScratch struct {
	nonce [16]byte
	ad    [5]byte
}

// NewTrafficAEAD derives the traffic key and IV from secret using cs's HKDF label
// templates and constructs a TrafficAEAD ready to encrypt or decrypt records under
// cs's AEAD algorithm.
func NewTrafficAEAD(_ func() hash.Hash, secret []byte, cs *CipherSuiteConfig) (*TrafficAEAD, error) {
	t := &TrafficAEAD{}
	if err := t.install(secret, cs); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *TrafficAEAD) install(secret []byte, cs *CipherSuiteConfig) error {
	var keyBuf [64]byte
	var ivBuf [64]byte
	key := cs.labelKey.ExpandTo(cs.HashFn, secret, nil, keyBuf[:0])
	iv := cs.labelIV.ExpandTo(cs.HashFn, secret, nil, ivBuf[:0])
	a, err := cs.MakeAEAD(key)
	clear(keyBuf[:])
	if err != nil {
		return err
	}
	staticLen := cs.IVLen - 8
	*t = TrafficAEAD{aead: a, oh: a.Overhead(), nonceSize: cs.IVLen, staticLen: staticLen, suite: cs}
	copy(t.iv[:], iv)
	t.ivLow = binary.BigEndian.Uint64(t.iv[staticLen:])
	copy(t.secret[:], secret)
	return nil
}

func (t *TrafficAEAD) nextGeneration(next *TrafficAEAD) error {
	cs := t.suite
	var secretBuf [64]byte
	secret := cs.labelTrafficUpdate.ExpandTo(cs.HashFn, t.secret[:cs.HashLen], nil, secretBuf[:0])
	err := next.install(secret, cs)
	clear(secretBuf[:])
	return err
}

func (t *TrafficAEAD) keyWornOut() bool { return t != nil && t.seq >= tls13RecordsPerKeyLimit }

func (t *TrafficAEAD) prepareRecord(sp *trafficAEADScratch, recordLen uint16) {
	sl := t.staticLen
	copy(sp.nonce[:sl], t.iv[:sl])
	binary.BigEndian.PutUint64(sp.nonce[sl:], t.ivLow^t.seq)
	sp.ad[0] = 0x17
	sp.ad[1] = 0x03
	sp.ad[2] = 0x03
	sp.ad[3] = byte(recordLen >> 8)
	sp.ad[4] = byte(recordLen)
}

// Overhead returns the number of extra bytes the AEAD adds to each record (the authentication tag length).
func (t *TrafficAEAD) Overhead() int {
	return t.oh
}

// Encrypt seals plaintext in place, reusing its backing array, with the next record
// nonce, returns the ciphertext, and advances the internal sequence number.
func (t *TrafficAEAD) Encrypt(plaintext []byte) []byte {
	ciphertextLen := len(plaintext) + t.oh
	if ciphertextLen > 0xFFFF {
		ciphertextLen = 0xFFFF
	}
	recordLen := uint16(ciphertextLen)
	sp := &t.scratch
	t.prepareRecord(sp, recordLen)
	ct := t.aead.Seal(plaintext[:0], sp.nonce[:t.nonceSize], plaintext, sp.ad[:])
	t.seq++
	return ct
}

// EncryptAppend seals plaintext with the next record nonce and appends the
// ciphertext to dst, returning the extended slice and advancing the internal
// sequence number.
func (t *TrafficAEAD) EncryptAppend(dst, plaintext []byte) []byte {
	ciphertextLen := len(plaintext) + t.oh
	if ciphertextLen > 0xFFFF {
		ciphertextLen = 0xFFFF
	}
	recordLen := uint16(ciphertextLen)
	sp := &t.scratch
	t.prepareRecord(sp, recordLen)
	dst = t.aead.Seal(dst, sp.nonce[:t.nonceSize], plaintext, sp.ad[:])
	t.seq++
	return dst
}

// Decrypt opens ciphertext in place, reusing its backing array, using the next
// record nonce, returning the plaintext and advancing the internal sequence number on success.
func (t *TrafficAEAD) Decrypt(ciphertext []byte) ([]byte, error) {
	recordLen := uint16(len(ciphertext))
	sp := &t.scratch
	t.prepareRecord(sp, recordLen)
	pt, err := t.aead.Open(ciphertext[:0], sp.nonce[:t.nonceSize], ciphertext, sp.ad[:])
	if err != nil {
		return nil, err
	}
	t.seq++
	return pt, nil
}

func (t *TrafficAEAD) decryptAppend(dst, ciphertext []byte) ([]byte, error) {
	sp := &t.scratch
	t.prepareRecord(sp, uint16(len(ciphertext)))
	out, err := t.aead.Open(dst, sp.nonce[:t.nonceSize], ciphertext, sp.ad[:])
	if err != nil {
		return nil, err
	}
	t.seq++
	return out, nil
}

// GenerateSelfSignedForDomain creates a self-signed ECDSA P-256 certificate valid for
// 365 days for domain, used as a DNS SAN, or as an IP SAN if domain parses as an IP
// address, and returns the DER-encoded certificate and its private key.
func GenerateSelfSignedForDomain(domain string) ([]byte, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"ALOS"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}
	if ip := net.ParseIP(domain); ip != nil {
		tmpl.DNSNames = nil
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	return der, priv, nil
}

// GenerateCert creates a self-signed ECDSA P-256 certificate valid for 365 days for
// "localhost" and 127.0.0.1, and returns the DER-encoded certificate and its private key.
func GenerateCert() ([]byte, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"ALOS"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{{127, 0, 0, 1}},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	return der, priv, nil
}

const defaultCertFile = ".alos-cert.pem"
const defaultKeyFile = ".alos-key.pem"

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, errors.New("pkcs8 key is not a crypto.Signer")
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key format")
}

// LoadOrGenerateCert loads a certificate/key pair from certFile and keyFile and
// returns the leaf certificate. When both paths are empty it uses
// ".alos-cert.pem" / ".alos-key.pem", generating and saving a new self-signed
// certificate via GenerateCert if that pair does not exist, is invalid, or has
// expired. When either path is set, both are required and a missing, invalid,
// or expired pair is returned as an error; configured files are never written.
func LoadOrGenerateCert(certFile, keyFile string) ([]byte, crypto.Signer, error) {
	chainDER, privKey, err := loadOrGenerateCertChain(certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}
	return chainDER[0], privKey, nil
}

func loadOrGenerateCertChain(certFile, keyFile string) ([][]byte, crypto.Signer, error) {
	if certFile != "" || keyFile != "" {
		return loadConfiguredCertFiles(certFile, keyFile)
	}

	chainDER, privKey, err := loadCertFromDisk(defaultCertFile, defaultKeyFile)
	if err == nil {
		logger().Info("TLS certificate loaded", "file", defaultCertFile)
		return chainDER, privKey, nil
	}
	if errors.Is(err, errCertKeyMismatch) {
		return nil, nil, err
	}

	certDER, privKey, err := GenerateCert()
	if err != nil {
		return nil, nil, err
	}

	if saveErr := saveCertToDisk(defaultCertFile, defaultKeyFile, certDER, privKey); saveErr != nil {
		logger().Warn("generated TLS certificate not saved; a new one is generated at the next start", "file", defaultCertFile, "err", saveErr)
	} else {
		logger().Info("TLS certificate generated", "file", defaultCertFile)
	}

	return [][]byte{certDER}, privKey, nil
}

func loadConfiguredCertFiles(certFile, keyFile string) ([][]byte, crypto.Signer, error) {
	if certFile == "" || keyFile == "" {
		return nil, nil, errCertPairIncomplete
	}
	chainDER, privKey, err := loadCertFromDisk(certFile, keyFile)
	if err != nil {
		if errors.Is(err, errCertKeyMismatch) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("TLS certificate %s: %w", certFile, err)
	}
	logger().Info("TLS certificate loaded", "file", certFile)
	return chainDER, privKey, nil
}

func loadCertFromDisk(certFile, keyFile string) ([][]byte, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}

	chainDER := pemCertificateChain(certPEM)
	if len(chainDER) == 0 {
		return nil, nil, &staticError{"invalid cert PEM"}
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, &staticError{"invalid key PEM"}
	}

	privKey, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		return nil, nil, err
	}
	if time.Now().After(cert.NotAfter) {
		return nil, nil, &staticError{"certificate expired"}
	}
	if pub, ok := privKey.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(cert.PublicKey) {
		return nil, nil, fmt.Errorf("%s and %s: %w", certFile, keyFile, errCertKeyMismatch)
	}

	return chainDER, privKey, nil
}

var errCertKeyMismatch = errors.New("TLS private key does not match the certificate")

var errCertPairIncomplete = errors.New("TLS certificate and key files must be configured together")

func pemCertificateChain(certPEM []byte) [][]byte {
	var chainDER [][]byte
	for rest := certPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return chainDER
		}
		if block.Type == "CERTIFICATE" {
			chainDER = append(chainDER, block.Bytes)
		}
	}
}

func saveCertToDisk(certFile, keyFile string, certDER []byte, privKey crypto.Signer) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return err
	}
	return nil
}
