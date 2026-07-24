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
	"hash"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
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
}

// SupportedSuites lists, in negotiation-preference order, the TLS 1.3 cipher suites
// this server supports: a private AEGIS-128L suite (ID 0x1306), followed by the
// standard suites TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302),
// and TLS_CHACHA20_POLY1305_SHA256 (0x1303).
var SupportedSuites = [4]CipherSuiteConfig{
	{
		ID: 0x1306, KeyLen: 16, IVLen: 16,
		HashFn: sha256.New, HashLen: 32,
		MakeAEAD: func(key []byte) (cipher.AEAD, error) {
			return aegis.New(key)
		},
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
	for i := range SupportedSuites {
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
}

type trafficAEADScratch struct {
	nonce [16]byte
	ad    [5]byte
}

var trafficAEADScratchPool = sync.Pool{
	New: func() any {
		s := &trafficAEADScratch{}
		s.ad[0] = 0x17
		s.ad[1] = 0x03
		s.ad[2] = 0x03
		return s
	},
}

// NewTrafficAEAD derives the traffic key and IV from secret using cs's HKDF label
// templates and constructs a TrafficAEAD ready to encrypt or decrypt records under
// cs's AEAD algorithm.
func NewTrafficAEAD(_ func() hash.Hash, secret []byte, cs *CipherSuiteConfig) (*TrafficAEAD, error) {
	var keyBuf [64]byte
	var ivBuf [64]byte
	key := cs.labelKey.ExpandTo(cs.HashFn, secret, nil, keyBuf[:0])
	iv := cs.labelIV.ExpandTo(cs.HashFn, secret, nil, ivBuf[:0])
	a, err := cs.MakeAEAD(key)
	if err != nil {
		return nil, err
	}
	staticLen := cs.IVLen - 8
	t := &TrafficAEAD{aead: a, oh: a.Overhead(), nonceSize: cs.IVLen, staticLen: staticLen}
	copy(t.iv[:], iv)
	t.ivLow = binary.BigEndian.Uint64(t.iv[staticLen:])
	return t, nil
}

func (t *TrafficAEAD) prepareRecord(sp *trafficAEADScratch, recordLen uint16) {
	sl := t.staticLen
	copy(sp.nonce[:sl], t.iv[:sl])
	binary.BigEndian.PutUint64(sp.nonce[sl:], t.ivLow^t.seq)
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
	sp := trafficAEADScratchPool.Get().(*trafficAEADScratch)
	t.prepareRecord(sp, recordLen)
	ct := t.aead.Seal(plaintext[:0], sp.nonce[:t.nonceSize], plaintext, sp.ad[:])
	t.seq++
	trafficAEADScratchPool.Put(sp)
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
	sp := trafficAEADScratchPool.Get().(*trafficAEADScratch)
	t.prepareRecord(sp, recordLen)
	dst = t.aead.Seal(dst, sp.nonce[:t.nonceSize], plaintext, sp.ad[:])
	t.seq++
	trafficAEADScratchPool.Put(sp)
	return dst
}

// Decrypt opens ciphertext in place, reusing its backing array, using the next
// record nonce, returning the plaintext and advancing the internal sequence number on success.
func (t *TrafficAEAD) Decrypt(ciphertext []byte) ([]byte, error) {
	recordLen := uint16(len(ciphertext))
	sp := trafficAEADScratchPool.Get().(*trafficAEADScratch)
	t.prepareRecord(sp, recordLen)
	pt, err := t.aead.Open(ciphertext[:0], sp.nonce[:t.nonceSize], ciphertext, sp.ad[:])
	if err != nil {
		trafficAEADScratchPool.Put(sp)
		return nil, err
	}
	t.seq++
	trafficAEADScratchPool.Put(sp)
	return pt, nil
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

// LoadOrGenerateCert loads a certificate/key pair from certFile and keyFile
// (defaulting to ".alos-cert.pem" / ".alos-key.pem" when empty), generating and
// saving a new self-signed certificate via GenerateCert if none exists, is invalid,
// or has expired.
func LoadOrGenerateCert(certFile, keyFile string) ([]byte, crypto.Signer, error) {
	if certFile == "" {
		certFile = defaultCertFile
	}
	if keyFile == "" {
		keyFile = defaultKeyFile
	}

	certDER, privKey, err := loadCertFromDisk(certFile, keyFile)
	if err == nil {
		log.Printf("Loaded existing TLS certificate from %s", certFile)
		return certDER, privKey, nil
	}

	certDER, privKey, err = GenerateCert()
	if err != nil {
		return nil, nil, err
	}

	if saveErr := saveCertToDisk(certFile, keyFile, certDER, privKey); saveErr != nil {
		log.Printf("[WARN] could not save cert to disk: %v (will regenerate on next restart)", saveErr)
	} else {
		log.Printf("Generated and saved new TLS certificate to %s", certFile)
	}

	return certDER, privKey, nil
}

func loadCertFromDisk(certFile, keyFile string) ([]byte, crypto.Signer, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
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

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if time.Now().After(cert.NotAfter) {
		return nil, nil, &staticError{"certificate expired"}
	}

	return certBlock.Bytes, privKey, nil
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
