package core

import (
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
	"hash"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type CipherSuiteConfig struct {
	ID       uint16
	KeyLen   int
	IVLen    int
	HashFn   func() hash.Hash
	HashLen  int
	MakeAEAD func(key []byte) (cipher.AEAD, error)
}

var SupportedSuites = [3]CipherSuiteConfig{
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

type TrafficAEAD struct {
	aead  cipher.AEAD
	iv    [12]byte
	ivLow uint64 // pre-decoded binary.BigEndian.Uint64(iv[4:])
	seq   uint64
}

func NewTrafficAEAD(h func() hash.Hash, secret []byte, cs *CipherSuiteConfig) (*TrafficAEAD, error) {
	key := TLSExpandLabel(h, secret, "key", nil, cs.KeyLen)
	iv := TLSExpandLabel(h, secret, "iv", nil, cs.IVLen)
	a, err := cs.MakeAEAD(key)
	if err != nil {
		return nil, err
	}
	t := &TrafficAEAD{aead: a}
	copy(t.iv[:], iv)
	t.ivLow = binary.BigEndian.Uint64(t.iv[4:])
	return t, nil
}

func (t *TrafficAEAD) fillNonce(dst []byte) {
	_ = dst[11] // bounds check elimination
	copy(dst[:4], t.iv[:4])
	binary.BigEndian.PutUint64(dst[4:], t.ivLow^t.seq)
}

func (t *TrafficAEAD) Overhead() int {
	return t.aead.Overhead()
}

func (t *TrafficAEAD) Encrypt(plaintext []byte) []byte {
	ciphertextLen := len(plaintext) + t.aead.Overhead()
	if ciphertextLen > 0xFFFF {
		ciphertextLen = 0xFFFF
	}
	recordLen := uint16(ciphertextLen)
	var ad [5]byte
	ad[0] = 0x17
	ad[1] = 0x03
	ad[2] = 0x03
	ad[3] = byte(recordLen >> 8)
	ad[4] = byte(recordLen)
	var nonce [12]byte
	t.fillNonce(nonce[:])
	ct := t.aead.Seal(plaintext[:0], nonce[:], plaintext, ad[:])
	t.seq++
	return ct
}

func (t *TrafficAEAD) EncryptAppend(dst, plaintext []byte) []byte {
	ciphertextLen := len(plaintext) + t.aead.Overhead()
	if ciphertextLen > 0xFFFF {
		ciphertextLen = 0xFFFF
	}
	recordLen := uint16(ciphertextLen)
	var ad [5]byte
	ad[0] = 0x17
	ad[1] = 0x03
	ad[2] = 0x03
	ad[3] = byte(recordLen >> 8)
	ad[4] = byte(recordLen)
	var nonce [12]byte
	t.fillNonce(nonce[:])
	dst = t.aead.Seal(dst, nonce[:], plaintext, ad[:])
	t.seq++
	return dst
}

func (t *TrafficAEAD) Decrypt(ciphertext []byte) ([]byte, error) {
	recordLen := uint16(len(ciphertext))
	var ad [5]byte
	ad[0] = 0x17
	ad[1] = 0x03
	ad[2] = 0x03
	ad[3] = byte(recordLen >> 8)
	ad[4] = byte(recordLen)
	var nonce [12]byte
	t.fillNonce(nonce[:])
	pt, err := t.aead.Open(ciphertext[:0], nonce[:], ciphertext, ad[:])
	if err != nil {
		return nil, err
	}
	t.seq++
	return pt, nil
}

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

func LoadOrGenerateCert(certFile, keyFile string) ([]byte, *ecdsa.PrivateKey, error) {
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

func loadCertFromDisk(certFile, keyFile string) ([]byte, *ecdsa.PrivateKey, error) {
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
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return nil, nil, &staticError{"invalid key PEM"}
	}

	privKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
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

func saveCertToDisk(certFile, keyFile string, certDER []byte, privKey *ecdsa.PrivateKey) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return err
	}
	return nil
}
