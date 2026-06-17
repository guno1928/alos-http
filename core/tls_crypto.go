package core

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
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
	"sync"
	"time"

	"github.com/ericlagergren/aegis"
	"golang.org/x/crypto/chacha20poly1305"
)

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

func FindSuiteByID(id uint16) *CipherSuiteConfig {
	for i := range SupportedSuites {
		if SupportedSuites[i].ID == id {
			return &SupportedSuites[i]
		}
	}
	return nil
}

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

func (t *TrafficAEAD) Overhead() int {
	return t.oh
}

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
