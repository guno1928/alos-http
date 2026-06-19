package core

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

func tls12PRF(newHash func() hash.Hash, secret, label, seed []byte, length int) []byte {
	labelSeed := make([]byte, 0, len(label)+len(seed))
	labelSeed = append(labelSeed, label...)
	labelSeed = append(labelSeed, seed...)

	out := make([]byte, 0, length)
	a := labelSeed
	for len(out) < length {
		h := hmac.New(newHash, secret)
		h.Write(a)
		a = h.Sum(nil)

		h2 := hmac.New(newHash, secret)
		h2.Write(a)
		h2.Write(labelSeed)
		out = append(out, h2.Sum(nil)...)
	}
	return out[:length]
}

func tls12MasterSecret(newHash func() hash.Hash, pms, clientRandom, serverRandom []byte) []byte {
	seed := make([]byte, 0, 64)
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)
	return tls12PRF(newHash, pms, []byte("master secret"), seed, 48)
}

func tls12KeyBlock(newHash func() hash.Hash, master, clientRandom, serverRandom []byte, keyLen, ivLen int) (cwk, swk, civ, siv []byte) {
	seed := make([]byte, 0, 64)
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)
	kb := tls12PRF(newHash, master, []byte("key expansion"), seed, 2*keyLen+2*ivLen)
	off := 0
	cwk = kb[off : off+keyLen]
	off += keyLen
	swk = kb[off : off+keyLen]
	off += keyLen
	civ = kb[off : off+ivLen]
	off += ivLen
	siv = kb[off : off+ivLen]
	return
}

func tls12Finished(newHash func() hash.Hash, master []byte, label string, transcriptHash []byte) []byte {
	return tls12PRF(newHash, master, []byte(label), transcriptHash, 12)
}

type tls12KeyType uint8

const (
	keyTypeECDSA tls12KeyType = iota
	keyTypeRSA
)

type tls12Suite struct {
	id       uint16
	keyType  tls12KeyType
	keyLen   int
	ivLen    int
	newHash  func() hash.Hash
	aead     func(key []byte) (cipher.AEAD, error)
	isChaCha bool
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

var tls12Suites = []tls12Suite{
	{0xC02B, keyTypeECDSA, 16, 4, sha256.New, newGCM, false},
	{0xC02F, keyTypeRSA, 16, 4, sha256.New, newGCM, false},
	{0xCCA9, keyTypeECDSA, 32, 12, sha256.New, chacha20poly1305.New, true},
	{0xCCA8, keyTypeRSA, 32, 12, sha256.New, chacha20poly1305.New, true},
	{0xC02C, keyTypeECDSA, 32, 4, sha512.New384, newGCM, false},
	{0xC030, keyTypeRSA, 32, 4, sha512.New384, newGCM, false},
}

func negotiateTLS12Suite(clientIDs []uint16, kt tls12KeyType) *tls12Suite {
	for i := range tls12Suites {
		if tls12Suites[i].keyType != kt {
			continue
		}
		for _, cid := range clientIDs {
			if tls12Suites[i].id == cid {
				return &tls12Suites[i]
			}
		}
	}
	return nil
}

type tls12Curve uint16

const (
	curveP256   tls12Curve = 0x0017
	curveX25519 tls12Curve = 0x001d
)

func ecdhCurve(c tls12Curve) (ecdh.Curve, bool) {
	switch c {
	case curveP256:
		return ecdh.P256(), true
	case curveX25519:
		return ecdh.X25519(), true
	}
	return nil, false
}

func tls12GenerateECDHE(c tls12Curve) (*ecdh.PrivateKey, []byte, error) {
	curve, ok := ecdhCurve(c)
	if !ok {
		return nil, nil, errors.New("unsupported curve")
	}
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

func tls12ECDHEShared(c tls12Curve, priv *ecdh.PrivateKey, peer []byte) ([]byte, bool) {
	curve, ok := ecdhCurve(c)
	if !ok {
		return nil, false
	}
	peerPub, err := curve.NewPublicKey(peer)
	if err != nil {
		return nil, false
	}
	shared, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, false
	}
	return shared, true
}

type tls12AEAD struct {
	aead     cipher.AEAD
	iv       []byte
	seq      uint64
	isChaCha bool
}

func (c *tls12AEAD) aad(seq uint64, typ byte, ptLen int) []byte {
	var b [13]byte
	binary.BigEndian.PutUint64(b[0:8], seq)
	b[8] = typ
	b[9] = 0x03
	b[10] = 0x03
	binary.BigEndian.PutUint16(b[11:13], uint16(ptLen))
	return b[:]
}

func (c *tls12AEAD) nonce(seq uint64) []byte {
	n := make([]byte, 12)
	if c.isChaCha {
		copy(n, c.iv)
		var s [8]byte
		binary.BigEndian.PutUint64(s[:], seq)
		for i := 0; i < 8; i++ {
			n[4+i] ^= s[i]
		}
		return n
	}
	copy(n[0:4], c.iv)
	binary.BigEndian.PutUint64(n[4:12], seq)
	return n
}

func (c *tls12AEAD) seal(typ byte, plaintext []byte) []byte {
	seq := c.seq
	c.seq++
	nonce := c.nonce(seq)
	aad := c.aad(seq, typ, len(plaintext))

	var fragment []byte
	if c.isChaCha {
		fragment = c.aead.Seal(nil, nonce, plaintext, aad)
	} else {
		fragment = make([]byte, 8, 8+len(plaintext)+c.aead.Overhead())
		binary.BigEndian.PutUint64(fragment[0:8], seq)
		fragment = c.aead.Seal(fragment, nonce, plaintext, aad)
	}
	rec := make([]byte, 5, 5+len(fragment))
	rec[0] = typ
	rec[1] = 0x03
	rec[2] = 0x03
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(fragment)))
	return append(rec, fragment...)
}

func (c *tls12AEAD) open(record []byte) (byte, []byte, bool) {
	if len(record) < 5 {
		return 0, nil, false
	}
	typ := record[0]
	fragLen := int(record[3])<<8 | int(record[4])
	if len(record) < 5+fragLen {
		return 0, nil, false
	}
	fragment := record[5 : 5+fragLen]
	seq := c.seq

	var nonce, ct []byte
	if c.isChaCha {
		nonce = c.nonce(seq)
		ct = fragment
	} else {
		if len(fragment) < 8 {
			return 0, nil, false
		}
		n := make([]byte, 12)
		copy(n[0:4], c.iv)
		copy(n[4:12], fragment[0:8])
		nonce = n
		ct = fragment[8:]
	}
	ptLen := len(ct) - c.aead.Overhead()
	if ptLen < 0 {
		return 0, nil, false
	}
	aad := c.aad(seq, typ, ptLen)
	pt, err := c.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return 0, nil, false
	}
	c.seq++
	return typ, pt, true
}

func tls12Handshake(typ byte, body []byte) []byte {
	out := make([]byte, 4, 4+len(body))
	out[0] = typ
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	return append(out, body...)
}

func buildTLS12ServerHello(serverRandom []byte, suite uint16, alpn string) []byte {
	body := make([]byte, 0, 80)
	body = append(body, 0x03, 0x03)
	body = append(body, serverRandom...)
	body = append(body, 0x00)
	body = append(body, byte(suite>>8), byte(suite))
	body = append(body, 0x00)

	ext := make([]byte, 0, 32)
	ext = append(ext, 0xff, 0x01, 0x00, 0x01, 0x00)
	ext = append(ext, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)
	if alpn != "" {
		inner := []byte{byte(len(alpn))}
		inner = append(inner, alpn...)
		list := append([]byte{byte(len(inner) >> 8), byte(len(inner))}, inner...)
		ext = append(ext, 0x00, 0x10, byte(len(list)>>8), byte(len(list)))
		ext = append(ext, list...)
	}
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	return tls12Handshake(0x02, body)
}

func buildTLS12Certificate(chain [][]byte) []byte {
	total := 0
	for _, c := range chain {
		total += 3 + len(c)
	}
	body := make([]byte, 0, 3+total)
	body = append(body, byte(total>>16), byte(total>>8), byte(total))
	for _, c := range chain {
		body = append(body, byte(len(c)>>16), byte(len(c)>>8), byte(len(c)))
		body = append(body, c...)
	}
	return tls12Handshake(0x0b, body)
}

func buildTLS12ServerHelloDone() []byte { return tls12Handshake(0x0e, nil) }

func parseTLS12ClientKeyExchange(msg []byte) ([]byte, bool) {
	if len(msg) < 4 || msg[0] != 0x10 {
		return nil, false
	}
	body := msg[4:]
	if len(body) < 1 {
		return nil, false
	}
	pl := int(body[0])
	if 1+pl > len(body) {
		return nil, false
	}
	return body[1 : 1+pl], true
}

const (
	sigSchemeECDSAP256SHA256 uint16 = 0x0403
	sigSchemeRSAPSSSHA256    uint16 = 0x0804
)

func tls12Sign(signer crypto.Signer, msg []byte) (uint16, []byte, error) {
	d := sha256.Sum256(msg)
	switch k := signer.(type) {
	case *ecdsa.PrivateKey:
		sig, err := ecdsa.SignASN1(rand.Reader, k, d[:])
		return sigSchemeECDSAP256SHA256, sig, err
	case *rsa.PrivateKey:
		sig, err := rsa.SignPSS(rand.Reader, k, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		return sigSchemeRSAPSSSHA256, sig, err
	}
	return 0, nil, errors.New("unsupported signer for ServerKeyExchange")
}

func buildTLS12ServerKeyExchange(signer crypto.Signer, clientRandom, serverRandom []byte, curve tls12Curve, pub []byte) ([]byte, error) {
	params := make([]byte, 0, 4+len(pub))
	params = append(params, 0x03)
	params = append(params, byte(uint16(curve)>>8), byte(uint16(curve)))
	params = append(params, byte(len(pub)))
	params = append(params, pub...)

	signed := make([]byte, 0, 64+len(params))
	signed = append(signed, clientRandom...)
	signed = append(signed, serverRandom...)
	signed = append(signed, params...)

	scheme, sig, err := tls12Sign(signer, signed)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, len(params)+4+len(sig))
	body = append(body, params...)
	body = append(body, byte(scheme>>8), byte(scheme))
	body = append(body, byte(len(sig)>>8), byte(len(sig)))
	body = append(body, sig...)
	return tls12Handshake(0x0c, body), nil
}
