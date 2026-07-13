//go:build linux

package core

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"hash"
)

func hashForScheme(scheme uint16) crypto.Hash {
	switch scheme & 0xff {
	case 0x04:
		return crypto.SHA256
	case 0x05:
		return crypto.SHA384
	case 0x06:
		return crypto.SHA512
	}
	return crypto.SHA256
}

const (
	suite12RSAAES128 = 0xc02f
	suite12ECDSAES128 = 0xc02b
	suite12RSAAES256 = 0xc030
	suite12ECDSAES256 = 0xc02c
)

type aead12 struct {
	aead cipher.AEAD
	iv   [4]byte
	seq  uint64
}

func (t *tlsTransport) begin12() error {
	switch t.suite {
	case suite12RSAAES128, suite12ECDSAES128, suite12RSAAES256, suite12ECDSAES256:
	default:
		return errTLS
	}
	if t.suite == suite12RSAAES256 || t.suite == suite12ECDSAES256 {
		t.hashFn = sha512.New384
		t.hashLen = 48
	} else {
		t.hashFn = sha256.New
		t.hashLen = 32
	}
	t.version = 0x0303
	t.state = tls12ExpectHandshake
	return nil
}

func (t *tlsTransport) feed12Record(c *backendConn, ctype byte, body []byte) error {
	switch ctype {
	case tlsRecChangeCipher:
		t.serverCipherActive = true
		return nil
	case tlsRecHandshake:
		if t.serverCipherActive {
			plain, err := t.open12(&t.server12, tlsRecHandshake, body)
			if err != nil {
				return err
			}
			return t.handle12Finished(c, plain)
		}
		return t.handle12Handshake(c, body)
	case tlsRecAppData:
		plain, err := t.open12(&t.server12, tlsRecAppData, body)
		if err != nil {
			return err
		}
		return c.proto.onData(c, plain)
	case tlsRecAlert:
		return fpErrConnClosed
	}
	return nil
}

func (t *tlsTransport) handle12Handshake(c *backendConn, data []byte) error {
	t.inHS = append(t.inHS, data...)
	for {
		if len(t.inHS) < 4 {
			return nil
		}
		mlen := int(t.inHS[1])<<16 | int(t.inHS[2])<<8 | int(t.inHS[3])
		if len(t.inHS) < 4+mlen {
			return nil
		}
		msg := t.inHS[:4+mlen]
		mtype := msg[0]
		t.transcript = append(t.transcript, msg...)
		switch mtype {
		case tlsHSCertificate:
			t.parseCertificate(msg[4:])
		case 12:
			if err := t.parseServerKeyExchange(msg[4:]); err != nil {
				return err
			}
		case 14:
			if err := t.send12ClientFlight(c); err != nil {
				return err
			}
		}
		t.inHS = t.inHS[4+mlen:]
	}
}

func (t *tlsTransport) parseServerKeyExchange(body []byte) error {
	if len(body) < 4 {
		return errTLS
	}
	if body[0] != 3 {
		return errTLS
	}
	group := uint16(body[1])<<8 | uint16(body[2])
	if group != tlsGroupX25519 {
		return errTLS
	}
	pubLen := int(body[3])
	if 4+pubLen > len(body) {
		return errTLS
	}
	t.serverPub12 = make([]byte, pubLen)
	copy(t.serverPub12, body[4:4+pubLen])
	paramsEnd := 4 + pubLen

	if t.skipVerify {
		return nil
	}
	if len(body) < paramsEnd+4 {
		return errTLS
	}
	sigScheme := uint16(body[paramsEnd])<<8 | uint16(body[paramsEnd+1])
	sigLen := int(body[paramsEnd+2])<<8 | int(body[paramsEnd+3])
	sigStart := paramsEnd + 4
	if sigStart+sigLen > len(body) {
		return errTLS
	}
	sig := body[sigStart : sigStart+sigLen]
	signed := make([]byte, 0, 64+paramsEnd)
	signed = append(signed, t.clientRandom[:]...)
	signed = append(signed, t.serverRandom[:]...)
	signed = append(signed, body[:paramsEnd]...)
	return t.verifySKESignature(sigScheme, signed, sig)
}

func (t *tlsTransport) verifySKESignature(scheme uint16, signed, sig []byte) error {
	if len(t.certs) == 0 {
		return errTLS
	}
	leaf, err := x509.ParseCertificate(t.certs[0])
	if err != nil {
		return err
	}
	var h hash.Hash
	var ch []byte
	switch scheme & 0xff {
	case 0x04:
		s := sha256.Sum256(signed)
		ch = s[:]
		h = sha256.New()
	case 0x05:
		s := sha512.Sum384(signed)
		ch = s[:]
		h = sha512.New384()
	case 0x06:
		s := sha512.Sum512(signed)
		ch = s[:]
		h = sha512.New()
	case 0x08:
		ch = signed
	default:
		s := sha256.Sum256(signed)
		ch = s[:]
		h = sha256.New()
	}
	_ = h
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if scheme>>8 == 0x08 {
			return rsa.VerifyPSS(pub, hashForScheme(scheme), ch, sig, nil)
		}
		return rsa.VerifyPKCS1v15(pub, hashForScheme(scheme), ch, sig)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, ch, sig) {
			return errTLS
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, signed, sig) {
			return errTLS
		}
		return nil
	}
	return errTLS
}

func (t *tlsTransport) send12ClientFlight(c *backendConn) error {
	if !t.skipVerify {
		if err := t.verifyCerts(); err != nil {
			return err
		}
	}
	peerPub, err := ecdh.X25519().NewPublicKey(t.serverPub12)
	if err != nil {
		return err
	}
	shared, err := t.priv.ECDH(peerPub)
	if err != nil {
		return err
	}

	crsr := make([]byte, 0, 64)
	crsr = append(crsr, t.clientRandom[:]...)
	crsr = append(crsr, t.serverRandom[:]...)
	master := t.prf(shared, "master secret", crsr, 48)
	t.master12 = master

	srcr := make([]byte, 0, 64)
	srcr = append(srcr, t.serverRandom[:]...)
	srcr = append(srcr, t.clientRandom[:]...)
	keyLen := t.keyLen()
	kb := t.prf(master, "key expansion", srcr, 2*keyLen+8)
	cwk := kb[:keyLen]
	swk := kb[keyLen : 2*keyLen]
	civ := kb[2*keyLen : 2*keyLen+4]
	siv := kb[2*keyLen+4 : 2*keyLen+8]
	t.client12 = makeAEAD12(cwk, civ)
	t.server12 = makeAEAD12(swk, siv)

	pub := t.priv.PublicKey().Bytes()
	cke := make([]byte, 0, 5+len(pub))
	cke = append(cke, 16, 0, 0, byte(len(pub)+1), byte(len(pub)))
	cke = append(cke, pub...)
	t.transcript = append(t.transcript, cke...)
	c.wbuf.write(tlsPlaintextRecord(tlsRecHandshake, cke))

	verifyData := t.prf(master, "client finished", t.hashOf(t.transcript), 12)
	fin := make([]byte, 4+12)
	fin[0] = tlsHSFinished
	fin[3] = 12
	copy(fin[4:], verifyData)
	t.transcript = append(t.transcript, fin...)

	c.wbuf.write(tlsPlaintextRecord(tlsRecChangeCipher, []byte{0x01}))
	c.wbuf.write(t.seal12(&t.client12, tlsRecHandshake, fin))
	t.state = tls12ExpectFinished
	return nil
}

func (t *tlsTransport) handle12Finished(c *backendConn, plain []byte) error {
	if len(plain) < 4 || plain[0] != tlsHSFinished {
		return errTLS
	}
	expected := t.prf(t.master12, "server finished", t.hashOf(t.transcript), 12)
	if !hmac.Equal(plain[4:4+12], expected) {
		return errTLS
	}
	t.negALPN = "http/1.1"
	if t.alpnNegotiatedH2 {
		t.negALPN = "h2"
	}
	t.state = tlsDone
	c.loop.onTransportReady(c)
	return nil
}

func (t *tlsTransport) prf(secret []byte, label string, seed []byte, length int) []byte {
	labelSeed := make([]byte, 0, len(label)+len(seed))
	labelSeed = append(labelSeed, label...)
	labelSeed = append(labelSeed, seed...)
	out := make([]byte, 0, length)
	a := labelSeed
	for len(out) < length {
		am := hmac.New(t.hashFn, secret)
		am.Write(a)
		a = am.Sum(nil)
		pm := hmac.New(t.hashFn, secret)
		pm.Write(a)
		pm.Write(labelSeed)
		out = append(out, pm.Sum(nil)...)
	}
	return out[:length]
}

func makeAEAD12(key, iv []byte) aead12 {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	var k aead12
	k.aead = gcm
	copy(k.iv[:], iv)
	return k
}

func (t *tlsTransport) seal12(k *aead12, contentType byte, plain []byte) []byte {
	var nonce [12]byte
	copy(nonce[:4], k.iv[:])
	seq := k.seq
	for i := 0; i < 8; i++ {
		nonce[11-i] = byte(seq)
		seq >>= 8
	}
	var aad [13]byte
	s := k.seq
	for i := 0; i < 8; i++ {
		aad[7-i] = byte(s)
		s >>= 8
	}
	aad[8] = contentType
	aad[9] = 0x03
	aad[10] = 0x03
	aad[11] = byte(len(plain) >> 8)
	aad[12] = byte(len(plain))

	ct := k.aead.Seal(nil, nonce[:], plain, aad[:])
	total := 8 + len(ct)
	rec := make([]byte, 5+total)
	rec[0] = contentType
	rec[1] = 0x03
	rec[2] = 0x03
	rec[3] = byte(total >> 8)
	rec[4] = byte(total)
	copy(rec[5:13], nonce[4:])
	copy(rec[13:], ct)
	k.seq++
	return rec
}

func (t *tlsTransport) open12(k *aead12, contentType byte, body []byte) ([]byte, error) {
	if len(body) < 8+16 {
		return nil, errTLS
	}
	var nonce [12]byte
	copy(nonce[:4], k.iv[:])
	copy(nonce[4:], body[:8])
	ct := body[8:]
	plainLen := len(ct) - 16
	var aad [13]byte
	s := k.seq
	for i := 0; i < 8; i++ {
		aad[7-i] = byte(s)
		s >>= 8
	}
	aad[8] = contentType
	aad[9] = 0x03
	aad[10] = 0x03
	aad[11] = byte(plainLen >> 8)
	aad[12] = byte(plainLen)
	out, err := k.aead.Open(nil, nonce[:], ct, aad[:])
	if err != nil {
		return nil, err
	}
	k.seq++
	return out, nil
}
