//go:build linux

package core

import (
	"crypto"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"hash"
)

var errTLS = errors.New("outbound: tls handshake failed")

const (
	tlsRecHandshake       = 22
	tlsRecAppData         = 23
	tlsRecAlert           = 21
	tlsRecChangeCipher    = 20
	tlsHSClientHello      = 1
	tlsHSServerHello      = 2
	tlsHSEncryptedExts    = 8
	tlsHSCertificate      = 11
	tlsHSCertVerify       = 15
	tlsHSFinished         = 20
	suiteAES128GCMSHA256  = 0x1301
	suiteAES256GCMSHA384  = 0x1302
	tlsGroupX25519        = 0x001d
	tlsMaxRecordPlaintext = 16384
)

type tlsState int8

const (
	tlsExpectServerHello tlsState = iota
	tlsExpectEncrypted
	tls12ExpectHandshake
	tls12ExpectFinished
	tlsDone
)

type tlsTransport struct {
	state                     tlsState
	version                   uint16
	priv                      *ecdh.PrivateKey
	clientRandom              [32]byte
	serverRandom              [32]byte
	suite                     uint16
	hashFn                    func() hash.Hash
	hashLen                   int
	transcript                []byte
	handshakeSecret           []byte
	savedClientHS             []byte
	savedServerHS             []byte
	clientHSKey               aeadKey
	serverHSKey               aeadKey
	clientAppKey              aeadKey
	serverAppKey              aeadKey
	inHS                      []byte
	recBuf                    []byte
	serverName                string
	alpnH2                    bool
	skipVerify                bool
	certs                     [][]byte
	serverProvedKeyPossession bool
	negALPN                   string
	sentFinished              bool
	alpnNegotiatedH2          bool
	client12                  aead12
	server12                  aead12
	serverCipherActive        bool
	serverPub12               []byte
	master12                  []byte
}

type aeadKey struct {
	aead cipher.AEAD
	iv   [12]byte
	seq  uint64
}

func newTLSTransport(ex *Exchange) transport {
	host, _, _ := splitAuthority(ex.req.Authority, ex.req.Scheme)
	return &tlsTransport{
		serverName: host,
		alpnH2:     ex.key.h2,
		skipVerify: ex.key.skipVerify,
	}
}

func (t *tlsTransport) negotiatedALPN() string {
	return t.negALPN
}

func (t *tlsTransport) start(c *backendConn) error {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	t.priv = priv
	ch := t.buildClientHello(priv.PublicKey().Bytes())
	t.transcript = append(t.transcript, ch...)
	rec := tlsPlaintextRecord(tlsRecHandshake, ch)
	c.wbuf.write(rec)
	return nil
}

func (t *tlsTransport) wrapOut(c *backendConn, plain []byte) error {
	for len(plain) > 0 {
		chunk := plain
		if len(chunk) > tlsMaxRecordPlaintext {
			chunk = chunk[:tlsMaxRecordPlaintext]
		}
		plain = plain[len(chunk):]
		if t.version == 0x0303 {
			c.wbuf.write(t.seal12(&t.client12, tlsRecAppData, chunk))
			continue
		}
		rec, err := t.sealRecord(&t.clientAppKey, tlsRecAppData, chunk)
		if err != nil {
			return err
		}
		c.wbuf.write(rec)
	}
	return nil
}

func (t *tlsTransport) feed(c *backendConn, raw []byte) error {
	t.recBuf = append(t.recBuf, raw...)
	for {
		if len(t.recBuf) < 5 {
			return nil
		}
		ctype := t.recBuf[0]
		length := int(t.recBuf[3])<<8 | int(t.recBuf[4])
		if length > tlsMaxRecordPlaintext+256 {
			return errTLS
		}
		if len(t.recBuf) < 5+length {
			return nil
		}
		body := t.recBuf[5 : 5+length]
		if t.version == 0x0303 {
			if err := t.feed12Record(c, ctype, body); err != nil {
				return err
			}
			t.recBuf = t.recBuf[5+length:]
			continue
		}
		if t.state == tlsDone {
			if ctype == tlsRecChangeCipher {
				t.recBuf = t.recBuf[5+length:]
				continue
			}
			plain, err := t.openRecord(&t.serverAppKey, body)
			if err != nil {
				return err
			}
			t.recBuf = t.recBuf[5+length:]
			inner, realType := stripPadding(plain)
			if realType == tlsRecAppData {
				if err := c.proto.onData(c, inner); err != nil {
					return err
				}
			} else if realType == tlsRecAlert {
				return fpErrConnClosed
			}
			continue
		}
		switch ctype {
		case tlsRecChangeCipher:
		case tlsRecHandshake:
			if t.state == tlsExpectServerHello {
				if err := t.handleServerHello(body); err != nil {
					return err
				}
			} else {
				return errTLS
			}
		case tlsRecAppData:
			plain, err := t.openRecord(&t.serverHSKey, body)
			if err != nil {
				return err
			}
			inner, realType := stripPadding(plain)
			if realType == tlsRecHandshake {
				if err := t.handleEncryptedHandshake(c, inner); err != nil {
					return err
				}
			} else if realType == tlsRecAlert {
				return errTLS
			}
		case tlsRecAlert:
			return errTLS
		default:
			return errTLS
		}
		t.recBuf = t.recBuf[5+length:]
		if t.state == tlsDone {
			c.be.onTransportReady(c)
		}
	}
}

func (t *tlsTransport) handleServerHello(body []byte) error {
	t.transcript = append(t.transcript, body...)
	if len(body) < 4 || body[0] != tlsHSServerHello {
		return errTLS
	}
	msg := body[4:]
	if len(msg) < 34 {
		return errTLS
	}
	copy(t.serverRandom[:], msg[2:34])
	p := 34
	sidLen := int(msg[p])
	p += 1 + sidLen
	if p+2 > len(msg) {
		return errTLS
	}
	t.suite = uint16(msg[p])<<8 | uint16(msg[p+1])
	p += 2
	p++
	is13 := false
	var serverPub []byte
	if p+2 <= len(msg) {
		extLen := int(msg[p])<<8 | int(msg[p+1])
		p += 2
		if p+extLen > len(msg) {
			return errTLS
		}
		exts := msg[p : p+extLen]
		for len(exts) >= 4 {
			etype := uint16(exts[0])<<8 | uint16(exts[1])
			elen := int(exts[2])<<8 | int(exts[3])
			if 4+elen > len(exts) {
				return errTLS
			}
			edata := exts[4 : 4+elen]
			if etype == 0x2b && len(edata) >= 2 {
				if uint16(edata[0])<<8|uint16(edata[1]) == 0x0304 {
					is13 = true
				}
			}
			if etype == 51 && len(edata) >= 4 {
				group := uint16(edata[0])<<8 | uint16(edata[1])
				klen := int(edata[2])<<8 | int(edata[3])
				if group == tlsGroupX25519 && 4+klen <= len(edata) {
					serverPub = edata[4 : 4+klen]
				}
			}
			if etype == 0x10 && len(edata) >= 3 {
				plen := int(edata[2])
				if 3+plen <= len(edata) && string(edata[3:3+plen]) == "h2" {
					t.alpnNegotiatedH2 = true
				}
			}
			exts = exts[4+elen:]
		}
	}

	if !is13 {
		return t.begin12()
	}

	switch t.suite {
	case suiteAES128GCMSHA256:
		t.hashFn = sha256.New
		t.hashLen = 32
	case suiteAES256GCMSHA384:
		t.hashFn = sha512.New384
		t.hashLen = 48
	default:
		return errTLS
	}
	if serverPub == nil {
		return errTLS
	}
	t.version = 0x0304
	peerPub, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return err
	}
	shared, err := t.priv.ECDH(peerPub)
	if err != nil {
		return err
	}
	t.deriveHandshakeKeys(shared)
	t.state = tlsExpectEncrypted
	return nil
}

func (t *tlsTransport) deriveHandshakeKeys(shared []byte) {
	zero := make([]byte, t.hashLen)
	earlySecret := t.hkdfExtract(zero, zero)
	emptyHash := t.hashOf(nil)
	derived := t.deriveSecret(earlySecret, "derived", emptyHash)
	t.handshakeSecret = t.hkdfExtract(derived, shared)
	thHash := t.hashOf(t.transcript)
	cHS := t.deriveSecret(t.handshakeSecret, "c hs traffic", thHash)
	sHS := t.deriveSecret(t.handshakeSecret, "s hs traffic", thHash)
	t.savedClientHS = cHS
	t.savedServerHS = sHS
	t.clientHSKey = t.makeKey(cHS)
	t.serverHSKey = t.makeKey(sHS)
}

func (t *tlsTransport) handleEncryptedHandshake(c *backendConn, data []byte) error {
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
		if mtype == tlsHSFinished {
			if err := t.verifyServerFinished(msg); err != nil {
				return err
			}
			if err := t.finishHandshake(c, msg); err != nil {
				return err
			}
			t.inHS = t.inHS[4+mlen:]
			return nil
		}
		if mtype == tlsHSCertificate {
			t.parseCertificate(msg[4:])
		}
		if mtype == tlsHSCertVerify {
			if !t.skipVerify {
				if err := t.verifyCertificateVerify(msg[4:]); err != nil {
					return err
				}
			}
			t.serverProvedKeyPossession = true
		}
		if mtype == tlsHSEncryptedExts {
			t.parseEncryptedExtensions(msg[4:])
		}
		t.transcript = append(t.transcript, msg...)
		t.inHS = t.inHS[4+mlen:]
	}
}

func (t *tlsTransport) verifyServerFinished(msg []byte) error {
	thHash := t.hashOf(t.transcript)
	baseKey := t.serverFinishedKey()
	expected := t.hmacHash(baseKey, thHash)
	if len(msg) < 4 || !hmac.Equal(msg[4:], expected) {
		return errTLS
	}
	if !t.skipVerify {
		if !t.serverProvedKeyPossession {
			return errTLS
		}
		if err := t.verifyCerts(); err != nil {
			return err
		}
	}
	return nil
}

func (t *tlsTransport) finishHandshake(c *backendConn, serverFinished []byte) error {
	t.transcript = append(t.transcript, serverFinished...)

	zero := make([]byte, t.hashLen)
	derived := t.deriveSecret(t.handshakeSecret, "derived", t.hashOf(nil))
	masterSecret := t.hkdfExtract(derived, zero)
	thAfterFinished := t.hashOf(t.transcript)
	cAP := t.deriveSecret(masterSecret, "c ap traffic", thAfterFinished)
	sAP := t.deriveSecret(masterSecret, "s ap traffic", thAfterFinished)
	t.clientAppKey = t.makeKey(cAP)
	t.serverAppKey = t.makeKey(sAP)

	clientBaseKey := t.clientFinishedKey()
	verifyData := t.hmacHash(clientBaseKey, thAfterFinished)
	finishedMsg := make([]byte, 4+len(verifyData))
	finishedMsg[0] = tlsHSFinished
	finishedMsg[1] = byte(len(verifyData) >> 16)
	finishedMsg[2] = byte(len(verifyData) >> 8)
	finishedMsg[3] = byte(len(verifyData))
	copy(finishedMsg[4:], verifyData)

	ccs := tlsPlaintextRecord(tlsRecChangeCipher, []byte{0x01})
	c.wbuf.write(ccs)
	rec, err := t.sealRecord(&t.clientHSKey, tlsRecHandshake, finishedMsg)
	if err != nil {
		return err
	}
	c.wbuf.write(rec)
	t.negALPN = "http/1.1"
	if t.alpnNegotiatedH2 {
		t.negALPN = "h2"
	}
	t.state = tlsDone
	t.sentFinished = true
	return nil
}

func (t *tlsTransport) verifyCerts() error {
	if len(t.certs) == 0 {
		return errTLS
	}
	leaf, err := x509.ParseCertificate(t.certs[0])
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	for _, der := range t.certs[1:] {
		if inter, err := x509.ParseCertificate(der); err == nil {
			pool.AddCert(inter)
		}
	}
	_, err = leaf.Verify(x509.VerifyOptions{DNSName: t.serverName, Intermediates: pool})
	return err
}

func (t *tlsTransport) verifyCertificateVerify(body []byte) error {
	if len(body) < 4 {
		return errTLS
	}
	scheme := uint16(body[0])<<8 | uint16(body[1])
	sigLen := int(body[2])<<8 | int(body[3])
	if 4+sigLen > len(body) {
		return errTLS
	}
	if len(t.certs) == 0 {
		return errTLS
	}
	leaf, err := x509.ParseCertificate(t.certs[0])
	if err != nil {
		return err
	}
	return verifyHandshakeSignature(leaf.PublicKey, scheme, t.certVerifyContent(), body[4:4+sigLen])
}

func (t *tlsTransport) certVerifyContent() []byte {
	transcriptHash := t.hashOf(t.transcript)
	signed := make([]byte, 0, len(cvPrefix)+len(cvContext)+1+len(transcriptHash))
	signed = append(signed, cvPrefix[:]...)
	signed = append(signed, cvContext...)
	signed = append(signed, 0x00)
	signed = append(signed, transcriptHash...)
	return signed
}

func verifyHandshakeSignature(pub any, scheme uint16, signed, sig []byte) error {
	switch scheme {
	case 0x0804, 0x0805, 0x0806:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errTLS
		}
		h, id := signatureHash(scheme)
		h.Write(signed)
		return rsa.VerifyPSS(key, id, h.Sum(nil), sig,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: id})
	case 0x0403, 0x0503, 0x0603:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errTLS
		}
		h, _ := signatureHash(scheme)
		h.Write(signed)
		if !ecdsa.VerifyASN1(key, h.Sum(nil), sig) {
			return errTLS
		}
		return nil
	case 0x0807:
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errTLS
		}
		if !ed25519.Verify(key, signed, sig) {
			return errTLS
		}
		return nil
	default:
		return errTLS
	}
}

func signatureHash(scheme uint16) (hash.Hash, crypto.Hash) {
	switch scheme {
	case 0x0805, 0x0503:
		return sha512.New384(), crypto.SHA384
	case 0x0806, 0x0603:
		return sha512.New(), crypto.SHA512
	default:
		return sha256.New(), crypto.SHA256
	}
}

func (t *tlsTransport) parseCertificate(body []byte) {
	if len(body) < 1 {
		return
	}
	ctxLen := int(body[0])
	if 1+ctxLen+3 > len(body) {
		return
	}
	p := 1 + ctxLen
	listLen := int(body[p])<<16 | int(body[p+1])<<8 | int(body[p+2])
	p += 3
	end := p + listLen
	if end > len(body) {
		end = len(body)
	}
	for p+3 <= end {
		clen := int(body[p])<<16 | int(body[p+1])<<8 | int(body[p+2])
		p += 3
		if p+clen > end {
			return
		}
		der := make([]byte, clen)
		copy(der, body[p:p+clen])
		t.certs = append(t.certs, der)
		p += clen
		if p+2 <= end {
			extLen := int(body[p])<<8 | int(body[p+1])
			p += 2 + extLen
		}
	}
}
