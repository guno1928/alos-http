//go:build linux

package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"hash"
)

func (t *tlsTransport) hashOf(data []byte) []byte {
	h := t.hashFn()
	h.Write(data)
	return h.Sum(nil)
}

func (t *tlsTransport) hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(t.hashFn, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func (t *tlsTransport) hkdfExpandLabel(secret []byte, label string, ctx []byte, length int) []byte {
	const prefix = "tls13 "
	fullLen := len(prefix) + len(label)
	info := make([]byte, 0, 2+1+fullLen+1+len(ctx))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(fullLen))
	info = append(info, prefix...)
	info = append(info, label...)
	info = append(info, byte(len(ctx)))
	info = append(info, ctx...)

	out := make([]byte, 0, length)
	var prev []byte
	var counter byte = 1
	for len(out) < length {
		mac := hmac.New(t.hashFn, secret)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{counter})
		prev = mac.Sum(nil)
		out = append(out, prev...)
		counter++
	}
	return out[:length]
}

func (t *tlsTransport) deriveSecret(secret []byte, label string, transcriptHash []byte) []byte {
	return t.hkdfExpandLabel(secret, label, transcriptHash, t.hashLen)
}

func (t *tlsTransport) hmacHash(key, data []byte) []byte {
	mac := hmac.New(t.hashFn, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func (t *tlsTransport) serverFinishedKey() []byte {
	return t.hkdfExpandLabel(t.serverHSSecret(), "finished", nil, t.hashLen)
}

func (t *tlsTransport) clientFinishedKey() []byte {
	return t.hkdfExpandLabel(t.clientHSSecret(), "finished", nil, t.hashLen)
}

func (t *tlsTransport) serverHSSecret() []byte {
	return t.savedServerHS
}

func (t *tlsTransport) clientHSSecret() []byte {
	return t.savedClientHS
}

func (t *tlsTransport) keyLen() int {
	if t.suite == suiteAES256GCMSHA384 {
		return 32
	}
	return 16
}

func (t *tlsTransport) makeKey(secret []byte) aeadKey {
	keyBytes := t.hkdfExpandLabel(secret, "key", nil, t.keyLen())
	ivBytes := t.hkdfExpandLabel(secret, "iv", nil, 12)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	var k aeadKey
	k.aead = aead
	copy(k.iv[:], ivBytes)
	return k
}

func (k *aeadKey) nonce() [12]byte {
	var n [12]byte
	copy(n[:], k.iv[:])
	seq := k.seq
	for i := 0; i < 8; i++ {
		n[11-i] ^= byte(seq)
		seq >>= 8
	}
	return n
}

func (t *tlsTransport) sealRecord(k *aeadKey, contentType byte, plain []byte) ([]byte, error) {
	inner := make([]byte, len(plain)+1)
	copy(inner, plain)
	inner[len(plain)] = contentType
	total := len(inner) + 16
	rec := make([]byte, 5+total)
	rec[0] = tlsRecAppData
	rec[1] = 0x03
	rec[2] = 0x03
	rec[3] = byte(total >> 8)
	rec[4] = byte(total)
	nonce := k.nonce()
	sealed := k.aead.Seal(rec[5:5], nonce[:], inner, rec[:5])
	k.seq++
	return rec[:5+len(sealed)], nil
}

func (t *tlsTransport) openRecord(k *aeadKey, body []byte) ([]byte, error) {
	if len(body) < 16 {
		return nil, errTLS
	}
	aad := make([]byte, 5)
	aad[0] = tlsRecAppData
	aad[1] = 0x03
	aad[2] = 0x03
	aad[3] = byte(len(body) >> 8)
	aad[4] = byte(len(body))
	nonce := k.nonce()
	out, err := k.aead.Open(body[:0], nonce[:], body, aad)
	if err != nil {
		return nil, err
	}
	k.seq++
	return out, nil
}

func stripPadding(plain []byte) ([]byte, byte) {
	i := len(plain) - 1
	for i >= 0 && plain[i] == 0 {
		i--
	}
	if i < 0 {
		return nil, 0
	}
	return plain[:i], plain[i]
}

func tlsPlaintextRecord(contentType byte, body []byte) []byte {
	rec := make([]byte, 5+len(body))
	rec[0] = contentType
	rec[1] = 0x03
	rec[2] = 0x03
	rec[3] = byte(len(body) >> 8)
	rec[4] = byte(len(body))
	copy(rec[5:], body)
	return rec
}

func (t *tlsTransport) buildClientHello(pub []byte) []byte {
	var b []byte
	b = append(b, 0x03, 0x03)
	var random [32]byte
	_, _ = rand.Read(random[:])
	copy(t.clientRandom[:], random[:])
	b = append(b, random[:]...)
	var sid [32]byte
	_, _ = rand.Read(sid[:])
	b = append(b, 32)
	b = append(b, sid[:]...)
	b = append(b, 0x00, 0x0c, 0x13, 0x01, 0x13, 0x02, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30)
	b = append(b, 0x01, 0x00)

	exts := t.buildExtensions(pub)
	b = append(b, byte(len(exts)>>8), byte(len(exts)))
	b = append(b, exts...)

	msg := make([]byte, 4+len(b))
	msg[0] = tlsHSClientHello
	msg[1] = byte(len(b) >> 16)
	msg[2] = byte(len(b) >> 8)
	msg[3] = byte(len(b))
	copy(msg[4:], b)
	return msg
}

func (t *tlsTransport) buildExtensions(pub []byte) []byte {
	var e []byte

	sni := []byte(t.serverName)
	sniData := make([]byte, 0, len(sni)+5)
	nameLen := len(sni)
	listLen := nameLen + 3
	sniData = append(sniData, byte(listLen>>8), byte(listLen))
	sniData = append(sniData, 0x00)
	sniData = append(sniData, byte(nameLen>>8), byte(nameLen))
	sniData = append(sniData, sni...)
	e = appendExt(e, 0x0000, sniData)

	e = appendExt(e, 0x000b, []byte{0x01, 0x00})

	e = appendExt(e, 0x000a, []byte{0x00, 0x02, 0x00, 0x1d})

	sigAlgs := []byte{0x00, 0x0a, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05}
	e = appendExt(e, 0x000d, sigAlgs)

	e = appendExt(e, 0x002b, []byte{0x04, 0x03, 0x04, 0x03, 0x03})

	e = appendExt(e, 0x0033, buildKeyShare(pub))

	e = appendExt(e, 0x0010, buildALPN(t.alpnH2))

	return e
}

func appendExt(dst []byte, extType uint16, data []byte) []byte {
	dst = append(dst, byte(extType>>8), byte(extType))
	dst = append(dst, byte(len(data)>>8), byte(len(data)))
	return append(dst, data...)
}

func buildKeyShare(pub []byte) []byte {
	entryLen := 4 + len(pub)
	out := make([]byte, 0, 2+entryLen)
	out = append(out, byte(entryLen>>8), byte(entryLen))
	out = append(out, 0x00, 0x1d)
	out = append(out, byte(len(pub)>>8), byte(len(pub)))
	out = append(out, pub...)
	return out
}

func buildALPN(h2 bool) []byte {
	var protos []byte
	if h2 {
		protos = append(protos, 2, 'h', '2')
	}
	protos = append(protos, 8, 'h', 't', 't', 'p', '/', '1', '.', '1')
	out := make([]byte, 0, 2+len(protos))
	out = append(out, byte(len(protos)>>8), byte(len(protos)))
	out = append(out, protos...)
	return out
}

func (t *tlsTransport) parseEncryptedExtensions(body []byte) {
	if len(body) < 2 {
		return
	}
	extLen := int(body[0])<<8 | int(body[1])
	exts := body[2:]
	if extLen > len(exts) {
		extLen = len(exts)
	}
	exts = exts[:extLen]
	for len(exts) >= 4 {
		etype := uint16(exts[0])<<8 | uint16(exts[1])
		elen := int(exts[2])<<8 | int(exts[3])
		if 4+elen > len(exts) {
			return
		}
		edata := exts[4 : 4+elen]
		if etype == 0x0010 && len(edata) >= 3 {
			p := 2
			plen := int(edata[p])
			p++
			if p+plen <= len(edata) {
				proto := string(edata[p : p+plen])
				if proto == "h2" {
					t.alpnNegotiatedH2 = true
				}
			}
		}
		exts = exts[4+elen:]
	}
}

var _ hash.Hash
