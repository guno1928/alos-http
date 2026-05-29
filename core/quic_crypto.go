package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/chacha20"
)

var quicV1Salt = [20]byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

type quicKeys struct {
	aead      cipher.AEAD
	hp        headerProtector
	iv        [12]byte
	valid     bool
	suiteID   uint16
}

type headerProtector interface {
	mask(sample []byte) [5]byte
}

type aesHeaderProtector struct {
	block cipher.Block
}

func (a *aesHeaderProtector) mask(sample []byte) [5]byte {
	var encrypted [16]byte
	a.block.Encrypt(encrypted[:], sample[:16])
	return [5]byte{encrypted[0], encrypted[1], encrypted[2], encrypted[3], encrypted[4]}
}

type chachaHeaderProtector struct {
	key [32]byte
}

func (c *chachaHeaderProtector) mask(sample []byte) [5]byte {
	counter := binary.LittleEndian.Uint32(sample[:4])
	nonce := sample[4:16]
	cipher, err := chacha20.NewUnauthenticatedCipher(c.key[:], nonce)
	if err != nil {
		return [5]byte{}
	}
	cipher.SetCounter(counter)
	var out [5]byte
	cipher.XORKeyStream(out[:], out[:])
	return out
}

func quicExpandLabel(h func() hash.Hash, secret []byte, label string, ctx []byte, length int) []byte {
	const prefix = "quic "
	fullLen := len(prefix) + len(label)
	infoLen := 2 + 1 + fullLen + 1 + len(ctx)
	var infoBuf [128]byte
	var info []byte
	if infoLen <= len(infoBuf) {
		info = infoBuf[:infoLen]
	} else {
		info = make([]byte, infoLen)
	}
	info[0] = byte(length >> 8)
	info[1] = byte(length)
	info[2] = byte(fullLen)
	copy(info[3:], prefix)
	copy(info[3+len(prefix):], label)
	info[3+fullLen] = byte(len(ctx))
	copy(info[3+fullLen+1:], ctx)

	mac := hmac.New(h, secret)
	mac.Write(info)
	mac.Write(hkdfExpandOneByte[:])
	return mac.Sum(nil)[:length]
}

func quicDeriveKeys(h func() hash.Hash, secret []byte, cs *CipherSuiteConfig) (*quicKeys, error) {
	key := TLSExpandLabel(h, secret, "quic key", nil, cs.KeyLen)
	iv := TLSExpandLabel(h, secret, "quic iv", nil, cs.IVLen)
	hpKey := TLSExpandLabel(h, secret, "quic hp", nil, cs.KeyLen)

	aead, err := cs.MakeAEAD(key)
	if err != nil {
		return nil, err
	}

	qk := &quicKeys{
		aead:    aead,
		valid:   true,
		suiteID: cs.ID,
	}
	copy(qk.iv[:], iv)

	switch cs.ID {
	case 0x1301, 0x1302:
		block, err := aes.NewCipher(hpKey)
		if err != nil {
			return nil, err
		}
		qk.hp = &aesHeaderProtector{block: block}
	case 0x1303:
		hp := &chachaHeaderProtector{}
		copy(hp.key[:], hpKey)
		qk.hp = hp
	}

	return qk, nil
}

func quicDeriveInitialKeys(dcid []byte) (client, server *quicKeys, err error) {
	h := sha256.New
	cs := &SupportedSuites[0]

	initialSecret := TLSExtract(h, quicV1Salt[:], dcid)

	clientInitial := TLSExpandLabel(h, initialSecret, "client in", nil, 32)
	serverInitial := TLSExpandLabel(h, initialSecret, "server in", nil, 32)

	client, err = quicDeriveKeys(h, clientInitial, cs)
	if err != nil {
		return nil, nil, err
	}

	server, err = quicDeriveKeys(h, serverInitial, cs)
	if err != nil {
		return nil, nil, err
	}

	return client, server, nil
}

func quicDeriveHandshakeKeys(h func() hash.Hash, secret []byte, cs *CipherSuiteConfig) (*quicKeys, error) {
	return quicDeriveKeys(h, secret, cs)
}

func quicDeriveAppKeys(h func() hash.Hash, secret []byte, cs *CipherSuiteConfig) (*quicKeys, error) {
	return quicDeriveKeys(h, secret, cs)
}

func (qk *quicKeys) encrypt(dst, header, payload []byte, pn uint64, pnOffset int) []byte {
	var nonce [12]byte
	copy(nonce[:], qk.iv[:])
	binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(nonce[4:])^pn)

	dst = qk.aead.Seal(dst, nonce[:], payload, header)
	return dst
}

func (qk *quicKeys) decrypt(dst, header, payload []byte, pn uint64) ([]byte, error) {
	var nonce [12]byte
	copy(nonce[:], qk.iv[:])
	binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(nonce[4:])^pn)

	return qk.aead.Open(dst, nonce[:], payload, header)
}

func (qk *quicKeys) applyHeaderProtection(packet []byte, pnOffset int, pnLen int) {
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(packet) {
		return
	}
	mask := qk.hp.mask(packet[sampleOffset:])

	if packet[0]&0x80 != 0 {
		packet[0] ^= mask[0] & 0x0f
	} else {
		packet[0] ^= mask[0] & 0x1f
	}
	for i := 0; i < pnLen; i++ {
		packet[pnOffset+i] ^= mask[1+i]
	}
}

func (qk *quicKeys) removeHeaderProtection(packet []byte, pnOffset int) (pnLen int) {
	sampleOffset := pnOffset + 4
	if sampleOffset+16 > len(packet) {
		return 0
	}
	mask := qk.hp.mask(packet[sampleOffset:])

	if packet[0]&0x80 != 0 {
		packet[0] ^= mask[0] & 0x0f
	} else {
		packet[0] ^= mask[0] & 0x1f
	}

	pnLen = int(packet[0]&0x03) + 1
	for i := 0; i < pnLen; i++ {
		packet[pnOffset+i] ^= mask[1+i]
	}
	return pnLen
}

func quicDecodePacketNumber(truncated uint64, truncatedLen int, largestAcked int64) uint64 {
	expectedPN := uint64(largestAcked + 1)
	pnWin := uint64(1) << (uint(truncatedLen) * 8)
	pnHalf := pnWin / 2
	pnMask := pnWin - 1

	candidate := (expectedPN & ^pnMask) | truncated
	if candidate+pnHalf <= expectedPN && candidate < (1<<62)-pnWin {
		return candidate + pnWin
	}
	if candidate > expectedPN+pnHalf && candidate >= pnWin {
		return candidate - pnWin
	}
	return candidate
}

func quicEncodePacketNumber(pn uint64, largestAcked int64) (truncated uint64, length int) {
	numUnacked := pn - uint64(largestAcked)
	if numUnacked < 0x80 {
		return pn & 0xff, 1
	}
	if numUnacked < 0x8000 {
		return pn & 0xffff, 2
	}
	if numUnacked < 0x800000 {
		return pn & 0xffffff, 3
	}
	return pn & 0xffffffff, 4
}
