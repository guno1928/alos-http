package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"hash"
)

func TLSExtract(h func() hash.Hash, salt, ikm []byte) []byte {
	return TLSExtractTo(h, salt, ikm, nil)
}

var hkdfExpandOneByte = [1]byte{0x01}

func TLSExpandLabel(h func() hash.Hash, secret []byte, label string, ctx []byte, length int) []byte {
	const prefix = "tls13 "
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

func TLSDeriveSecret(h func() hash.Hash, hashLen int, secret []byte, label string, transcriptHash []byte) []byte {
	return TLSExpandLabel(h, secret, label, transcriptHash, hashLen)
}

func EmptyTranscriptHash(h func() hash.Hash) []byte {
	d := h()
	return d.Sum(nil)
}

func HSWrap(msgType byte, body []byte) []byte {
	out := make([]byte, 4+len(body))
	out[0] = msgType
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	copy(out[4:], body)
	return out
}

func BuildServerHello(random, sessionID []byte, suiteID uint16, pubKey []byte) []byte {
	const versionExtLen = 6
	const keyShareEntryHeaderLen = 4

	sidLen := len(sessionID)
	pubLen := len(pubKey)
	keyShareExtDataLen := keyShareEntryHeaderLen + pubLen
	keyShareExtLen := 4 + keyShareExtDataLen
	extsLen := versionExtLen + keyShareExtLen
	bodyLen := 40 + sidLen + extsLen

	out := make([]byte, 4+bodyLen)
	out[0] = 0x02
	out[1] = byte(bodyLen >> 16)
	out[2] = byte(bodyLen >> 8)
	out[3] = byte(bodyLen)

	off := 4
	out[off] = 0x03
	out[off+1] = 0x03
	off += 2
	copy(out[off:], random)
	off += len(random)
	out[off] = byte(sidLen)
	off++
	copy(out[off:], sessionID)
	off += sidLen
	out[off] = byte(suiteID >> 8)
	out[off+1] = byte(suiteID)
	out[off+2] = 0x00
	off += 3

	out[off] = byte(extsLen >> 8)
	out[off+1] = byte(extsLen)
	off += 2

	out[off] = 0x00
	out[off+1] = 0x2b
	out[off+2] = 0x00
	out[off+3] = 0x02
	out[off+4] = 0x03
	out[off+5] = 0x04
	off += versionExtLen

	out[off] = 0x00
	out[off+1] = 0x33
	out[off+2] = byte(keyShareExtDataLen >> 8)
	out[off+3] = byte(keyShareExtDataLen)
	out[off+4] = 0x00
	out[off+5] = 0x1d
	out[off+6] = byte(pubLen >> 8)
	out[off+7] = byte(pubLen)
	off += 8
	copy(out[off:], pubKey)
	return out
}

func BuildALPNExtension(proto string) []byte {
	protoLen := len(proto)
	listLen := 1 + protoLen
	extLen := 2 + listLen
	out := make([]byte, 4+extLen)
	out[0] = 0x00
	out[1] = 0x10
	out[2] = byte(extLen >> 8)
	out[3] = byte(extLen)
	out[4] = byte(listLen >> 8)
	out[5] = byte(listLen)
	out[6] = byte(protoLen)
	copy(out[7:], proto)
	return out
}

func BuildEncryptedExtensions(alpn string) []byte {
	if alpn == "" {
		return HSWrap(0x08, []byte{0x00, 0x00})
	}
	alpnExt := BuildALPNExtension(alpn)
	body := make([]byte, 2+len(alpnExt))
	alpnLen := uint16(len(alpnExt))
	body[0] = byte(alpnLen >> 8)
	body[1] = byte(alpnLen)
	copy(body[2:], alpnExt)
	return HSWrap(0x08, body)
}

func BuildCertificate(chain [][]byte) []byte {
	var entriesLen int
	for _, certDER := range chain {
		entriesLen += 3 + len(certDER) + 2
	}
	bodyLen := 1 + 3 + entriesLen
	out := make([]byte, 4+bodyLen)
	out[0] = 0x0b
	out[1] = byte(bodyLen >> 16)
	out[2] = byte(bodyLen >> 8)
	out[3] = byte(bodyLen)
	out[4] = 0x00
	out[5] = byte(entriesLen >> 16)
	out[6] = byte(entriesLen >> 8)
	out[7] = byte(entriesLen)
	off := 8
	for _, certDER := range chain {
		out[off] = byte(len(certDER) >> 16)
		out[off+1] = byte(len(certDER) >> 8)
		out[off+2] = byte(len(certDER))
		copy(out[off+3:], certDER)
		off += 3 + len(certDER)
		out[off] = 0x00
		out[off+1] = 0x00
		off += 2
	}
	return out
}

func BuildCertificateVerify(scheme uint16, sig []byte) []byte {
	return appendCertificateVerify(nil, scheme, sig)
}

func BuildFinished(verifyData []byte) []byte {
	return appendFinished(nil, verifyData)
}

func appendCertificateVerify(dst []byte, scheme uint16, sig []byte) []byte {
	sigLen := len(sig)
	bodyLen := 4 + sigLen
	dst = append(dst, 0x0f, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))
	dst = append(dst, byte(scheme>>8), byte(scheme), byte(sigLen>>8), byte(sigLen))
	return append(dst, sig...)
}

func appendFinished(dst, verifyData []byte) []byte {
	bodyLen := len(verifyData)
	dst = append(dst, 0x14, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))
	return append(dst, verifyData...)
}

var cvPrefix = func() [64]byte {
	var p [64]byte
	for i := range p {
		p[i] = 0x20
	}
	return p
}()

var cvContext = []byte("TLS 1.3, server CertificateVerify")

func SignCertificateVerify(signer crypto.Signer, transcriptHash []byte) (uint16, []byte, error) {
	content := make([]byte, 64+len(cvContext)+1+len(transcriptHash))
	copy(content, cvPrefix[:])
	copy(content[64:], cvContext)
	content[64+len(cvContext)] = 0x00
	copy(content[64+len(cvContext)+1:], transcriptHash)

	digest := sha256.Sum256(content)
	switch k := signer.(type) {
	case *ecdsa.PrivateKey:
		sig, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
		if err != nil {
			return 0, nil, err
		}
		return 0x0403, sig, nil
	case *rsa.PrivateKey:
		sig, err := rsa.SignPSS(rand.Reader, k, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		if err != nil {
			return 0, nil, err
		}
		return 0x0804, sig, nil
	default:
		return 0, nil, errors.New("unsupported certificate key type")
	}
}

func ComputeFinished(h func() hash.Hash, hashLen int, baseSecret, transcriptHash []byte) []byte {
	finishedKey := TLSExpandLabel(h, baseSecret, "finished", nil, hashLen)
	mac := hmac.New(h, finishedKey)
	mac.Write(transcriptHash)
	return mac.Sum(nil)
}

type ParsedClientHello struct {
	SessionID         []byte
	CipherSuites      []uint16
	X25519PubKey      []byte
	ALPNProtos        []string
	ServerName        string
	SupportedVersions []uint16
	SupportedGroups   []uint16
	SignatureSchemes  []uint16
	Random            [32]byte
	MaxUDPPayload     uint64
	InitialMaxData    uint64
	InitialMaxStreamDataBidiLocal uint64

	hasUncompressedPoint bool

	sessionIDBuf          [32]byte
	x25519PubKeyBuf       [32]byte
	cipherSuitesSmall     [64]uint16
	supportedVersSmall    [8]uint16
	alpnProtosSmall       [4]string
	cipherSuitesOverflow  []uint16
	supportedVersOverflow []uint16
	alpnProtosOverflow    []string
}

func (ch *ParsedClientHello) SupportsTLS13() bool {
	for _, v := range ch.SupportedVersions {
		if v == 0x0304 {
			return true
		}
	}
	return false
}

func (ch *ParsedClientHello) Reset() {
	ch.SessionID = nil
	ch.CipherSuites = nil
	ch.X25519PubKey = nil
	ch.ALPNProtos = nil
	ch.ServerName = ""
	ch.SupportedVersions = nil
	ch.SupportedGroups = nil
	ch.SignatureSchemes = nil
	ch.MaxUDPPayload = 0
	ch.InitialMaxData = 0
	ch.InitialMaxStreamDataBidiLocal = 0
	ch.hasUncompressedPoint = false
	ch.cipherSuitesOverflow = nil
	ch.supportedVersOverflow = nil
	ch.alpnProtosOverflow = nil
}

func (ch *ParsedClientHello) cipherSuitesDst(count int) []uint16 {
	if count <= len(ch.cipherSuitesSmall) {
		return ch.cipherSuitesSmall[:count]
	}
	if cap(ch.cipherSuitesOverflow) < count {
		ch.cipherSuitesOverflow = make([]uint16, count)
	}
	return ch.cipherSuitesOverflow[:count]
}

func (ch *ParsedClientHello) supportedVersionsDst(count int) []uint16 {
	if count <= len(ch.supportedVersSmall) {
		return ch.supportedVersSmall[:count]
	}
	if cap(ch.supportedVersOverflow) < count {
		ch.supportedVersOverflow = make([]uint16, count)
	}
	return ch.supportedVersOverflow[:count]
}

func (ch *ParsedClientHello) alpnDst(count int) []string {
	if count <= len(ch.alpnProtosSmall) {
		return ch.alpnProtosSmall[:count]
	}
	if cap(ch.alpnProtosOverflow) < count {
		ch.alpnProtosOverflow = make([]string, count)
	}
	return ch.alpnProtosOverflow[:count]
}

func ParseClientHello(data []byte, result *ParsedClientHello) error {
	if len(data) < 6 || data[0] != 0x01 {
		return ErrNotClientHello
	}
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+msgLen {
		return ErrTruncated
	}
	ch := data[4 : 4+msgLen]
	if len(ch) < 35 {
		return ErrBodyTooShort
	}

	result.Reset()
	copy(result.Random[:], ch[2:34])
	pos := 34

	if pos >= len(ch) {
		return ErrNoSessionID
	}
	sidLen := int(ch[pos])
	pos++
	if pos+sidLen > len(ch) {
		return ErrSessionIDTruncated
	}
	copy(result.sessionIDBuf[:], ch[pos:pos+sidLen])
	result.SessionID = result.sessionIDBuf[:sidLen]
	pos += sidLen

	if pos+2 > len(ch) {
		return ErrNoCipherSuites
	}
	csLen := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2
	if pos+csLen > len(ch) || csLen%2 != 0 {
		return ErrBadCSLen
	}
	suites := result.cipherSuitesDst(csLen / 2)
	for i, j := 0, 0; i < csLen; i, j = i+2, j+1 {
		suites[j] = uint16(ch[pos+i])<<8 | uint16(ch[pos+i+1])
	}
	result.CipherSuites = suites
	pos += csLen

	if pos >= len(ch) {
		return ErrNoCompression
	}
	compLen := int(ch[pos])
	pos += 1 + compLen

	if pos+2 > len(ch) {
		return ErrNoExtensions
	}
	extTotalLen := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2
	if pos+extTotalLen > len(ch) {
		return ErrExtsTruncated
	}
	exts := ch[pos : pos+extTotalLen]

	for i := 0; i < len(exts); {
		if i+4 > len(exts) {
			break
		}
		extType := uint16(exts[i])<<8 | uint16(exts[i+1])
		extLen := int(exts[i+2])<<8 | int(exts[i+3])
		i += 4
		if i+extLen > len(exts) {
			break
		}
		extData := exts[i : i+extLen]

		switch extType {
		case 0x0000:
			result.ServerName = parseSNI(extData)
		case 0x0010:
			result.ALPNProtos = parseALPN(result, extData)
		case 0x002b:
			result.SupportedVersions = parseSupportedVersions(result, extData)
		case 0x0033:
			result.X25519PubKey = findX25519KeyShare(result, extData)
		case 0x000a:
			result.SupportedGroups = parseU16List(extData)
		case 0x000d:
			result.SignatureSchemes = parseU16List(extData)
		case 0x000b:
			if len(extData) > 1 {
				for _, f := range extData[1:] {
					if f == 0x00 {
						result.hasUncompressedPoint = true
					}
				}
			}
		case 0x0039:
			parseQUICTransportParams(result, extData)
		}
		i += extLen
	}

	return nil
}

func parseQUICTransportParams(result *ParsedClientHello, data []byte) {
	for pos := 0; pos < len(data); {
		id, n := quicParseVarint(data[pos:])
		if n == 0 {
			return
		}
		pos += n
		plen, n2 := quicParseVarint(data[pos:])
		if n2 == 0 {
			return
		}
		pos += n2
		if pos+int(plen) > len(data) {
			return
		}
		switch id {
		case 0x03, 0x04, 0x05:
			v, n3 := quicParseVarint(data[pos:])
			if n3 == 0 {
				return
			}
			switch id {
			case 0x03:
				result.MaxUDPPayload = v
			case 0x04:
				result.InitialMaxData = v
			case 0x05:
				result.InitialMaxStreamDataBidiLocal = v
			}
		}
		pos += int(plen)
	}
}

func parseU16List(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	n := int(data[0])<<8 | int(data[1])
	if 2+n > len(data) || n%2 != 0 {
		return nil
	}
	out := make([]uint16, 0, n/2)
	for i := 2; i+1 < 2+n; i += 2 {
		out = append(out, uint16(data[i])<<8|uint16(data[i+1]))
	}
	return out
}

func parseSNI(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return ""
	}
	list := data[2 : 2+listLen]
	for i := 0; i < len(list); {
		if i+3 > len(list) {
			break
		}
		nameType := list[i]
		nameLen := int(list[i+1])<<8 | int(list[i+2])
		i += 3
		if i+nameLen > len(list) {
			break
		}
		if nameType == 0x00 {
			return string(list[i : i+nameLen])
		}
		i += nameLen
	}
	return ""
}

func parseSupportedVersions(ch *ParsedClientHello, data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	if listLen%2 != 0 || len(data) < 1+listLen {
		return nil
	}
	versions := ch.supportedVersionsDst(listLen / 2)
	for i, j := 1, 0; i < 1+listLen; i, j = i+2, j+1 {
		versions[j] = uint16(data[i])<<8 | uint16(data[i+1])
	}
	return versions
}

func parseALPN(ch *ParsedClientHello, data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return nil
	}
	list := data[2 : 2+listLen]
	count := 0
	for i := 0; i < len(list); {
		if i >= len(list) {
			break
		}
		pLen := int(list[i])
		i++
		if i+pLen > len(list) {
			break
		}
		count++
		i += pLen
	}
	if count == 0 {
		return nil
	}
	protos := ch.alpnDst(count)
	for i, j := 0, 0; i < len(list) && j < count; j++ {
		pLen := int(list[i])
		i++
		protos[j] = string(list[i : i+pLen])
		i += pLen
	}
	return protos
}

func findX25519KeyShare(ch *ParsedClientHello, data []byte) []byte {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return nil
	}
	entries := data[2 : 2+listLen]
	for j := 0; j < len(entries); {
		if j+4 > len(entries) {
			break
		}
		group := uint16(entries[j])<<8 | uint16(entries[j+1])
		kLen := int(entries[j+2])<<8 | int(entries[j+3])
		if j+4+kLen > len(entries) {
			break
		}
		if group == 0x001d && kLen == 32 {
			copy(ch.x25519PubKeyBuf[:], entries[j+4:j+4+32])
			return ch.x25519PubKeyBuf[:]
		}
		j += 4 + kLen
	}
	return nil
}

func NegotiateALPN(clientProtos []string, allowH2 bool) string {
	if allowH2 {
		for _, p := range clientProtos {
			if p == "h2" {
				return "h2"
			}
		}
	}
	for _, p := range clientProtos {
		if p == "http/1.1" {
			return "http/1.1"
		}
	}
	return ""
}
