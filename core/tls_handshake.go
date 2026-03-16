package core

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"
)

func TLSExtract(h func() hash.Hash, salt, ikm []byte) []byte {
	mac := hmac.New(h, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
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
	bp := MediumBufPool.Get().(*[]byte)
	b := (*bp)[:0]

	b = append(b, 0x03, 0x03)
	b = append(b, random...)
	b = append(b, byte(len(sessionID)))
	b = append(b, sessionID...)
	b = append(b, byte(suiteID>>8), byte(suiteID))
	b = append(b, 0x00)

	var exts []byte
	exts = append(exts, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)

	ksEntry := make([]byte, 4+len(pubKey))
	ksEntry[0] = 0x00
	ksEntry[1] = 0x1d
	ksEntry[2] = 0x00
	ksEntry[3] = 0x20
	copy(ksEntry[4:], pubKey)
	exts = append(exts, 0x00, 0x33)
	exts = append(exts, byte(len(ksEntry)>>8), byte(len(ksEntry)))
	exts = append(exts, ksEntry...)

	b = append(b, byte(len(exts)>>8), byte(len(exts)))
	b = append(b, exts...)

	result := HSWrap(0x02, b)
	*bp = b[:0]
	MediumBufPool.Put(bp)
	return result
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

func BuildCertificateVerify(sig []byte) []byte {
	body := make([]byte, 4+len(sig))
	body[0] = 0x04
	body[1] = 0x03
	sigLen := uint16(len(sig))
	body[2] = byte(sigLen >> 8)
	body[3] = byte(sigLen)
	copy(body[4:], sig)
	return HSWrap(0x0f, body)
}

func BuildFinished(verifyData []byte) []byte {
	return HSWrap(0x14, verifyData)
}

var cvPrefix = func() [64]byte {
	var p [64]byte
	for i := range p {
		p[i] = 0x20
	}
	return p
}()

var cvContext = []byte("TLS 1.3, server CertificateVerify")

func SignCertificateVerify(priv *ecdsa.PrivateKey, transcriptHash []byte) ([]byte, error) {
	content := make([]byte, 64+len(cvContext)+1+len(transcriptHash))
	copy(content, cvPrefix[:])
	copy(content[64:], cvContext)
	content[64+len(cvContext)] = 0x00
	copy(content[64+len(cvContext)+1:], transcriptHash)

	digest := sha256.Sum256(content)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}
	if !ecdsa.VerifyASN1(&priv.PublicKey, digest[:], sig) {
		return nil, ErrSigVerifyFailed
	}
	return sig, nil
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
}

func (ch *ParsedClientHello) SupportsTLS13() bool {
	for _, v := range ch.SupportedVersions {
		if v == 0x0304 {
			return true
		}
	}
	return false
}

func ParseClientHello(data []byte) (*ParsedClientHello, error) {
	if len(data) < 6 || data[0] != 0x01 {
		return nil, ErrNotClientHello
	}
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+msgLen {
		return nil, ErrTruncated
	}
	ch := data[4 : 4+msgLen]
	if len(ch) < 35 {
		return nil, ErrBodyTooShort
	}

	result := &ParsedClientHello{}
	pos := 34

	if pos >= len(ch) {
		return nil, ErrNoSessionID
	}
	sidLen := int(ch[pos])
	pos++
	if pos+sidLen > len(ch) {
		return nil, ErrSessionIDTruncated
	}
	result.SessionID = make([]byte, sidLen)
	copy(result.SessionID, ch[pos:pos+sidLen])
	pos += sidLen

	if pos+2 > len(ch) {
		return nil, ErrNoCipherSuites
	}
	csLen := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2
	if pos+csLen > len(ch) || csLen%2 != 0 {
		return nil, ErrBadCSLen
	}
	result.CipherSuites = make([]uint16, 0, csLen/2)
	for i := 0; i < csLen; i += 2 {
		result.CipherSuites = append(result.CipherSuites, uint16(ch[pos+i])<<8|uint16(ch[pos+i+1]))
	}
	pos += csLen

	if pos >= len(ch) {
		return nil, ErrNoCompression
	}
	compLen := int(ch[pos])
	pos += 1 + compLen

	if pos+2 > len(ch) {
		return nil, ErrNoExtensions
	}
	extTotalLen := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2
	if pos+extTotalLen > len(ch) {
		return nil, ErrExtsTruncated
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
			result.ALPNProtos = parseALPN(extData)
		case 0x002b:
			result.SupportedVersions = parseSupportedVersions(extData)
		case 0x0033:
			result.X25519PubKey = findX25519KeyShare(extData)
		}
		i += extLen
	}

	return result, nil
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

func parseSupportedVersions(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	if listLen%2 != 0 || len(data) < 1+listLen {
		return nil
	}
	versions := make([]uint16, 0, listLen/2)
	for i := 1; i < 1+listLen; i += 2 {
		versions = append(versions, uint16(data[i])<<8|uint16(data[i+1]))
	}
	return versions
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return nil
	}
	list := data[2 : 2+listLen]
	protos := make([]string, 0, 4)
	for i := 0; i < len(list); {
		pLen := int(list[i])
		i++
		if i+pLen > len(list) {
			break
		}
		protos = append(protos, string(list[i:i+pLen]))
		i += pLen
	}
	return protos
}

func findX25519KeyShare(data []byte) []byte {
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
			pub := make([]byte, 32)
			copy(pub, entries[j+4:j+4+32])
			return pub
		}
		j += 4 + kLen
	}
	return nil
}

func NegotiateALPN(clientProtos []string) string {
	for _, p := range clientProtos {
		if p == "h2" {
			return "h2"
		}
	}
	for _, p := range clientProtos {
		if p == "http/1.1" {
			return "http/1.1"
		}
	}
	return ""
}
