//go:build linux && amd64

package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

// TLSExtract performs the TLS 1.3 HKDF-Extract step (HMAC(salt, ikm)) and returns a newly allocated result.
func TLSExtract(h func() hash.Hash, salt, ikm []byte) []byte {
	return TLSExtractTo(h, salt, ikm, nil)
}

var hkdfExpandOneByte = [1]byte{0x01}

// TLSExpandLabel performs the TLS 1.3 HKDF-Expand-Label step, deriving length bytes
// from secret using label and ctx, and returns a newly allocated result.
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

// TLSDeriveSecret derives a TLS 1.3 secret of hashLen bytes from secret using label
// and transcriptHash as the HKDF-Expand-Label context.
func TLSDeriveSecret(h func() hash.Hash, hashLen int, secret []byte, label string, transcriptHash []byte) []byte {
	return TLSExpandLabel(h, secret, label, transcriptHash, hashLen)
}

// EmptyTranscriptHash returns the hash of an empty input using h, as used for the
// TLS 1.3 transcript hash before any handshake messages have been processed.
func EmptyTranscriptHash(h func() hash.Hash) []byte {
	d := h()
	return d.Sum(nil)
}

// HSWrap wraps body in a TLS handshake message header (1-byte type, 3-byte length)
// of the given msgType and returns the framed message.
func HSWrap(msgType byte, body []byte) []byte {
	out := make([]byte, 4+len(body))
	out[0] = msgType
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	copy(out[4:], body)
	return out
}

// BuildServerHello constructs a framed TLS 1.3 ServerHello handshake message
// carrying random, sessionID, the negotiated suiteID, and pubKey in a
// supported_versions and key_share extension for group.
func BuildServerHello(random, sessionID []byte, suiteID, group uint16, pubKey []byte) []byte {
	return buildServerHelloMessage(serverHelloSpec{random: random, sessionID: sessionID, suite: suiteID, group: group, share: pubKey})
}

func buildHelloRetryRequest(sessionID []byte, suiteID uint16, group tlsGroup) []byte {
	return buildServerHelloMessage(serverHelloSpec{random: helloRetryRequestRandom[:], sessionID: sessionID, suite: suiteID, group: uint16(group), retry: true})
}

type serverHelloSpec struct {
	random    []byte
	sessionID []byte
	suite     uint16
	group     uint16
	share     []byte
	retry     bool
	psk       bool
}

func buildServerHelloMessage(spec serverHelloSpec) []byte {
	const versionExtLen = 6
	const extHeaderLen = 4
	const groupLen = 2
	const shareLenLen = 2
	const pskExtLen = extHeaderLen + 2

	sidLen := len(spec.sessionID)
	keyShareExtDataLen := groupLen
	if !spec.retry {
		keyShareExtDataLen += shareLenLen + len(spec.share)
	}
	extsLen := versionExtLen + extHeaderLen + keyShareExtDataLen
	if spec.psk {
		extsLen += pskExtLen
	}
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
	copy(out[off:], spec.random)
	off += len(spec.random)
	out[off] = byte(sidLen)
	off++
	copy(out[off:], spec.sessionID)
	off += sidLen
	out[off] = byte(spec.suite >> 8)
	out[off+1] = byte(spec.suite)
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
	out[off+4] = byte(spec.group >> 8)
	out[off+5] = byte(spec.group)
	off += extHeaderLen + groupLen
	if !spec.retry {
		out[off] = byte(len(spec.share) >> 8)
		out[off+1] = byte(len(spec.share))
		copy(out[off+shareLenLen:], spec.share)
		off += shareLenLen + len(spec.share)
	}
	if spec.psk {
		out[off] = byte(tlsExtPreSharedKey >> 8)
		out[off+1] = byte(tlsExtPreSharedKey & 0xff)
		out[off+2] = 0x00
		out[off+3] = 0x02
		out[off+4] = byte(pskSelectedIdentityFirst >> 8)
		out[off+5] = byte(pskSelectedIdentityFirst)
	}
	return out
}

// BuildALPNExtension constructs a TLS ALPN extension (type 0x0010) advertising the single protocol proto.
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

// BuildEncryptedExtensions constructs a framed TLS 1.3 EncryptedExtensions handshake
// message, including an ALPN extension for alpn when it is non-empty.
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

// BuildCertificate constructs a framed TLS 1.3 Certificate handshake message from
// chain, a list of DER-encoded certificates, with an empty extensions block for each entry.
func BuildCertificate(chain [][]byte) []byte {
	return buildCertificate13(chain, nil)
}

func buildCertificate13(chain [][]byte, leafStatus []byte) []byte {
	leafExtLen := 0
	if len(leafStatus) > 0 {
		leafExtLen = 4 + len(leafStatus)
	}
	entriesLen := 0
	for _, certDER := range chain {
		entriesLen += 3 + len(certDER) + 2
	}
	if len(chain) > 0 {
		entriesLen += leafExtLen
	}
	bodyLen := 1 + 3 + entriesLen
	out := make([]byte, 0, 4+bodyLen)
	out = append(out, tlsHSCertificate, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))
	out = append(out, 0x00, byte(entriesLen>>16), byte(entriesLen>>8), byte(entriesLen))
	for i, certDER := range chain {
		out = append(out, byte(len(certDER)>>16), byte(len(certDER)>>8), byte(len(certDER)))
		out = append(out, certDER...)
		if i > 0 || leafExtLen == 0 {
			out = append(out, 0x00, 0x00)
			continue
		}
		out = append(out, byte(leafExtLen>>8), byte(leafExtLen))
		out = append(out, byte(tlsExtStatusRequest>>8), byte(tlsExtStatusRequest), byte(len(leafStatus)>>8), byte(len(leafStatus)))
		out = append(out, leafStatus...)
	}
	return out
}

// BuildCertificateVerify constructs a framed TLS 1.3 CertificateVerify handshake
// message carrying the given signature scheme and signature.
func BuildCertificateVerify(scheme uint16, sig []byte) []byte {
	return appendCertificateVerify(nil, scheme, sig)
}

// BuildFinished constructs a framed TLS Finished handshake message carrying verifyData.
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

const cvContextText = "TLS 1.3, server CertificateVerify"

var cvContext = []byte(cvContextText)

const (
	sigECDSAP256SHA256 uint16 = 0x0403
	sigECDSAP384SHA384 uint16 = 0x0503
	sigECDSAP521SHA512 uint16 = 0x0603
	sigRSAPSSSHA256    uint16 = 0x0804
	sigRSAPSSSHA384    uint16 = 0x0805
	sigRSAPSSSHA512    uint16 = 0x0806
	sigEd25519         uint16 = 0x0807
)

var errUnsupportedSignatureKey = errors.New("unsupported certificate key type")
var errNoCommonSignatureScheme = errors.New("client offers no signature scheme usable with the certificate key")

func schemeOffered(offered []uint16, scheme uint16) bool {
	if offered == nil {
		return true
	}
	for _, s := range offered {
		if s == scheme {
			return true
		}
	}
	return false
}

const certificateVerifyContentMax = len(cvPrefix) + len(cvContextText) + 1 + sha512.Size

func certificateVerifyContent(transcriptHash []byte) []byte {
	return certificateVerifyContentInto(make([]byte, 64+len(cvContext)+1+len(transcriptHash)), transcriptHash)
}

func certificateVerifyContentInto(content, transcriptHash []byte) []byte {
	content = content[:64+len(cvContext)+1+len(transcriptHash)]
	copy(content, cvPrefix[:])
	copy(content[64:], cvContext)
	content[64+len(cvContext)] = 0x00
	copy(content[64+len(cvContext)+1:], transcriptHash)
	return content
}

func ecdsaScheme(k *ecdsa.PrivateKey) (uint16, crypto.Hash, bool) {
	switch k.Curve {
	case elliptic.P256():
		return sigECDSAP256SHA256, crypto.SHA256, true
	case elliptic.P384():
		return sigECDSAP384SHA384, crypto.SHA384, true
	case elliptic.P521():
		return sigECDSAP521SHA512, crypto.SHA512, true
	}
	return 0, 0, false
}

var rsaPSSSchemes = [...]struct {
	scheme uint16
	hash   crypto.Hash
}{
	{sigRSAPSSSHA256, crypto.SHA256},
	{sigRSAPSSSHA384, crypto.SHA384},
	{sigRSAPSSSHA512, crypto.SHA512},
}

// SignCertificateVerify signs transcriptHash for a TLS 1.3 server CertificateVerify
// message using signer. The signature scheme is dictated by the key: ECDSA keys sign
// with the hash their curve mandates (P-256/SHA-256, P-384/SHA-384, P-521/SHA-512),
// Ed25519 keys use ed25519, and RSA keys use RSA-PSS with the strongest hash the
// client offered. offered is the client's signature_algorithms list; nil accepts any
// scheme. It returns the scheme and signature, or an error when the key type is
// unsupported or the client offers no scheme the key can produce.
func SignCertificateVerify(signer crypto.Signer, transcriptHash []byte, offered []uint16) (uint16, []byte, error) {
	if len(transcriptHash) > sha512.Size {
		return signTLS13(signer, certificateVerifyContent(transcriptHash), offered)
	}
	var buf [certificateVerifyContentMax]byte
	return signTLS13(signer, certificateVerifyContentInto(buf[:], transcriptHash), offered)
}

func signTLS13(signer crypto.Signer, content []byte, offered []uint16) (uint16, []byte, error) {
	switch k := signer.(type) {
	case *ecdsa.PrivateKey:
		scheme, h, ok := ecdsaScheme(k)
		if !ok {
			return 0, nil, errUnsupportedSignatureKey
		}
		if !schemeOffered(offered, scheme) {
			return 0, nil, errNoCommonSignatureScheme
		}
		digest := hashSum(h, content)
		sig, err := ecdsa.SignASN1(rand.Reader, k, digest)
		if err != nil {
			return 0, nil, err
		}
		return scheme, sig, nil
	case ed25519.PrivateKey:
		if !schemeOffered(offered, sigEd25519) {
			return 0, nil, errNoCommonSignatureScheme
		}
		return sigEd25519, ed25519.Sign(k, content), nil
	case *rsa.PrivateKey:
		for _, cand := range rsaPSSSchemes {
			if !schemeOffered(offered, cand.scheme) {
				continue
			}
			digest := hashSum(cand.hash, content)
			sig, err := rsa.SignPSS(rand.Reader, k, cand.hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: cand.hash})
			if err != nil {
				return 0, nil, err
			}
			return cand.scheme, sig, nil
		}
		return 0, nil, errNoCommonSignatureScheme
	default:
		return 0, nil, errUnsupportedSignatureKey
	}
}

func hashSum(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA256:
		sum := sha256.Sum256(data)
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(data)
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(data)
		return sum[:]
	}
	hh := h.New()
	hh.Write(data)
	return hh.Sum(nil)
}

// ComputeFinished computes a TLS 1.3 Finished message MAC over transcriptHash,
// deriving the finished key from baseSecret via TLSExpandLabel.
func ComputeFinished(h func() hash.Hash, hashLen int, baseSecret, transcriptHash []byte) []byte {
	finishedKey := TLSExpandLabel(h, baseSecret, "finished", nil, hashLen)
	mac := hmac.New(h, finishedKey)
	mac.Write(transcriptHash)
	return mac.Sum(nil)
}

// ParsedClientHello holds the fields extracted from a parsed TLS ClientHello by
// ParseClientHello. Reuse an instance across parses via Reset to avoid reallocating
// its internal scratch buffers.
type ParsedClientHello struct {
	SessionID                     []byte
	CipherSuites                  []uint16
	X25519PubKey                  []byte
	ALPNProtos                    []string
	ServerName                    string
	SupportedVersions             []uint16
	SupportedGroups               []uint16
	SignatureSchemes              []uint16
	Random                        [32]byte
	LegacyVersion                 uint16
	MaxUDPPayload                 uint64
	InitialMaxData                uint64
	InitialMaxStreamDataBidiLocal uint64
	InitialMaxStreamDataUni       uint64
	ActiveConnIDLimit             uint64
	quicTP                        quicPeerTransportParams

	hasUncompressedPoint bool
	extendedMasterSecret bool
	secureRenegotiation  bool
	renegotiatedConn     bool
	fallbackSCSV         bool
	pskDHE               bool
	pskNotLast           bool
	pskIdentities        int
	pskBinders           int
	pskBindersOffset     int
	pskIdentity          []byte
	pskBinder            []byte
	sessionTicketOffered bool
	sessionTicket        []byte
	statusRequest        bool
	keyShareCount        int
	x25519Share          []byte
	p256Share            []byte
	mlkemShare           []byte

	sessionIDBuf          [32]byte
	x25519PubKeyBuf       [32]byte
	cipherSuitesSmall     [64]uint16
	supportedVersSmall    [8]uint16
	alpnProtosSmall       [4]string
	groupsSmall           [16]uint16
	sigSchemesSmall       [32]uint16
	cipherSuitesOverflow  []uint16
	supportedVersOverflow []uint16
	alpnProtosOverflow    []string
	groupsOverflow        []uint16
	sigSchemesOverflow    []uint16
	lastServerName        string
}

// SupportsTLS13 reports whether the client advertised TLS 1.3 (0x0304) in its supported_versions extension.
func (ch *ParsedClientHello) SupportsTLS13() bool {
	for _, v := range ch.SupportedVersions {
		if v == 0x0304 {
			return true
		}
	}
	return false
}

// Reset clears ch so it can be reused for parsing another ClientHello, without
// releasing its internal scratch buffers.
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
	ch.InitialMaxStreamDataUni = 0
	ch.ActiveConnIDLimit = 0
	ch.quicTP = quicPeerTransportParams{}
	ch.hasUncompressedPoint = false
	ch.extendedMasterSecret = false
	ch.secureRenegotiation = false
	ch.renegotiatedConn = false
	ch.fallbackSCSV = false
	ch.pskDHE = false
	ch.pskNotLast = false
	ch.pskIdentities = 0
	ch.pskBinders = 0
	ch.pskBindersOffset = 0
	ch.pskIdentity = nil
	ch.pskBinder = nil
	ch.sessionTicketOffered = false
	ch.statusRequest = false
	ch.sessionTicket = nil
	ch.keyShareCount = 0
	ch.x25519Share = nil
	ch.p256Share = nil
	ch.mlkemShare = nil
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

// ParseClientHello parses a TLS handshake ClientHello message from data into result,
// which is cleared first via result.Reset. It returns an error if the message is
// truncated, malformed, or not a ClientHello.
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
	result.LegacyVersion = uint16(ch[0])<<8 | uint16(ch[1])
	copy(result.Random[:], ch[2:34])
	pos := 34

	if pos >= len(ch) {
		return ErrNoSessionID
	}
	sidLen := int(ch[pos])
	pos++
	if sidLen > len(result.sessionIDBuf) {
		return ErrSessionIDTruncated
	}
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
		switch suites[j] {
		case tlsSCSVRenegotiation:
			result.secureRenegotiation = true
		case tlsSCSVFallback:
			result.fallbackSCSV = true
		}
	}
	result.CipherSuites = suites
	pos += csLen

	if pos >= len(ch) {
		return ErrNoCompression
	}
	compLen := int(ch[pos])
	if pos+1+compLen > len(ch) {
		return ErrNoCompression
	}
	compression := ch[pos+1 : pos+1+compLen]
	if indexByteFrom(compression, tlsCompressionNull, 0) < 0 {
		return ErrBadCompression
	}
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

	var seen extensionSet
	for i, extCount := 0, 0; i < len(exts); extCount++ {
		if i+4 > len(exts) {
			return ErrExtsTruncated
		}
		if extCount == maxClientHelloExtensions {
			return ErrTooManyExtensions
		}
		extType := uint16(exts[i])<<8 | uint16(exts[i+1])
		extLen := int(exts[i+2])<<8 | int(exts[i+3])
		i += 4
		if i+extLen > len(exts) {
			return ErrExtsTruncated
		}
		if seen.seenBefore(extType) {
			return ErrDuplicateExtension
		}
		extData := exts[i : i+extLen]

		switch extType {
		case 0x0000:
			result.ServerName = result.internServerName(parseSNI(extData))
		case 0x0010:
			protos, ok := parseALPN(result, extData)
			if !ok {
				return ErrBadALPN
			}
			result.ALPNProtos = protos
		case 0x002b:
			result.SupportedVersions = parseSupportedVersions(result, extData)
		case 0x0033:
			parseKeyShares(result, extData)
		case 0x000a:
			result.SupportedGroups = parseU16ListInto(extData, result.groupsSmall[:], &result.groupsOverflow)
		case 0x000d:
			result.SignatureSchemes = parseU16ListInto(extData, result.sigSchemesSmall[:], &result.sigSchemesOverflow)
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
		case tlsExtExtendedMasterSecret:
			result.extendedMasterSecret = true
		case tlsExtRenegotiationInfo:
			result.secureRenegotiation = true
			result.renegotiatedConn = len(extData) != 1 || extData[0] != 0
		case tlsExtSessionTicket:
			result.sessionTicketOffered = true
			result.sessionTicket = extData
		case tlsExtStatusRequest:
			result.statusRequest = len(extData) > 0 && extData[0] == ocspStatusTypeOCSP
		case tlsExtPSKModes:
			result.pskDHE = parsePSKModes(extData)
		case tlsExtPreSharedKey:
			result.pskNotLast = i+extLen != len(exts)
			parsePreSharedKey(result, extData, tlsHandshakeHeaderLen+pos+i)
		}
		i += extLen
	}
	if len(compression) != 1 && result.SupportsTLS13() {
		return ErrBadCompression
	}

	return nil
}

const (
	tlsCompressionNull       = 0
	maxClientHelloExtensions = 128
	maxALPNProtocols         = 32
	extensionSetLowTypes     = 128
	extensionSetWordBits     = 64
)

var (
	ErrDuplicateExtension = &staticError{"duplicate extension"}
	ErrTooManyExtensions  = &staticError{"too many extensions"}
	ErrBadCompression     = &staticError{"compression methods must be exactly null"}
	ErrBadALPN            = &staticError{"malformed application_layer_protocol_negotiation"}
)

type extensionSet struct {
	low   [extensionSetLowTypes / extensionSetWordBits]uint64
	high  [maxClientHelloExtensions]uint16
	nHigh int
}

func (s *extensionSet) seenBefore(extType uint16) bool {
	if extType >= extensionSetLowTypes {
		return s.seenHighBefore(extType)
	}
	word, bit := &s.low[extType/extensionSetWordBits], uint64(1)<<(extType%extensionSetWordBits)
	dup := *word&bit != 0
	*word |= bit
	return dup
}

func (s *extensionSet) seenHighBefore(extType uint16) bool {
	for _, t := range s.high[:s.nHigh] {
		if t == extType {
			return true
		}
	}
	s.high[s.nHigh] = extType
	s.nHigh++
	return false
}

func clientHelloParseAlert(err error) tlsAlert {
	if err == ErrDuplicateExtension || err == ErrBadCompression {
		return alertIllegalParameter
	}
	return alertDecodeError
}

func parseQUICTransportParams(result *ParsedClientHello, data []byte) {
	tp := &result.quicTP
	tp.seen = true
	tp.ackDelayExponent = quicDefaultAckDelayExponent
	tp.maxAckDelayMs = quicDefaultMaxAckDelayMs
	var seenIDs uint64
	for pos := 0; pos < len(data); {
		id, n := quicParseVarint(data[pos:])
		if n == 0 {
			tp.invalid = true
			return
		}
		pos += n
		plen, n2 := quicParseVarint(data[pos:])
		if n2 == 0 || plen > uint64(len(data)-pos-n2) {
			tp.invalid = true
			return
		}
		pos += n2
		value := data[pos : pos+int(plen)]
		pos += int(plen)
		if id < quicTPTrackedIDs {
			if seenIDs&(1<<id) != 0 {
				tp.invalid = true
				return
			}
			seenIDs |= 1 << id
		}
		if !applyQUICTransportParam(result, id, value) {
			tp.invalid = true
			return
		}
	}
}

func applyQUICTransportParam(result *ParsedClientHello, id uint64, value []byte) bool {
	switch id {
	case quicTPOrigDstCID, quicTPStatelessResetToken, quicTPPreferredAddress, quicTPRetrySrcCID:
		return false
	case quicTPInitialSrcCID:
		result.quicTP.initialSrcCID = value
		result.quicTP.hasInitialSrcCID = true
		return len(value) <= quicMaxCIDLen
	case quicTPDisableActiveMigration:
		return len(value) == 0
	}
	if !quicTPIsInteger(id) {
		return true
	}
	v, n := quicParseVarint(value)
	if n == 0 || n != len(value) {
		return false
	}
	switch id {
	case quicTPMaxUDPPayloadSize:
		result.MaxUDPPayload = v
		return v >= quicMinUDPPayloadSize
	case quicTPInitialMaxData:
		result.InitialMaxData = v
	case quicTPInitialMaxStreamBidiL:
		result.InitialMaxStreamDataBidiLocal = v
	case quicTPInitialMaxStreamUni:
		result.InitialMaxStreamDataUni = v
	case quicTPActiveConnIDLimit:
		result.ActiveConnIDLimit = v
		return v >= quicMinActiveConnIDLimit
	case quicTPAckDelayExponent:
		result.quicTP.ackDelayExponent = v
		return v <= quicMaxAckDelayExponent
	case quicTPMaxAckDelay:
		result.quicTP.maxAckDelayMs = v
		return v < quicMaxAckDelayLimitMs
	case quicTPInitialMaxStreamsBidi, quicTPInitialMaxStreamsUni:
		return v <= quicMaxStreamsLimit
	}
	return true
}

func parseU16ListInto(data []byte, small []uint16, overflow *[]uint16) []uint16 {
	if len(data) < 2 {
		return nil
	}
	n := int(data[0])<<8 | int(data[1])
	if 2+n > len(data) || n%2 != 0 {
		return nil
	}
	count := n / 2
	var out []uint16
	if count <= len(small) {
		out = small[:count]
	} else {
		if cap(*overflow) < count {
			*overflow = make([]uint16, count)
		}
		out = (*overflow)[:count]
	}
	for i, j := 2, 0; j < count; i, j = i+2, j+1 {
		out[j] = uint16(data[i])<<8 | uint16(data[i+1])
	}
	return out
}

func (ch *ParsedClientHello) internServerName(name []byte) string {
	if name == nil {
		return ""
	}
	if string(name) != ch.lastServerName {
		ch.lastServerName = string(name)
	}
	return ch.lastServerName
}

func internALPN(p []byte) string {
	switch string(p) {
	case "h2":
		return "h2"
	case "http/1.1":
		return "http/1.1"
	}
	return string(p)
}

func parseSNI(data []byte) []byte {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return nil
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
			return list[i : i+nameLen]
		}
		i += nameLen
	}
	return nil
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

func parseALPN(ch *ParsedClientHello, data []byte) ([]string, bool) {
	if len(data) < 2 {
		return nil, false
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) != 2+listLen || listLen == 0 {
		return nil, false
	}
	list := data[2:]
	count := 0
	for i := 0; i < len(list); {
		pLen := int(list[i])
		i++
		if pLen == 0 || i+pLen > len(list) {
			return nil, false
		}
		if count < maxALPNProtocols {
			count++
		}
		i += pLen
	}
	protos := ch.alpnDst(count)
	for i, j := 0, 0; i < len(list) && j < count; j++ {
		pLen := int(list[i])
		i++
		protos[j] = internALPN(list[i : i+pLen])
		i += pLen
	}
	return protos, true
}

func parseKeyShares(ch *ParsedClientHello, data []byte) {
	if len(data) < 2 {
		return
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return
	}
	entries := data[2 : 2+listLen]
	for j := 0; j+4 <= len(entries); {
		group := tlsGroup(uint16(entries[j])<<8 | uint16(entries[j+1]))
		kLen := int(entries[j+2])<<8 | int(entries[j+3])
		if j+4+kLen > len(entries) {
			return
		}
		ch.recordKeyShare(group, entries[j+4:j+4+kLen])
		j += 4 + kLen
	}
}

// NegotiateALPN returns "h2" if allowH2 is true and clientProtos contains it,
// otherwise "http/1.1" if clientProtos contains it, otherwise an empty string.
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
