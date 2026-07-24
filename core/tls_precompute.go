package core

import (
	"crypto/hmac"
	"hash"
)

type hkdfLabelTemplate struct {
	prefix    []byte
	totalLen  int
	outLen    int
	digestLen int
}

func newHKDFLabelTemplate(label string, outLen, ctxLen, digestLen int) hkdfLabelTemplate {
	const tls13Prefix = "tls13 "
	fullLen := len(tls13Prefix) + len(label)
	prefixLen := 2 + 1 + fullLen + 1
	prefix := make([]byte, prefixLen)
	prefix[0] = byte(outLen >> 8)
	prefix[1] = byte(outLen)
	prefix[2] = byte(fullLen)
	copy(prefix[3:], tls13Prefix)
	copy(prefix[3+len(tls13Prefix):], label)
	prefix[3+fullLen] = byte(ctxLen)
	return hkdfLabelTemplate{
		prefix:    prefix,
		totalLen:  prefixLen + ctxLen,
		outLen:    outLen,
		digestLen: digestLen,
	}
}

func (t hkdfLabelTemplate) ExpandTo(h func() hash.Hash, secret, ctx, dst []byte) []byte {
	var infoBuf [128]byte
	var info []byte
	if t.totalLen <= len(infoBuf) {
		info = infoBuf[:t.totalLen]
	} else {
		info = make([]byte, t.totalLen)
	}
	copy(info, t.prefix)
	copy(info[len(t.prefix):], ctx)

	mac := hmac.New(h, secret)
	mac.Write(info)
	mac.Write(hkdfExpandOneByte[:])

	if cap(dst) < t.digestLen {
		dst = make([]byte, 0, t.digestLen)
	} else {
		dst = dst[:0]
	}
	out := mac.Sum(dst)
	return out[:t.outLen]
}

// TLSExtractTo performs the TLS 1.3 HKDF-Extract step (HMAC(salt, ikm)), appending the result to dst and returning the extended slice.
func TLSExtractTo(h func() hash.Hash, salt, ikm, dst []byte) []byte {
	mac := hmac.New(h, salt)
	mac.Write(ikm)
	size := mac.Size()
	if cap(dst) < size {
		dst = make([]byte, 0, size)
	} else {
		dst = dst[:0]
	}
	return mac.Sum(dst)
}

func init() {
	for i := range SupportedSuites {
		SupportedSuites[i].initPrecompute()
	}
}

func (cs *CipherSuiteConfig) initPrecompute() {
	cs.zeroHashInput = make([]byte, cs.HashLen)
	cs.emptyTranscriptHash = EmptyTranscriptHash(cs.HashFn)

	cs.labelDerived = newHKDFLabelTemplate("derived", cs.HashLen, cs.HashLen, cs.HashLen)
	cs.labelFinished = newHKDFLabelTemplate("finished", cs.HashLen, 0, cs.HashLen)
	cs.labelKey = newHKDFLabelTemplate("key", cs.KeyLen, 0, cs.HashLen)
	cs.labelIV = newHKDFLabelTemplate("iv", cs.IVLen, 0, cs.HashLen)
	cs.labelClientHSTraffic = newHKDFLabelTemplate("c hs traffic", cs.HashLen, cs.HashLen, cs.HashLen)
	cs.labelServerHSTraffic = newHKDFLabelTemplate("s hs traffic", cs.HashLen, cs.HashLen, cs.HashLen)
	cs.labelClientAppTraffic = newHKDFLabelTemplate("c ap traffic", cs.HashLen, cs.HashLen, cs.HashLen)
	cs.labelServerAppTraffic = newHKDFLabelTemplate("s ap traffic", cs.HashLen, cs.HashLen, cs.HashLen)

	var earlyBuf [64]byte
	cs.earlySecret = append(cs.earlySecret[:0], TLSExtractTo(cs.HashFn, cs.zeroHashInput, cs.zeroHashInput, earlyBuf[:0])...)
	var derivedBuf [64]byte
	cs.derivedFromEarly = append(cs.derivedFromEarly[:0], cs.labelDerived.ExpandTo(cs.HashFn, cs.earlySecret, cs.emptyTranscriptHash, derivedBuf[:0])...)
}

// DeriveSecretTo derives a TLS 1.3 secret from secret and transcriptHash using the given HKDF label template, appending the result to dst.
func (cs *CipherSuiteConfig) DeriveSecretTo(tmpl *hkdfLabelTemplate, secret, transcriptHash, dst []byte) []byte {
	return tmpl.ExpandTo(cs.HashFn, secret, transcriptHash, dst)
}

// ComputeFinishedTo computes a TLS 1.3 Finished message MAC over transcriptHash using baseSecret, appending the result to dst.
func (cs *CipherSuiteConfig) ComputeFinishedTo(baseSecret, transcriptHash, dst []byte) []byte {
	var finishedKeyBuf [64]byte
	finishedKey := cs.labelFinished.ExpandTo(cs.HashFn, baseSecret, nil, finishedKeyBuf[:0])
	mac := hmac.New(cs.HashFn, finishedKey)
	mac.Write(transcriptHash)
	size := mac.Size()
	if cap(dst) < size {
		dst = make([]byte, 0, size)
	} else {
		dst = dst[:0]
	}
	return mac.Sum(dst)
}
