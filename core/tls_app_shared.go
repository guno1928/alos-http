//go:build linux && amd64

package core

const (
	tlsConnPhaseClientHello    = 0
	tlsConnPhaseClientFinished = 1
	tlsConnPhaseApplication    = 2
	tlsConnPhaseH2Native       = 3
	tlsConnPhase12ClientFinish = 4
)

func nextTLSRecord(buf []byte) (byte, []byte, int, bool, error) {
	if len(buf) < 5 {
		return 0, nil, 0, false, nil
	}
	ct := buf[0]
	length := int(buf[3])<<8 | int(buf[4])
	if length > MaxRecordSize {
		return 0, nil, 0, false, ErrRecordTooLarge
	}
	totalLen := 5 + length
	if len(buf) < totalLen {
		return 0, nil, 0, false, nil
	}
	return ct, buf[5:totalLen], totalLen, true, nil
}

const tlsRecordHeaderLen = 5

func ensureTailCap(dst []byte, need int) []byte {
	if cap(dst)-len(dst) >= need {
		return dst
	}
	want := len(dst) + need
	if want > epollIOBufPoolMaxCap {
		return growIOBuf(dst, need)
	}
	newCap := cap(dst) * 2
	if newCap < want {
		newCap = want
	}
	grown := make([]byte, len(dst), newCap)
	copy(grown, dst)
	return grown
}

func sealTLSInnerInPlace(dst []byte, writer *TrafficAEAD, hdr int) []byte {
	start := hdr + tlsRecordHeaderLen
	ciphertextLen := len(dst) - start + writer.Overhead()
	dst[hdr] = 0x17
	dst[hdr+1] = 0x03
	dst[hdr+2] = 0x03
	dst[hdr+3] = byte(ciphertextLen >> 8)
	dst[hdr+4] = byte(ciphertextLen)
	sealed := writer.Encrypt(dst[start:])
	return dst[:start+len(sealed)]
}

func appendTLSInnerRecord(dst []byte, writer *TrafficAEAD, innerPayload []byte) []byte {
	hdr := len(dst)
	dst = ensureTailCap(dst, tlsRecordHeaderLen+len(innerPayload)+writer.Overhead())
	dst = append(dst[:hdr+tlsRecordHeaderLen], innerPayload...)
	return sealTLSInnerInPlace(dst, writer, hdr)
}

func appendTLSInnerRecords(dst []byte, writer *TrafficAEAD, innerPayload []byte) []byte {
	if len(innerPayload) <= MaxRecordPayload {
		return appendTLSInnerRecord(dst, writer, innerPayload)
	}
	const maxContent = MaxRecordPayload - 1
	content, innerType := innerPayload[:len(innerPayload)-1], innerPayload[len(innerPayload)-1]
	for len(content) > 0 {
		n := min(len(content), maxContent)
		hdr := len(dst)
		dst = ensureTailCap(dst, tlsRecordHeaderLen+n+1+writer.Overhead())
		dst = append(dst[:hdr+tlsRecordHeaderLen], content[:n]...)
		dst = append(dst, innerType)
		dst = sealTLSInnerInPlace(dst, writer, hdr)
		content = content[n:]
	}
	return dst
}

func buildTLSAppDataRecords(dst []byte, writer *TrafficAEAD, payload []byte) []byte {
	return buildTLSAppDataRecordsParts(dst, writer, payload, nil)
}

func buildTLSAppDataRecordsParts(dst []byte, writer *TrafficAEAD, head, body []byte) []byte {
	if writer == nil {
		return dst
	}
	const maxContent = MaxRecordPayload - 1
	total := len(head) + len(body)
	if total == 0 {
		return dst
	}
	records := (total + maxContent - 1) / maxContent
	dst = ensureTailCap(dst, total+records*(tlsRecordHeaderLen+1+writer.Overhead()))
	return appendTLSCopiedRecords(dst, writer, head, body)
}

func appendTLSCopiedRecords(dst []byte, writer *TrafficAEAD, head, body []byte) []byte {
	const maxContent = MaxRecordPayload - 1
	for len(head)+len(body) > 0 {
		hdr := len(dst)
		n := min(len(head), maxContent)
		m := min(len(body), maxContent-n)
		dst = append(dst[:hdr+tlsRecordHeaderLen], head[:n]...)
		dst = append(dst, body[:m]...)
		dst = append(dst, 0x17)
		head, body = head[n:], body[m:]
		dst = sealTLSInnerInPlace(dst, writer, hdr)
	}
	return dst
}

func buildTLSAppDataRecordsMutableBody(dst []byte, writer *TrafficAEAD, head, body []byte) []byte {
	if writer == nil {
		return dst
	}
	const maxContent = MaxRecordPayload - 1
	total := len(head) + len(body)
	if total == 0 {
		return dst
	}
	records := (total + maxContent - 1) / maxContent
	dst = ensureTailCap(dst, total+records*(tlsRecordHeaderLen+1+writer.Overhead()))
	if len(head) > 0 {
		lead := min(len(body), (maxContent-len(head)%maxContent)%maxContent)
		dst = appendTLSCopiedRecords(dst, writer, head, body[:lead])
		body = body[lead:]
	}
	for len(body) > 0 {
		n := min(len(body), maxContent)
		dst = sealTLSRecordAround(dst, writer, nil, body, 0, n)
		body = body[n:]
	}
	return dst
}

const tlsRecordAroundMaxPrefix = 16

func sealTLSRecordAround(dst []byte, writer *TrafficAEAD, prefix, body []byte, off, n int) []byte {
	dst = ensureTailCap(dst, tlsRecordHeaderLen+len(prefix)+n+1+writer.Overhead())
	start := off - len(prefix)
	if start < 0 || len(prefix) > tlsRecordAroundMaxPrefix || off+n >= cap(body) {
		return appendTLSCopiedRecords(dst, writer, prefix, body[off:off+n])
	}
	inner := body[start : off+n+1]
	last := len(inner) - 1
	var saved [tlsRecordAroundMaxPrefix]byte
	copy(saved[:], inner[:len(prefix)])
	savedLast := inner[last]
	copy(inner, prefix)
	inner[last] = 0x17
	ciphertextLen := len(inner) + writer.Overhead()
	dst = append(dst, 0x17, 0x03, 0x03, byte(ciphertextLen>>8), byte(ciphertextLen))
	dst = writer.EncryptAppend(dst, inner)
	copy(inner, saved[:len(prefix)])
	inner[last] = savedLast
	return dst
}
