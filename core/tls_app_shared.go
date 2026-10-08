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
	newCap := cap(dst) * 2
	if newCap < want {
		newCap = want
	}
	grown := make([]byte, len(dst), newCap)
	copy(grown, dst)
	return grown
}

func appendTLSInnerRecord(dst []byte, writer *TrafficAEAD, innerPayload []byte) []byte {
	ciphertextLen := len(innerPayload) + writer.Overhead()
	dst = append(dst, 0x17, 0x03, 0x03, byte(ciphertextLen>>8), byte(ciphertextLen))
	return writer.EncryptAppend(dst, innerPayload)
}

func buildTLSAppDataRecords(dst []byte, writer *TrafficAEAD, payload []byte) []byte {
	if writer == nil {
		return dst
	}
	const maxContent = MaxRecordPayload - 1
	if len(payload) == 0 {
		return dst
	}
	records := (len(payload) + maxContent - 1) / maxContent
	dst = ensureTailCap(dst, len(payload)+records*(tlsRecordHeaderLen+1+writer.Overhead()))
	scratch := acquirePooledBuf(&tlsScratchPool)
	if cap(scratch) < MaxRecordPayload {
		scratch = make([]byte, 0, MaxRecordPayload)
	}
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > maxContent {
			chunk = chunk[:maxContent]
		}
		payload = payload[len(chunk):]
		inner := scratch[:len(chunk)+1]
		copy(inner, chunk)
		inner[len(chunk)] = 0x17
		dst = appendTLSInnerRecord(dst, writer, inner)
	}
	releasePooledBuf(&tlsScratchPool, scratch, MaxRecordSize)
	return dst
}
