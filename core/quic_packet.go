package core

import (
	"encoding/binary"
	"sync"
)

var quicHdrCopyPool = sync.Pool{
	New: func() any { b := make([]byte, 0, 32); return &b },
}

const (
	quicVersion1      uint32 = 0x00000001
	quicLongHeaderBit byte   = 0x80
	quicFixedBit      byte   = 0x40
	quicInitialType   byte   = 0x00
	quicZeroRTTType   byte   = 0x01
	quicHandshakeType byte   = 0x02
	quicRetryType     byte   = 0x03
)

const (
	quicPktInitial   = 0
	quicPktHandshake = 1
	quicPktZeroRTT   = 2
	quicPktRetry     = 3
	quicPktShort     = 4
)

type quicPacketHeader struct {
	pktType     int
	version     uint32
	dcid        []byte
	scid        []byte
	token       []byte
	pn          uint64
	pnLen       int
	pnOffset    int
	payloadOff  int
	payloadLen  int
	headerBytes []byte
}

func quicParseLongHeader(data []byte) (hdr quicPacketHeader, total int, err error) {
	if len(data) < 7 {
		return hdr, 0, ErrTruncated
	}
	first := data[0]
	if first&quicLongHeaderBit == 0 {
		return hdr, 0, ErrNotClientHello
	}

	hdr.version = binary.BigEndian.Uint32(data[1:5])
	dcidLen := int(data[5])
	if dcidLen > 20 || 6+dcidLen >= len(data) {
		return hdr, 0, ErrTruncated
	}
	hdr.dcid = data[6 : 6+dcidLen]

	off := 6 + dcidLen
	if off >= len(data) {
		return hdr, 0, ErrTruncated
	}
	scidLen := int(data[off])
	off++
	if off+scidLen > len(data) || scidLen > 20 {
		return hdr, 0, ErrTruncated
	}
	hdr.scid = data[off : off+scidLen]
	off += scidLen

	if hdr.version == 0 {
		hdr.pktType = -1
		hdr.payloadOff = off
		hdr.payloadLen = len(data) - off
		return hdr, len(data), nil
	}

	longType := (first & 0x30) >> 4
	switch longType {
	case quicInitialType:
		hdr.pktType = quicPktInitial
		tokenLen, n := quicParseVarint(data[off:])
		if n == 0 {
			return hdr, 0, ErrTruncated
		}
		off += n
		if uint64(off)+tokenLen > uint64(len(data)) {
			return hdr, 0, ErrTruncated
		}
		if tokenLen > 0 {
			hdr.token = data[off : off+int(tokenLen)]
			off += int(tokenLen)
		}
	case quicHandshakeType:
		hdr.pktType = quicPktHandshake
	case quicZeroRTTType:
		hdr.pktType = quicPktZeroRTT
	case quicRetryType:
		hdr.pktType = quicPktRetry
		hdr.payloadOff = off
		hdr.payloadLen = len(data) - off
		return hdr, len(data), nil
	}

	pktLen, n := quicParseVarint(data[off:])
	if n == 0 {
		return hdr, 0, ErrTruncated
	}
	off += n
	if uint64(off)+pktLen > uint64(len(data)) {
		return hdr, 0, ErrTruncated
	}

	hdr.pnOffset = off
	hdr.payloadOff = off
	hdr.payloadLen = int(pktLen)
	total = off + int(pktLen)
	return hdr, total, nil
}

func quicParseShortHeader(data []byte, dcidLen int) (hdr quicPacketHeader, err error) {
	if len(data) < 1+dcidLen {
		return hdr, ErrTruncated
	}
	hdr.pktType = quicPktShort
	hdr.dcid = data[1 : 1+dcidLen]
	hdr.pnOffset = 1 + dcidLen
	hdr.payloadOff = 1 + dcidLen
	hdr.payloadLen = len(data) - (1 + dcidLen)
	return hdr, nil
}

func quicIsLongHeader(data []byte) bool {
	return len(data) > 0 && data[0]&quicLongHeaderBit != 0
}

func quicIsInitialPacket(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	if data[0]&quicLongHeaderBit == 0 {
		return false
	}
	longType := (data[0] & 0x30) >> 4
	return longType == quicInitialType
}

func quicBuildLongHeader(dst []byte, pktType byte, version uint32, dcid, scid, token []byte, pnLen int) []byte {
	first := quicLongHeaderBit | quicFixedBit | (pktType << 4) | byte(pnLen-1)
	dst = append(dst, first)
	var vbuf [4]byte
	binary.BigEndian.PutUint32(vbuf[:], version)
	dst = append(dst, vbuf[:]...)
	dst = append(dst, byte(len(dcid)))
	dst = append(dst, dcid...)
	dst = append(dst, byte(len(scid)))
	dst = append(dst, scid...)

	if pktType == quicInitialType {
		dst = quicAppendVarint(dst, uint64(len(token)))
		dst = append(dst, token...)
	}

	return dst
}

func quicBuildShortHeader(dst []byte, dcid []byte, pn uint64, pnLen int, keyPhase uint32) []byte {
	first := quicFixedBit | byte(pnLen-1)
	if keyPhase == 1 {
		first |= 0x04
	}
	dst = append(dst, first)
	dst = append(dst, dcid...)
	pnOff := len(dst)
	for i := pnLen - 1; i >= 0; i-- {
		dst = append(dst, byte(pn>>(uint(i)*8)))
	}
	_ = pnOff
	return dst
}

func quicAppendPacketNumber(dst []byte, pn uint64, pnLen int) []byte {
	for i := pnLen - 1; i >= 0; i-- {
		dst = append(dst, byte(pn>>(uint(i)*8)))
	}
	return dst
}

func quicReadPacketNumber(data []byte, pnLen int) uint64 {
	var pn uint64
	for i := 0; i < pnLen; i++ {
		pn = pn<<8 | uint64(data[i])
	}
	return pn
}

func quicBuildInitialPacket(dst []byte, dcid, scid, token, payload []byte, pn uint64, largestAcked int64, keys *quicKeys) []byte {
	truncatedPN, pnLen := quicEncodePacketNumber(pn, largestAcked)

	headerStart := len(dst)
	dst = quicBuildLongHeader(dst, quicInitialType, quicVersion1, dcid, scid, token, pnLen)

	payloadWithPN := pnLen + len(payload) + keys.aead.Overhead()
	dst = quicAppendVarint(dst, uint64(payloadWithPN))

	pnOffset := len(dst)
	dst = quicAppendPacketNumber(dst, truncatedPN, pnLen)

	header := dst[headerStart:len(dst)]
	hcp := quicHdrCopyPool.Get().(*[]byte)
	headerCopy := append((*hcp)[:0], header...)

	dst = keys.encrypt(dst, headerCopy, payload, pn, pnOffset)

	keys.applyHeaderProtection(dst[headerStart:], pnOffset-headerStart, pnLen)

	*hcp = headerCopy
	quicHdrCopyPool.Put(hcp)
	return dst
}

func quicBuildHandshakePacket(dst []byte, dcid, scid, payload []byte, pn uint64, largestAcked int64, keys *quicKeys) []byte {
	truncatedPN, pnLen := quicEncodePacketNumber(pn, largestAcked)

	headerStart := len(dst)
	dst = quicBuildLongHeader(dst, quicHandshakeType, quicVersion1, dcid, scid, nil, pnLen)

	payloadWithPN := pnLen + len(payload) + keys.aead.Overhead()
	dst = quicAppendVarint(dst, uint64(payloadWithPN))

	pnOffset := len(dst)
	dst = quicAppendPacketNumber(dst, truncatedPN, pnLen)

	header := dst[headerStart:len(dst)]
	hcp := quicHdrCopyPool.Get().(*[]byte)
	headerCopy := append((*hcp)[:0], header...)

	dst = keys.encrypt(dst, headerCopy, payload, pn, pnOffset)

	keys.applyHeaderProtection(dst[headerStart:], pnOffset-headerStart, pnLen)

	*hcp = headerCopy
	quicHdrCopyPool.Put(hcp)
	return dst
}

func quicBuildShortPacket(dst []byte, dcid, payload []byte, pn uint64, largestAcked int64, keys *quicKeys, keyPhase uint32) []byte {
	truncatedPN, pnLen := quicEncodePacketNumber(pn, largestAcked)

	headerStart := len(dst)
	dst = quicBuildShortHeader(dst, dcid, truncatedPN, pnLen, keyPhase)

	pnOffset := headerStart + 1 + len(dcid)

	header := dst[headerStart:len(dst)]
	hcp := quicHdrCopyPool.Get().(*[]byte)
	headerCopy := append((*hcp)[:0], header...)

	dst = keys.encrypt(dst, headerCopy, payload, pn, pnOffset)

	keys.applyHeaderProtection(dst[headerStart:], pnOffset-headerStart, pnLen)

	*hcp = headerCopy
	quicHdrCopyPool.Put(hcp)
	return dst
}

func quicDecryptPacket(packet []byte, hdr *quicPacketHeader, keys *quicKeys, largestAcked int64) ([]byte, error) {
	pnLen := keys.removeHeaderProtection(packet, hdr.pnOffset)
	if pnLen == 0 {
		return nil, ErrTruncated
	}

	truncatedPN := quicReadPacketNumber(packet[hdr.pnOffset:], pnLen)
	hdr.pn = quicDecodePacketNumber(truncatedPN, pnLen, largestAcked)
	hdr.pnLen = pnLen

	headerEnd := hdr.pnOffset + pnLen
	payloadEnd := hdr.payloadOff + hdr.payloadLen
	if headerEnd > payloadEnd {
		return nil, ErrTruncated
	}

	header := packet[:headerEnd]
	ciphertext := packet[headerEnd:payloadEnd]

	plaintext, err := keys.decrypt(ciphertext[:0], header, ciphertext, hdr.pn)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
