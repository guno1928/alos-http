package core

import (
	"bufio"
	"io"
	"net"
)

const (
	writeOwnedReleaseNone uint8 = iota
	writeOwnedReleaseSmallBuf
	writeOwnedReleaseMediumBuf
	writeOwnedReleaseLargeBuf
)

type ownedWriteConn interface {
	WriteOwned(p []byte, releaseBuf *[]byte, releasePool uint8) (int, error)
}

type BufConn struct {
	net.Conn
	br *bufio.Reader
}

func NewBufConn(c net.Conn) *BufConn {
	br := BufReaderPool.Get().(*bufio.Reader)
	br.Reset(c)
	return &BufConn{Conn: c, br: br}
}

func (bc *BufConn) Release() {
	bc.br.Reset(nil)
	BufReaderPool.Put(bc.br)
	bc.br = nil
}

func (bc *BufConn) Read(p []byte) (int, error) {
	return bc.br.Read(p)
}

type TLSConn struct {
	Raw     net.Conn
	ReadBuf []byte
}

func NewTLSConn(c net.Conn) *TLSConn {
	bp := RecordBufPool.Get().(*[]byte)
	return &TLSConn{Raw: c, ReadBuf: (*bp)[:0]}
}

func (c *TLSConn) Release() {
	if c.ReadBuf != nil {
		b := c.ReadBuf[:0]
		RecordBufPool.Put(&b)
		c.ReadBuf = nil
	}
}

func ReadRecord(conn net.Conn, hdrScratch []byte) (byte, []byte, *[]byte, error) {
	hdr := hdrScratch[:5]
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, nil, err
	}
	ct := hdr[0]
	length := int(hdr[3])<<8 | int(hdr[4])
	if length > MaxRecordSize {
		return 0, nil, nil, ErrRecordTooLarge
	}
	bp := RecordBufPool.Get().(*[]byte)
	if cap(*bp) < length {
		*bp = make([]byte, length)
	}
	payload := (*bp)[:length]
	if _, err := io.ReadFull(conn, payload); err != nil {
		*bp = (*bp)[:0]
		RecordBufPool.Put(bp)
		return 0, nil, nil, err
	}
	Dbg("Read record: type=0x%02x len=%d", ct, length)
	return ct, payload, bp, nil
}

func ReadRecordSkipCCS(conn net.Conn, hdr []byte) (byte, []byte, *[]byte, error) {
	maxCCSSkips := 5
	for i := 0; ; i++ {
		ct, data, bp, err := ReadRecord(conn, hdr)
		if err != nil {
			return 0, nil, nil, err
		}
		if ct == 0x14 {
			Dbg("Skipping CCS record from client")
			*bp = (*bp)[:0]
			RecordBufPool.Put(bp)
			if i >= maxCCSSkips {
				return 0, nil, nil, ErrTruncated
			}
			continue
		}
		return ct, data, bp, nil
	}
}

func ReleaseRecordBuf(bp *[]byte) {
	if bp != nil {
		*bp = (*bp)[:0]
		RecordBufPool.Put(bp)
	}
}

func writeFull(conn net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := conn.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func WriteRecord(conn net.Conn, ct byte, payload []byte) error {
	if len(payload) > MaxRecordSize {
		return ErrRecordTooLarge
	}
	bp := RecordBufPool.Get().(*[]byte)
	rec := (*bp)[:5+len(payload)]
	rec[0] = ct
	rec[1] = 0x03
	rec[2] = 0x03
	pLen := uint16(len(payload))
	rec[3] = byte(pLen >> 8)
	rec[4] = byte(pLen)
	copy(rec[5:], payload)
	err := writeFull(conn, rec)
	*bp = rec[:0]
	RecordBufPool.Put(bp)
	return err
}

func SendCCS(conn net.Conn) error {
	return WriteRecord(conn, 0x14, []byte{0x01})
}

func AppendRecord(dst []byte, ct byte, payload []byte) []byte {
	pLen := len(payload)
	if pLen > MaxRecordPayload {
		pLen = MaxRecordPayload
		payload = payload[:pLen]
	}
	dst = append(dst, ct, 0x03, 0x03, byte(pLen>>8), byte(pLen))
	dst = append(dst, payload...)
	return dst
}

// MaxInnerPadding bounds the backward scan over TLS 1.3 inner-plaintext
// trailing zero padding (RFC 8446 §5.4). Legitimate padding is small; without
// a cap an attacker can send a single content byte followed by ~16 KiB of zero
// padding to force a full-record scan per record (CPU amplification). 256 bytes
// is generous for any conformant peer (matches MaxRecordOverhead and the
// WriteAppData fast-path) while bounding the scan to a constant.
const MaxInnerPadding = 256

func StripInnerPlaintext(data []byte) (content []byte, contentType byte, err error) {
	limit := len(data) - MaxInnerPadding
	if limit < 0 {
		limit = 0
	}
	for i := len(data) - 1; i >= limit; i-- {
		if data[i] != 0 {
			return data[:i], data[i], nil
		}
	}
	if limit > 0 {
		// Content-type byte is more than MaxInnerPadding bytes from the end:
		// reject rather than keep scanning attacker-controlled padding.
		return nil, 0, ErrExcessiveInnerPadding
	}
	return nil, 0, ErrAllZeroInner
}

func SendCloseNotify(conn net.Conn, writer *TrafficAEAD) {
	var inner [3]byte
	inner[0] = 0x01
	inner[1] = 0x00
	inner[2] = 0x15
	rbp := SmallBufPool.Get().(*[]byte)
	ct := writer.EncryptAppend((*rbp)[:0], inner[:])
	WriteRecord(conn, 0x17, ct)
	*rbp = ct[:0]
	SmallBufPool.Put(rbp)
}

func WriteAppData(conn net.Conn, writer *TrafficAEAD, data []byte) error {
	const maxContent = MaxRecordPayload - 1
	overhead := writer.Overhead()

	if len(data) <= 256 {
		innerLen := len(data) + 1
		ciphertextLen := innerLen + overhead
		var innerBuf [257]byte
		inner := innerBuf[:innerLen]
		copy(inner, data)
		inner[innerLen-1] = 0x17

		obp := LargeBufPool.Get().(*[]byte)
		out := (*obp)[:5]
		out[0] = 0x17
		out[1] = 0x03
		out[2] = 0x03
		out[3] = byte(ciphertextLen >> 8)
		out[4] = byte(ciphertextLen)
		out = writer.EncryptAppend(out, inner)

		if owned, ok := conn.(ownedWriteConn); ok {
			_, err := owned.WriteOwned(out, obp, writeOwnedReleaseLargeBuf)
			return err
		}
		err := writeFull(conn, out)
		*obp = out[:0]
		LargeBufPool.Put(obp)
		return err
	}

	ibp := WriteBufPool.Get().(*[]byte)
	maxRecordLen := 5 + maxContent + 1 + overhead

	numRecords := (len(data) + maxContent - 1) / maxContent
	if numRecords < 1 {
		numRecords = 1
	}
	outCap := numRecords * maxRecordLen
	obp := LargeBufPool.Get().(*[]byte)
	var out []byte
	if cap(*obp) >= outCap {
		out = (*obp)[:0]
	} else {
		out = make([]byte, 0, outCap)
	}

	for len(data) > 0 {
		chunk := data
		if len(chunk) > maxContent {
			chunk = chunk[:maxContent]
		}
		data = data[len(chunk):]

		innerLen := len(chunk) + 1
		ciphertextLen := innerLen + overhead

		inner := (*ibp)[:innerLen]
		copy(inner, chunk)
		inner[innerLen-1] = 0x17

		recStart := len(out)
		out = append(out, 0x17, 0x03, 0x03, byte(ciphertextLen>>8), byte(ciphertextLen))
		out = writer.EncryptAppend(out, inner)
		_ = out[recStart]
	}

	var err error
	if len(out) > 0 {
		if owned, ok := conn.(ownedWriteConn); ok {
			_, err = owned.WriteOwned(out, obp, writeOwnedReleaseLargeBuf)
			*ibp = (*ibp)[:0]
			WriteBufPool.Put(ibp)
			return err
		}
		err = writeFull(conn, out)
	}
	*ibp = (*ibp)[:0]
	WriteBufPool.Put(ibp)
	*obp = out[:0]
	LargeBufPool.Put(obp)
	return err
}
