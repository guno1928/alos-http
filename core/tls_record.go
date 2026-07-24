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

// BufConn wraps a net.Conn with a pooled bufio.Reader for buffered reads, while
// writes pass through directly to the underlying connection.
type BufConn struct {
	net.Conn
	br *bufio.Reader
}

// NewBufConn wraps c in a BufConn, acquiring a pooled bufio.Reader for buffered
// reads. Call Release when done to return the reader to the pool.
func NewBufConn(c net.Conn) *BufConn {
	br := BufReaderPool.Get().(*bufio.Reader)
	br.Reset(c)
	return &BufConn{Conn: c, br: br}
}

// Release resets and returns the BufConn's pooled bufio.Reader to the pool. The
// BufConn must not be used again afterward.
func (bc *BufConn) Release() {
	bc.br.Reset(nil)
	BufReaderPool.Put(bc.br)
	bc.br = nil
}

// Read reads from the underlying connection through the buffered reader.
func (bc *BufConn) Read(p []byte) (int, error) {
	return bc.br.Read(p)
}

func releaseOwnedWriteBuf(data []byte, releaseBuf *[]byte, releasePool uint8) {
	if releaseBuf == nil {
		return
	}
	switch releasePool {
	case writeOwnedReleaseSmallBuf:
		*releaseBuf = data[:0]
		SmallBufPool.Put(releaseBuf)
	case writeOwnedReleaseMediumBuf:
		*releaseBuf = data[:0]
		MediumBufPool.Put(releaseBuf)
	case writeOwnedReleaseLargeBuf:
		*releaseBuf = data[:0]
		LargeBufPool.Put(releaseBuf)
	}
}

// WriteOwned writes p to the underlying connection, delegating to the connection's
// own WriteOwned if it implements ownedWriteConn (letting it defer buffer release
// for async writes); otherwise it writes synchronously and immediately releases the
// buffer to the pool identified by releasePool.
func (bc *BufConn) WriteOwned(p []byte, releaseBuf *[]byte, releasePool uint8) (int, error) {
	if owned, ok := bc.Conn.(ownedWriteConn); ok {
		return owned.WriteOwned(p, releaseBuf, releasePool)
	}
	n, err := bc.Conn.Write(p)
	releaseOwnedWriteBuf(p, releaseBuf, releasePool)
	return n, err
}

// TLSConn pairs a raw net.Conn with a pooled scratch buffer sized for one TLS record.
type TLSConn struct {
	Raw     net.Conn
	ReadBuf []byte
}

// NewTLSConn wraps c in a TLSConn, acquiring a pooled buffer sized for one TLS
// record. Call Release when done to return the buffer to the pool.
func NewTLSConn(c net.Conn) *TLSConn {
	bp := RecordBufPool.Get().(*[]byte)
	return &TLSConn{Raw: c, ReadBuf: (*bp)[:0]}
}

// Release returns the TLSConn's pooled read buffer to the pool. The TLSConn must
// not be used again afterward.
func (c *TLSConn) Release() {
	if c.ReadBuf != nil {
		b := c.ReadBuf[:0]
		RecordBufPool.Put(&b)
		c.ReadBuf = nil
	}
}

// ReadRecord reads one raw TLS record from conn into a pooled buffer, using
// hdrScratch as scratch space for the 5-byte header, and returns the record's
// content type, payload, and the pool box pointer for the caller to release via
// ReleaseRecordBuf.
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

// ReadRecordSkipCCS is like ReadRecord but transparently discards up to 5 leading
// ChangeCipherSpec (0x14) records, returning ErrTruncated if more than that many are seen.
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

// ReleaseRecordBuf returns a record buffer obtained from ReadRecord (or ReadRecordSkipCCS) to RecordBufPool.
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

// WriteRecord writes payload to conn as a single TLS 1.2-framed record (version
// 0x0303) of content type ct, returning ErrRecordTooLarge if payload exceeds MaxRecordSize.
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

// SendCCS writes a TLS ChangeCipherSpec record to conn.
func SendCCS(conn net.Conn) error {
	return WriteRecord(conn, 0x14, []byte{0x01})
}

// AppendRecord appends a TLS 1.2-framed record (version 0x0303) of content type ct
// and payload to dst and returns the extended slice, truncating payload to
// MaxRecordPayload bytes if it is larger.
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

// StripInnerPlaintext parses a TLS 1.3 decrypted inner plaintext (content followed
// by a one-byte content type, followed by zero padding), returning the content and
// content type. It returns ErrAllZeroInner if data contains no non-zero byte.
func StripInnerPlaintext(data []byte) (content []byte, contentType byte, err error) {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0 {
			return data[:i], data[i], nil
		}
	}
	return nil, 0, ErrAllZeroInner
}

// SendCloseNotify encrypts and writes a TLS 1.3 close_notify alert to conn using writer.
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

// WriteAppData encrypts data with writer into one or more TLS 1.3 application-data
// records (each carrying at most MaxRecordPayload-1 bytes of inner content) and
// writes them to conn, using the connection's WriteOwned when available to hand off
// buffer ownership for async writes.
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

		obp := MediumBufPool.Get().(*[]byte)
		out := (*obp)[:5]
		out[0] = 0x17
		out[1] = 0x03
		out[2] = 0x03
		out[3] = byte(ciphertextLen >> 8)
		out[4] = byte(ciphertextLen)
		out = writer.EncryptAppend(out, inner)

		if owned, ok := conn.(ownedWriteConn); ok {
			_, err := owned.WriteOwned(out, obp, writeOwnedReleaseMediumBuf)
			return err
		}
		err := writeFull(conn, out)
		*obp = out[:0]
		MediumBufPool.Put(obp)
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
			*obp = out
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
