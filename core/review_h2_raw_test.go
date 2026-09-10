//go:build linux && amd64

package core

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type h2RawFrame struct {
	typ      byte
	flags    byte
	streamID uint32
	payload  []byte
}

type h2RawConn struct {
	t    *testing.T
	conn net.Conn
}

func startPlainH2Server(t *testing.T) string {
	t.Helper()
	addr := reserveLocalAddr(t)
	srv := New(Config{
		Addr:          addr,
		PlainHTTP:     true,
		HTTPAddr:      "-",
		LogRequests:   false,
		MaxConnsPerIP: -1,
	})
	srv.Router.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	waitForPort(t, addr)
	return addr
}

func h2RawDial(t *testing.T, addr string, settings []byte) *h2RawConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	rc := &h2RawConn{t: t, conn: conn}
	if _, err := conn.Write(H2ClientPreface[:]); err != nil {
		t.Fatalf("preface: %v", err)
	}
	rc.write(H2FrameSettings, 0, 0, settings)
	for {
		f := rc.read()
		if f.typ == H2FrameSettings && f.flags&H2FlagAck == 0 {
			rc.write(H2FrameSettings, H2FlagAck, 0, nil)
			return rc
		}
	}
}

func (rc *h2RawConn) write(typ, flags byte, streamID uint32, payload []byte) {
	rc.t.Helper()
	hdr := make([]byte, 9, 9+len(payload))
	hdr[0] = byte(len(payload) >> 16)
	hdr[1] = byte(len(payload) >> 8)
	hdr[2] = byte(len(payload))
	hdr[3] = typ
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:], streamID)
	if _, err := rc.conn.Write(append(hdr, payload...)); err != nil {
		rc.t.Fatalf("write frame type %d: %v", typ, err)
	}
}

func (rc *h2RawConn) read() h2RawFrame {
	rc.t.Helper()
	f, err := rc.tryRead()
	if err != nil {
		rc.t.Fatalf("read frame: %v", err)
	}
	return f
}

func (rc *h2RawConn) tryRead() (h2RawFrame, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(rc.conn, hdr[:]); err != nil {
		return h2RawFrame{}, err
	}
	n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	f := h2RawFrame{typ: hdr[3], flags: hdr[4], streamID: binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff}
	if n > 0 {
		f.payload = make([]byte, n)
		if _, err := io.ReadFull(rc.conn, f.payload); err != nil {
			return h2RawFrame{}, err
		}
	}
	return f, nil
}

func (rc *h2RawConn) awaitStreamOutcome(streamID uint32) (h2RawFrame, error) {
	for {
		f, err := rc.tryRead()
		if err != nil {
			return h2RawFrame{}, err
		}
		if f.typ == H2FrameGoAway {
			return f, nil
		}
		if f.streamID != streamID {
			continue
		}
		if f.typ == H2FrameHeaders || f.typ == H2FrameRSTStream {
			return f, nil
		}
	}
}

func h2RawStatusFromHeaders(t *testing.T, block []byte) int {
	t.Helper()
	dec := NewHpackDecoder()
	hdrs, err := dec.Decode(block)
	if err != nil {
		t.Fatalf("decode response headers: %v", err)
	}
	for _, kv := range hdrs {
		if kv[0] == ":status" {
			n := 0
			for _, ch := range kv[1] {
				n = n*10 + int(ch-'0')
			}
			return n
		}
	}
	return 0
}

func hpackLiteralWithIndexing(nameIdx byte, value string) []byte {
	out := []byte{0x40 | nameIdx, byte(len(value))}
	return append(out, value...)
}

func TestH2PeerHeaderTableSizeDoesNotShrinkServerDecoder(t *testing.T) {
	addr := startPlainH2Server(t)
	peerTableSizeZero := []byte{0, byte(H2SettingHeaderTableSize), 0, 0, 0, 0}
	rc := h2RawDial(t, addr, peerTableSizeZero)

	first := []byte{0x82, 0x86}
	first = append(first, hpackLiteralWithIndexing(4, "/ok")...)
	first = append(first, hpackLiteralWithIndexing(1, "raw.test")...)
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, first)
	f, err := rc.awaitStreamOutcome(1)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	if f.typ != H2FrameHeaders || h2RawStatusFromHeaders(t, f.payload) != 200 {
		t.Fatalf("first request: frame type %d, want 200 HEADERS", f.typ)
	}

	second := []byte{0x82, 0x86, 0xbf, 0xbe}
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 3, second)
	f, err = rc.awaitStreamOutcome(3)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if f.typ != H2FrameHeaders {
		t.Fatalf("second request referencing the dynamic table got frame type %d: the peer's SETTINGS_HEADER_TABLE_SIZE was applied to the server's own decoder", f.typ)
	}
	if st := h2RawStatusFromHeaders(t, f.payload); st != 200 {
		t.Fatalf("second request status = %d", st)
	}
}

func TestH2HeaderBlockDecodeErrorIsConnectionError(t *testing.T) {
	addr := startPlainH2Server(t)
	rc := h2RawDial(t, addr, nil)

	broken := []byte{0x82, 0x86, 0x80}
	rc.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, 1, broken)
	f, err := rc.awaitStreamOutcome(1)
	if err != nil {
		t.Fatalf("await: %v", err)
	}
	if f.typ != H2FrameGoAway {
		t.Fatalf("undecodable header block answered with frame type %d, want GOAWAY: the decoder table is now desynchronised but the connection stays open", f.typ)
	}
	if code := binary.BigEndian.Uint32(f.payload[4:8]); code != H2ErrCompression {
		t.Fatalf("GOAWAY error code = %d, want COMPRESSION_ERROR", code)
	}
	_ = rc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, err := rc.tryRead(); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("connection still open 2s after GOAWAY(COMPRESSION_ERROR)")
			}
			return
		}
	}
}
