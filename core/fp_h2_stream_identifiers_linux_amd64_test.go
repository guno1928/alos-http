package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func streamIdentifierConn(nextID uint32) *backendConn {
	conn := &backendConn{state: connClosed, be: &beLoop{cfg: &fpConfig{MaxHeaderBytes: 65536, MaxResponseBody: 1024}}, transport: &plainTransport{h2: true}}
	conn.h2init()
	conn.h2.nextID = nextID
	return conn
}

func streamIdentifierHeaderBlock() []byte {
	var encoder hpackEncoder
	encoder.reset([]byte{0x88, 0x40})
	encoder.appendString("x-identity")
	encoder.appendString("retained-value")
	return encoder.buf
}

func streamIdentifierWantCredit(t *testing.T, output []byte, streamIDs []uint32, consumed uint32) {
	t.Helper()
	if len(output) != len(streamIDs)*13 {
		t.Fatalf("credit bytes=%x, want %d frames", output, len(streamIDs))
	}
	for index, streamID := range streamIDs {
		frame := output[index*13 : (index+1)*13]
		if !bytes.Equal(frame[:5], []byte{0, 0, 4, h2FrameWindowUpdate, 0}) || binary.BigEndian.Uint32(frame[5:9]) != streamID || binary.BigEndian.Uint32(frame[9:13]) != consumed {
			t.Fatalf("credit frame=%x, want stream=%d consumed=%d", frame, streamID, consumed)
		}
	}
}

func TestFPH2RejectsUnopenedHeaderStreams(t *testing.T) {
	for _, streamID := range []uint32{0, 2, 3, 5} {
		for _, flags := range []byte{0, h2FlagEndHeaders, h2FlagEndHeaders | h2FlagEndStream} {
			t.Run(fmt.Sprintf("stream_%d_flags_%d", streamID, flags), func(t *testing.T) {
				conn := streamIdentifierConn(3)
				conn.h2.headerAssembly = []byte{0x82}
				active := &h2Stream{id: 1, status: 201, headers: [][2]string{{"x-live", "untouched"}}, body: []byte("live-body")}
				conn.h2.streams[1] = active
				err := conn.be.h2proto.onData(conn, h2Frame(h2FrameHeaders, flags, streamID, streamIdentifierHeaderBlock()))
				if err != errFPBadResponse {
					t.Errorf("unopened HEADERS error=%v, want bad response", err)
				}
				if !bytes.Equal(conn.h2.headerAssembly, []byte{0x82}) || len(conn.h2.dec.dyn) != 0 || conn.h2.continuation != 0 || len(conn.wbuf.unread()) != 0 || active.status != 201 || len(active.headers) != 1 || active.headers[0] != [2]string{"x-live", "untouched"} || string(active.body) != "live-body" {
					t.Fatalf("invalid HEADERS mutated assembly=%x dynamic=%d continuation=%d output=%x active=%+v", conn.h2.headerAssembly, len(conn.h2.dec.dyn), conn.h2.continuation, conn.wbuf.unread(), active)
				}
			})
		}
	}
}

func TestFPH2RejectsUnsolicitedContinuation(t *testing.T) {
	for _, flags := range []byte{0, h2FlagEndHeaders} {
		for _, streamID := range []uint32{0, 1} {
			t.Run(fmt.Sprintf("stream_%d_flags_%d", streamID, flags), func(t *testing.T) {
				conn := streamIdentifierConn(3)
				conn.h2.headerAssembly = []byte{0x82}
				err := conn.be.h2proto.onData(conn, h2Frame(h2FrameContinuation, flags, streamID, streamIdentifierHeaderBlock()))
				if err != errFPBadResponse || !bytes.Equal(conn.h2.headerAssembly, []byte{0x82}) || len(conn.h2.dec.dyn) != 0 || len(conn.wbuf.unread()) != 0 {
					t.Fatalf("unsolicited continuation error=%v assembly=%x dynamic=%d output=%x", err, conn.h2.headerAssembly, len(conn.h2.dec.dyn), conn.wbuf.unread())
				}
			})
		}
	}
}

func TestFPH2RejectsIdleDataWithoutCredit(t *testing.T) {
	for _, streamID := range []uint32{0, 2, 5, 7} {
		for _, payload := range [][]byte{nil, {'x'}} {
			t.Run(fmt.Sprintf("stream_%d_bytes_%d", streamID, len(payload)), func(t *testing.T) {
				conn := streamIdentifierConn(5)
				left := &h2Stream{id: 1, body: []byte("left")}
				right := &h2Stream{id: 3, body: []byte("right")}
				conn.h2.streams[1], conn.h2.streams[3] = left, right
				err := conn.be.h2proto.onData(conn, h2Frame(h2FrameData, h2FlagEndStream, streamID, payload))
				if err != errFPBadResponse || len(conn.wbuf.unread()) != 0 || string(left.body) != "left" || string(right.body) != "right" || len(conn.h2.streams) != 2 {
					t.Fatalf("idle DATA error=%v credit=%x left=%q right=%q streams=%d", err, conn.wbuf.unread(), left.body, right.body, len(conn.h2.streams))
				}
			})
		}
	}
}

func TestFPH2ClosedDataPreservesConnectionCredit(t *testing.T) {
	for _, flags := range []byte{h2FlagPadded, h2FlagPadded | h2FlagEndStream} {
		conn := streamIdentifierConn(3)
		payload := []byte{2, 'x', 'y', 0, 0}
		if err := conn.be.h2proto.onData(conn, h2Frame(h2FrameData, flags, 1, payload)); err != nil {
			t.Fatal(err)
		}
		streamIdentifierWantCredit(t, conn.wbuf.unread(), []uint32{0}, 5)
		if len(conn.h2.streams) != 0 {
			t.Fatalf("closed DATA allocated a stream: %d", len(conn.h2.streams))
		}
	}
}

func TestFPH2ClosedDataAtLastValidStreamID(t *testing.T) {
	for _, streamID := range []uint32{1, 0x7fffffff} {
		conn := streamIdentifierConn(0x80000001)
		if err := conn.be.h2proto.onData(conn, h2Frame(h2FrameData, 0, streamID, []byte{'x'})); err != nil {
			t.Fatal(err)
		}
		streamIdentifierWantCredit(t, conn.wbuf.unread(), []uint32{0}, 1)
	}
}

func TestFPH2MalformedClosedDataPaddingReceivesNoCredit(t *testing.T) {
	for _, payload := range [][]byte{nil, {2, 0}} {
		conn := streamIdentifierConn(3)
		if err := conn.be.h2proto.onData(conn, h2Frame(h2FrameData, h2FlagPadded, 1, payload)); err != errFPBadResponse || len(conn.wbuf.unread()) != 0 {
			t.Fatalf("padding error=%v credit=%x", err, conn.wbuf.unread())
		}
	}
}

func TestFPH2ClosedHeadersPreserveCompressionState(t *testing.T) {
	for _, fragmented := range []bool{false, true} {
		t.Run(fmt.Sprintf("fragmented_%t", fragmented), func(t *testing.T) {
			conn := streamIdentifierConn(5)
			active := &h2Stream{id: 3}
			conn.h2.streams[3] = active
			block := streamIdentifierHeaderBlock()
			input := h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, block)
			if fragmented {
				input = h2Frame(h2FrameHeaders, h2FlagEndStream, 1, block[:3])
				input = append(input, h2Frame(h2FrameContinuation, h2FlagEndHeaders, 1, block[3:])...)
			}
			input = append(input, h2Frame(h2FrameHeaders, h2FlagEndHeaders, 3, []byte{0x88, 0xbe})...)
			if err := conn.be.h2proto.onData(conn, input); err != nil {
				t.Fatal(err)
			}
			if !active.gotHeaders || active.status != 200 || len(active.headers) != 1 || active.headers[0] != [2]string{"x-identity", "retained-value"} || len(conn.h2.dec.dyn) != 1 || conn.h2.continuation != 0 || len(conn.wbuf.unread()) != 0 || len(conn.h2.streams) != 1 {
				t.Fatalf("closed header synchronization status=%d headers=%v dynamic=%d continuation=%d output=%x streams=%d", active.status, active.headers, len(conn.h2.dec.dyn), conn.h2.continuation, conn.wbuf.unread(), len(conn.h2.streams))
			}
		})
	}
}

func TestFPH2ActiveHeadersAndDataUseLiveStream(t *testing.T) {
	conn := streamIdentifierConn(1)
	active := &h2Stream{id: 5}
	conn.h2.streams[5] = active
	block := streamIdentifierHeaderBlock()
	input := h2Frame(h2FrameHeaders, 0, 5, block[:2])
	input = append(input, h2Frame(h2FrameContinuation, h2FlagEndHeaders, 5, block[2:])...)
	input = append(input, h2Frame(h2FrameData, h2FlagPadded, 5, []byte{2, 'o', 'k', 0, 0})...)
	if err := conn.be.h2proto.onData(conn, input); err != nil {
		t.Fatal(err)
	}
	if !active.gotHeaders || active.status != 200 || len(active.headers) != 1 || active.headers[0] != [2]string{"x-identity", "retained-value"} || string(active.body) != "ok" {
		t.Fatalf("active headers=%v status=%d body=%q", active.headers, active.status, active.body)
	}
	streamIdentifierWantCredit(t, conn.wbuf.unread(), []uint32{0, 5}, 5)
}

func TestFPH2PendingContinuationRejectsWrongSequence(t *testing.T) {
	for _, frame := range [][]byte{
		h2Frame(h2FrameContinuation, h2FlagEndHeaders, 3, []byte{0x88}),
		h2Frame(h2FrameData, 0, 1, []byte{'x'}),
	} {
		conn := streamIdentifierConn(3)
		conn.h2.continuation = 1
		conn.h2.headerAssembly = []byte{0x82}
		active := &h2Stream{id: 1}
		conn.h2.streams[1] = active
		if err := conn.be.h2proto.onData(conn, frame); err != errFPBadResponse || !bytes.Equal(conn.h2.headerAssembly, []byte{0x82}) || len(active.body) != 0 || len(conn.wbuf.unread()) != 0 {
			t.Fatalf("sequence error=%v assembly=%x body=%x credit=%x", err, conn.h2.headerAssembly, active.body, conn.wbuf.unread())
		}
	}
}

func TestFPH2ActiveDataBodyLimitRetained(t *testing.T) {
	conn := streamIdentifierConn(3)
	conn.be.cfg.MaxResponseBody = 3
	active := &h2Stream{id: 1, body: []byte("ab")}
	conn.h2.streams[1] = active
	if err := conn.be.h2proto.onData(conn, h2Frame(h2FrameData, 0, 1, []byte("cd"))); err != errFPBodyTooLarge || string(active.body) != "ab" || len(conn.wbuf.unread()) != 0 {
		t.Fatalf("body limit error=%v body=%q credit=%x", err, active.body, conn.wbuf.unread())
	}
}
