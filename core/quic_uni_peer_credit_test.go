//go:build linux && amd64

package core

import (
	"bytes"
	"net"
	"testing"
)

func quicTransportParamsClientHello(params []byte) []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
	body = append(body, byte((len(params)+4)>>8), byte(len(params)+4), 0, 0x39, byte(len(params)>>8), byte(len(params)))
	body = append(body, params...)
	return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func uniCreditParam(id, value uint64) []byte {
	encoded := quicAppendVarint(nil, value)
	param := quicAppendVarint(nil, id)
	param = quicAppendVarint(param, uint64(len(encoded)))
	return append(param, encoded...)
}

func uniCreditParse(t *testing.T, parsed *ParsedClientHello, params []byte) {
	t.Helper()
	if err := ParseClientHello(quicTransportParamsClientHello(params), parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.quicTP.seen || parsed.quicTP.invalid {
		t.Fatalf("transport parameters: seen=%v invalid=%v", parsed.quicTP.seen, parsed.quicTP.invalid)
	}
}

func uniCreditConn(t *testing.T) *QUICConn {
	t.Helper()
	server := New(Config{QUICMaxStreamData: 8192, MaxHeaderSize: 16384})
	conn := newQUICConn(server, nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}, []byte{1}, []byte{2})
	conn.maxDataRemote = 1 << 20
	conn.pktBudget = 1200
	conn.loss.mu.Lock()
	conn.loss.bytesInFlight = int(conn.loss.cwnd)
	conn.loss.mu.Unlock()
	t.Cleanup(conn.close)
	return conn
}

func uniCreditApply(t *testing.T, conn *QUICConn, params []byte) {
	t.Helper()
	var parsed ParsedClientHello
	uniCreditParse(t, &parsed, params)
	conn.applyPeerTransportParams(&parsed)
}

func uniCreditCongested(t *testing.T, conn *QUICConn) {
	t.Helper()
	if conn.loss.canSend() {
		t.Fatal("capture fixture permits packet draining")
	}
	if conn.maxDataRemote != 1<<20 || conn.pktBudget != 1200 {
		t.Fatalf("capture fixture changed: connection credit=%d packet budget=%d", conn.maxDataRemote, conn.pktBudget)
	}
}

func uniCreditQueued(t *testing.T, conn *QUICConn) map[uint64][]byte {
	t.Helper()
	uniCreditCongested(t, conn)
	streams := make(map[uint64][]byte)
	visitor := &quicFrameVisitor{onStream: func(frame quicStreamFrame) {
		if frame.streamID != 3 && frame.streamID != 7 && frame.streamID != 11 {
			t.Fatalf("unexpected server uni stream ID %d", frame.streamID)
		}
		if frame.offset != uint64(len(streams[frame.streamID])) || frame.fin {
			t.Fatalf("stream %d offset=%d prior=%d fin=%v", frame.streamID, frame.offset, len(streams[frame.streamID]), frame.fin)
		}
		streams[frame.streamID] = append(streams[frame.streamID], frame.data...)
	}}
	if err := quicParseFrames(conn.coalesceBuf[conn.coalesceStart:], visitor); err != nil {
		t.Fatal(err)
	}
	return streams
}

func uniCreditExpected() map[uint64][]byte {
	return map[uint64][]byte{
		3:  {0, 4, 9, 6, 0x80, 0, 0x40, 0, 1, 0, 7, 0},
		7:  {2},
		11: {3},
	}
}

func uniCreditCheck(t *testing.T, conn *QUICConn, credit uint64) {
	t.Helper()
	emitted := uniCreditQueued(t, conn)
	if len(conn.streams) != 3 {
		t.Fatalf("startup opened %d streams, want 3", len(conn.streams))
	}
	var total uint64
	for id, expected := range uniCreditExpected() {
		stream := conn.streams[id]
		if stream == nil {
			t.Fatalf("missing startup stream %d", id)
		}
		allowed := min(credit, uint64(len(expected)))
		if stream.maxSend != credit || stream.sendOff != allowed {
			t.Errorf("stream %d credit=%d offset=%d, want credit=%d offset=%d", id, stream.maxSend, stream.sendOff, credit, allowed)
		}
		if !bytes.Equal(emitted[id], expected[:allowed]) || !bytes.Equal(stream.sendBuf, expected[allowed:]) {
			t.Errorf("stream %d emitted=%x pending=%x, want emitted=%x pending=%x", id, emitted[id], stream.sendBuf, expected[:allowed], expected[allowed:])
		}
		total += allowed
	}
	if conn.dataSent != total {
		t.Errorf("connection sent=%d, want %d", conn.dataSent, total)
	}
}

func TestQUICUniPeerCreditStartupAndResume(t *testing.T) {
	for _, fixture := range []struct {
		name    string
		present bool
		credit  uint64
	}{
		{"omitted", false, 0},
		{"zero", true, 0},
		{"one", true, 1},
		{"exact_control", true, 12},
		{"ordinary", true, 1 << 20},
		{"largest_varint", true, 1<<62 - 1},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			conn := uniCreditConn(t)
			params := append(uniCreditParam(4, 1<<20), uniCreditParam(5, 23)...)
			if fixture.present {
				params = append(params, uniCreditParam(7, fixture.credit)...)
			}
			uniCreditApply(t, conn, params)
			uniCreditCongested(t, conn)
			newH3Conn(conn).start()
			var held []*QUICStream
			for _, id := range []uint64{3, 7, 11} {
				stream := conn.acquireStream(id)
				if stream == nil {
					t.Fatalf("startup did not publish stream %d", id)
				}
				held = append(held, stream)
			}
			t.Cleanup(func() {
				conn.close()
				for _, stream := range held {
					conn.releaseStream(stream)
				}
			})
			uniCreditCheck(t, conn, fixture.credit)
			if fixture.credit >= 12 {
				return
			}
			var packetNumber uint64
			update := func(id, credit uint64) {
				conn.processFrames(quicSpaceAppData, packetNumber, quicAppendMaxStreamDataFrame(nil, id, credit))
				if conn.recvLargest[quicSpaceAppData] != int64(packetNumber) {
					t.Fatalf("MAX_STREAM_DATA packet %d was not processed", packetNumber)
				}
				packetNumber++
				uniCreditCongested(t, conn)
			}
			for _, id := range []uint64{3, 7, 11} {
				update(id, 12)
			}
			uniCreditCheck(t, conn, 12)
			for _, credit := range []uint64{12, 1, 0} {
				for _, id := range []uint64{3, 7, 11} {
					update(id, credit)
				}
				uniCreditCheck(t, conn, 12)
			}
		})
	}
}

func uniCreditLocalGrant(conn *QUICConn) uint64 {
	stream := conn.openLocalUniStream()
	grant := stream.maxSend
	conn.releaseStream(stream)
	return grant
}

func TestQUICUniPeerCreditIndependentOfBidiCredit(t *testing.T) {
	for _, credit := range []uint64{0, 5, 1 << 21} {
		conn := uniCreditConn(t)
		uniCreditApply(t, conn, append(uniCreditParam(5, 29), uniCreditParam(7, credit)...))
		if got := uniCreditLocalGrant(conn); got != credit {
			t.Errorf("uni grant %d: local uni stream credit=%d", credit, got)
		}
		pooled := getPooledStream(0, conn)
		if pooled.maxSend != 29 {
			t.Errorf("uni grant %d: peer bidi stream credit=%d, want 29", credit, pooled.maxSend)
		}
		pooled.refCount.Store(1)
		conn.releaseStream(pooled)
	}
}

func TestQUICUniPeerCreditResetAndZeroAssignment(t *testing.T) {
	conn := uniCreditConn(t)
	var parsed ParsedClientHello
	uniCreditParse(t, &parsed, uniCreditParam(7, 19))
	conn.applyPeerTransportParams(&parsed)
	if got := uniCreditLocalGrant(conn); got != 19 {
		t.Fatalf("parsed positive uni grant=%d, want 19", got)
	}
	uniCreditParse(t, &parsed, nil)
	conn.applyPeerTransportParams(&parsed)
	if got := uniCreditLocalGrant(conn); got != 0 {
		t.Fatalf("reused parser omitted uni grant=%d, want 0", got)
	}
	uniCreditApply(t, conn, uniCreditParam(7, 37))
	uniCreditApply(t, conn, uniCreditParam(7, 0))
	if got := uniCreditLocalGrant(conn); got != 0 {
		t.Fatalf("explicit zero assignment uni grant=%d, want 0", got)
	}
}

func TestQUICUniPeerCreditRejectMalformedParameters(t *testing.T) {
	for _, params := range [][]byte{
		{7, 0},
		{7, 1, 0x40},
		{7, 2, 0},
		{7, 9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0},
		{7, 1, 0, 7, 1, 1},
	} {
		var parsed ParsedClientHello
		if err := ParseClientHello(quicTransportParamsClientHello(params), &parsed); err != nil {
			t.Fatal(err)
		}
		if !parsed.quicTP.invalid {
			t.Errorf("accepted malformed uni parameter %x", params)
		}
	}
}
