//go:build linux && amd64

package core

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

func zeroCreditParams(connection, bidi *uint64) []byte {
	params := []byte{15, 1, 2}
	if connection != nil {
		params = append(params, quicFixTPInt(4, *connection)...)
	}
	if bidi != nil {
		params = append(params, quicFixTPInt(5, *bidi)...)
	}
	return params
}

func zeroCreditParse(t *testing.T, parsed *ParsedClientHello, params []byte) {
	t.Helper()
	if err := ParseClientHello(quicTransportParamsClientHello(params), parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.quicTP.seen || parsed.quicTP.invalid || !parsed.quicTP.hasInitialSrcCID || !bytes.Equal(parsed.quicTP.initialSrcCID, []byte{2}) {
		t.Fatal("invalid fixture transport parameters")
	}
}

type zeroCreditFixture struct {
	conn         *QUICConn
	packetNumber uint64
	held         map[uint64]*QUICStream
	payloads     map[uint64]string
}

func newZeroCreditFixture(t *testing.T, params []byte) *zeroCreditFixture {
	t.Helper()
	server := New(Config{QUICMaxData: 73, QUICMaxStreamData: 37})
	conn := newQUICConn(server, nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}, []byte{1}, []byte{2})
	conn.pktBudget = 1200
	conn.loss.mu.Lock()
	conn.loss.bytesInFlight = int(conn.loss.cwnd)
	conn.loss.mu.Unlock()
	var parsed ParsedClientHello
	zeroCreditParse(t, &parsed, params)
	conn.applyPeerTransportParams(&parsed)
	conn.handshakeDone.Store(true)
	fixture := &zeroCreditFixture{conn: conn, held: make(map[uint64]*QUICStream), payloads: make(map[uint64]string)}
	t.Cleanup(func() {
		conn.close()
		for _, stream := range fixture.held {
			conn.releaseStream(stream)
		}
	})
	fixture.capturePreconditions(t)
	return fixture
}

func (fixture *zeroCreditFixture) capturePreconditions(t *testing.T) {
	t.Helper()
	if fixture.conn.loss.canSend() || fixture.conn.pktBudget != 1200 {
		t.Fatal("fixture permits packet draining or changed packet budget")
	}
	if fixture.conn.maxDataLocal != 73 {
		t.Fatalf("peer grant changed receive connection allowance to %d", fixture.conn.maxDataLocal)
	}
}

func (fixture *zeroCreditFixture) open(t *testing.T, id uint64, payload string) *QUICStream {
	t.Helper()
	if fixture.held[id] != nil {
		t.Fatalf("fixture already owns stream %d", id)
	}
	fixture.conn.handleStreamFrameIncoming(quicStreamFrame{streamID: id})
	stream := fixture.conn.acquireStream(id)
	if stream == nil {
		t.Fatalf("incoming client stream %d was not opened", id)
	}
	fixture.held[id] = stream
	fixture.payloads[id] = payload
	if stream.refCount.Load() != 2 || stream.recvWindow != 37 {
		t.Fatalf("stream %d references=%d receive window=%d, want 2/37", id, stream.refCount.Load(), stream.recvWindow)
	}
	if err := stream.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	fixture.capturePreconditions(t)
	fixture.conn.sendStreamData(stream)
	fixture.capturePreconditions(t)
	return stream
}

func (fixture *zeroCreditFixture) update(t *testing.T, frame []byte) {
	t.Helper()
	fixture.capturePreconditions(t)
	for id, stream := range fixture.held {
		if stream.refCount.Load() != 2 {
			t.Fatalf("stream %d references before MAX=%d", id, stream.refCount.Load())
		}
	}
	fixture.conn.processFrames(quicSpaceAppData, fixture.packetNumber, frame)
	if fixture.conn.closed.Load() || fixture.conn.recvLargest[quicSpaceAppData] != int64(fixture.packetNumber) {
		t.Fatalf("MAX packet %d was not accepted", fixture.packetNumber)
	}
	fixture.packetNumber++
	fixture.capturePreconditions(t)
	for id, stream := range fixture.held {
		if stream.refCount.Load() != 2 || fixture.conn.streams[id] != stream {
			t.Fatalf("MAX changed stream %d ownership: references=%d", id, stream.refCount.Load())
		}
	}
}

func (fixture *zeroCreditFixture) output(t *testing.T) map[uint64]string {
	t.Helper()
	fixture.capturePreconditions(t)
	output := make(map[uint64]string)
	if err := quicParseFrames(fixture.conn.coalesceBuf[fixture.conn.coalesceStart:], &quicFrameVisitor{onStream: func(frame quicStreamFrame) {
		if fixture.held[frame.streamID] == nil || frame.offset != uint64(len(output[frame.streamID])) || frame.fin {
			t.Fatalf("unexpected emitted stream=%d offset=%d fin=%v", frame.streamID, frame.offset, frame.fin)
		}
		output[frame.streamID] += string(frame.data)
	}}); err != nil {
		t.Fatal(err)
	}
	var total uint64
	for id, stream := range fixture.held {
		emitted, payload := output[id], fixture.payloads[id]
		if len(emitted) > len(payload) || emitted != payload[:len(emitted)] || string(stream.sendBuf) != payload[len(emitted):] || stream.sendOff != uint64(len(emitted)) {
			t.Fatalf("stream %d emitted=%q pending=%q offset=%d, payload=%q", id, emitted, stream.sendBuf, stream.sendOff, payload)
		}
		total += uint64(len(emitted))
	}
	if fixture.conn.dataSent != total {
		t.Fatalf("connection dataSent=%d, emitted bytes=%d", fixture.conn.dataSent, total)
	}
	return output
}

func (fixture *zeroCreditFixture) want(t *testing.T, expected map[uint64]string) {
	t.Helper()
	output := fixture.output(t)
	for id, want := range expected {
		if output[id] != want {
			t.Errorf("stream %d output=%q, want %q", id, output[id], want)
		}
	}
}

func TestQUICZeroPeerConnectionCredit(t *testing.T) {
	for _, fixture := range []struct {
		name    string
		present bool
		credit  uint64
		want    string
	}{
		{"omitted", false, 0, ""},
		{"zero", true, 0, ""},
		{"small", true, 2, "he"},
		{"exact", true, 5, "hello"},
		{"large", true, 1<<62 - 1, "hello"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			streamCredit := uint64(19)
			var connectionCredit *uint64
			if fixture.present {
				connectionCredit = &fixture.credit
			}
			peer := newZeroCreditFixture(t, zeroCreditParams(connectionCredit, &streamCredit))
			peer.open(t, 0, "hello")
			peer.want(t, map[uint64]string{0: fixture.want})
			if peer.conn.maxDataRemote != fixture.credit {
				t.Errorf("effective connection grant=%d, want %d", peer.conn.maxDataRemote, fixture.credit)
			}
			if fixture.credit < 5 {
				peer.update(t, quicAppendMaxDataFrame(nil, 5))
				peer.want(t, map[uint64]string{0: "hello"})
			}
		})
	}
}

func TestQUICZeroPeerBidiCredit(t *testing.T) {
	for _, fixture := range []struct {
		name    string
		present bool
		credit  uint64
		want    string
	}{
		{"omitted", false, 0, ""},
		{"zero", true, 0, ""},
		{"small", true, 2, "he"},
		{"exact", true, 5, "hello"},
		{"large", true, 1<<62 - 1, "hello"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			connectionCredit := uint64(61)
			var streamCredit *uint64
			if fixture.present {
				streamCredit = &fixture.credit
			}
			peer := newZeroCreditFixture(t, zeroCreditParams(&connectionCredit, streamCredit))
			stream := peer.open(t, 0, "hello")
			peer.want(t, map[uint64]string{0: fixture.want})
			if stream.maxSend != fixture.credit {
				t.Errorf("effective bidi grant=%d, want %d", stream.maxSend, fixture.credit)
			}
			if fixture.credit < 5 {
				peer.update(t, quicAppendMaxStreamDataFrame(nil, 0, 5))
				peer.want(t, map[uint64]string{0: "hello"})
			}
		})
	}
}

func TestQUICZeroPeerBudgetsResumeIndependently(t *testing.T) {
	zero := uint64(0)
	peer := newZeroCreditFixture(t, zeroCreditParams(&zero, &zero))
	stream := peer.open(t, 0, "hello")
	peer.want(t, map[uint64]string{0: ""})
	peer.update(t, quicAppendMaxDataFrame(nil, 2))
	peer.want(t, map[uint64]string{0: ""})
	peer.update(t, quicAppendMaxStreamDataFrame(nil, 0, 2))
	peer.want(t, map[uint64]string{0: "he"})
	peer.update(t, quicAppendMaxDataFrame(nil, 5))
	peer.want(t, map[uint64]string{0: "he"})
	peer.update(t, quicAppendMaxStreamDataFrame(nil, 0, 5))
	peer.want(t, map[uint64]string{0: "hello"})
	for _, limit := range []uint64{5, 1, 0} {
		peer.update(t, quicAppendMaxDataFrame(nil, limit))
		peer.update(t, quicAppendMaxStreamDataFrame(nil, 0, limit))
		peer.want(t, map[uint64]string{0: "hello"})
		if peer.conn.maxDataRemote != 5 || stream.maxSend != 5 {
			t.Fatalf("MAX retracted credit: connection=%d stream=%d", peer.conn.maxDataRemote, stream.maxSend)
		}
	}
}

func TestQUICZeroPeerSharedConnectionCredit(t *testing.T) {
	connectionCredit, streamCredit := uint64(0), uint64(19)
	peer := newZeroCreditFixture(t, zeroCreditParams(&connectionCredit, &streamCredit))
	peer.open(t, 0, "abc")
	peer.open(t, 4, "XYZ")
	peer.want(t, map[uint64]string{0: "", 4: ""})
	peer.update(t, quicAppendMaxDataFrame(nil, 5))
	peer.output(t)
	if peer.conn.dataSent != 5 {
		t.Fatalf("shared credit sent=%d, want exactly 5", peer.conn.dataSent)
	}
	peer.update(t, quicAppendMaxDataFrame(nil, 6))
	peer.want(t, map[uint64]string{0: "abc", 4: "XYZ"})
	if peer.conn.dataSent != 6 {
		t.Fatalf("resumed shared credit sent=%d, want 6", peer.conn.dataSent)
	}
}

func TestQUICZeroPeerCreditReusedParse(t *testing.T) {
	connectionCredit, streamCredit := uint64(19), uint64(23)
	peer := newZeroCreditFixture(t, zeroCreditParams(&connectionCredit, &streamCredit))
	var parsed ParsedClientHello
	zeroCreditParse(t, &parsed, zeroCreditParams(&connectionCredit, &streamCredit))
	zeroCreditParse(t, &parsed, zeroCreditParams(nil, nil))
	peer.conn.applyPeerTransportParams(&parsed)
	if peer.conn.maxDataRemote != 0 || peer.conn.peerStreamWindow != 0 {
		t.Errorf("omitted grants preserved stale credit: connection=%d bidi=%d", peer.conn.maxDataRemote, peer.conn.peerStreamWindow)
	}
	peer.open(t, 0, "hello")
	peer.want(t, map[uint64]string{0: ""})
}

func TestQUICZeroPeerCreditIncomingBidiStreams(t *testing.T) {
	peer := newZeroCreditFixture(t, zeroCreditParams(nil, nil))
	for _, id := range []uint64{0, 4} {
		stream := peer.open(t, id, "")
		if stream.maxSend != 0 {
			t.Errorf("incoming client bidi ID %d grant=%d, want 0", id, stream.maxSend)
		}
	}
}

func TestQUICZeroPeerCreditCloseRetainsCaller(t *testing.T) {
	peer := newZeroCreditFixture(t, zeroCreditParams(nil, nil))
	stream := peer.open(t, 0, "hello")
	peer.want(t, map[uint64]string{0: ""})
	peer.update(t, quicAppendMaxDataFrame(nil, 5))
	peer.want(t, map[uint64]string{0: ""})
	peer.conn.close()
	if !peer.conn.closed.Load() || !stream.sendClosed || !stream.recvClosed || stream.conn != peer.conn || stream.refCount.Load() < 1 {
		t.Fatal("close invalidated the held caller or left stream open")
	}
	if err := stream.Write([]byte("more")); !errors.Is(err, ErrStreamClosed) {
		t.Fatalf("write after close=%v", err)
	}
	if peer.conn.dataSent != 0 {
		t.Errorf("closed zero-credit stream counted %d sent bytes", peer.conn.dataSent)
	}
}
