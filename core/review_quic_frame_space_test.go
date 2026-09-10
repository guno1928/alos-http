package core

import "testing"

func TestQUICStreamFrameInInitialPacketIsRejected(t *testing.T) {
	srv := New(Config{MaxConnsPerIP: -1})
	qc := newTestQUIC(srv)
	streamFrame := quicAppendStreamFrame(nil, 0, 0, []byte("GET"), true)
	var sawStream bool
	v := &quicFrameVisitor{
		onStream: func(f quicStreamFrame) { sawStream = true },
		allowed:  quicFrameAllowedInHandshakeSpaces,
	}
	if err := quicParseFrames(streamFrame, v); err != errQUICFrameNotAllowedInSpace {
		t.Fatalf("STREAM in Initial space: err=%v, want frame-not-allowed", err)
	}
	if sawStream {
		t.Fatal("STREAM frame from an Initial packet reached the stream handler")
	}
	qc.processFrames(quicSpaceInitial, 1, streamFrame)
	if !qc.closed.Load() {
		t.Fatal("connection stayed open after a STREAM frame arrived in an Initial packet")
	}
	if _, ok := qc.streams[0]; ok {
		t.Fatal("stream 0 was created from an Initial-space STREAM frame")
	}
}

func TestQUICHandshakeSpaceStillAcceptsCryptoAndAck(t *testing.T) {
	for _, ft := range []uint64{quicFramePadding, quicFramePing, quicFrameACK, quicFrameACKECN, quicFrameCrypto, quicFrameConnClose} {
		if !quicFrameAllowedInHandshakeSpaces(ft) {
			t.Fatalf("frame %#x must be allowed in Initial/Handshake", ft)
		}
	}
	for _, ft := range []uint64{quicFrameStream, quicFrameStreamEnd, quicFrameMaxData, quicFrameMaxStreamData, quicFrameNewConnID, quicFrameHandshakeDone, quicFrameAppClose} {
		if quicFrameAllowedInHandshakeSpaces(ft) {
			t.Fatalf("frame %#x must not be allowed in Initial/Handshake", ft)
		}
	}
}
