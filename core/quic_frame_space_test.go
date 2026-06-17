package core

import "testing"

// newTestQUICConn builds a minimal server-side QUICConn suitable for exercising
// processFrames without any live UDP socket or TLS state. No keys are installed,
// so any outbound CONNECTION_CLOSE is a no-op and only the local teardown
// (qc.close) is observable.
func newTestQUICConn() *QUICConn {
	return newQUICConn(nil, nil, nil, []byte("origdcid"), []byte("scid1234"))
}

func TestProcessFramesRejectsStreamInInitialSpace(t *testing.T) {
	qc := newTestQUICConn()

	frames := quicAppendStreamFrame(nil, 0, 0, []byte("hello"), true)
	qc.processFrames(quicSpaceInitial, 0, frames)

	if !qc.closed.Load() {
		t.Fatal("STREAM frame in Initial space must trigger PROTOCOL_VIOLATION close")
	}
}

func TestProcessFramesRejectsStreamInHandshakeSpace(t *testing.T) {
	qc := newTestQUICConn()

	frames := quicAppendStreamFrame(nil, 0, 0, []byte("hello"), true)
	qc.processFrames(quicSpaceHandshake, 0, frames)

	if !qc.closed.Load() {
		t.Fatal("STREAM frame in Handshake space must trigger PROTOCOL_VIOLATION close")
	}
}

func TestProcessFramesAcceptsCryptoInInitialSpace(t *testing.T) {
	qc := newTestQUICConn()

	frames := quicAppendCryptoFrame(nil, 0, []byte("\x01\x00\x00\x00"))
	qc.processFrames(quicSpaceInitial, 0, frames)

	if qc.closed.Load() {
		t.Fatal("CRYPTO frame in Initial space must be accepted, not closed")
	}
}

func TestProcessFramesRejectsHandshakeDoneOnServer(t *testing.T) {
	qc := newTestQUICConn()

	// HANDSHAKE_DONE is permitted in the application space, but only
	// server->client; a server receiving it is a protocol violation.
	frames := quicAppendHandshakeDoneFrame(nil)
	qc.processFrames(quicSpaceAppData, 0, frames)

	if !qc.closed.Load() {
		t.Fatal("HANDSHAKE_DONE received by server must trigger PROTOCOL_VIOLATION close")
	}
}

func TestProcessFramesRejectsMaxDataInInitialSpace(t *testing.T) {
	qc := newTestQUICConn()

	frames := quicAppendMaxDataFrame(nil, 1<<20)
	qc.processFrames(quicSpaceInitial, 0, frames)

	if !qc.closed.Load() {
		t.Fatal("MAX_DATA frame in Initial space must trigger PROTOCOL_VIOLATION close")
	}
}

func TestFrameAllowedInSpaceMatrix(t *testing.T) {
	initialAndHandshakeAllowed := []uint64{
		quicFramePadding, quicFramePing, quicFrameACK, quicFrameACKECN,
		quicFrameCrypto, quicFrameConnClose,
	}
	for _, ft := range initialAndHandshakeAllowed {
		if !quicFrameAllowedInSpace(quicSpaceInitial, ft) {
			t.Errorf("frame 0x%x must be allowed in Initial space", ft)
		}
		if !quicFrameAllowedInSpace(quicSpaceHandshake, ft) {
			t.Errorf("frame 0x%x must be allowed in Handshake space", ft)
		}
	}

	disallowed := []uint64{
		quicFrameStream, quicFrameMaxData, quicFrameMaxStreamData,
		quicFrameNewConnID, quicFrameHandshakeDone, quicFrameResetStream,
		quicFrameStopSending, quicFrameNewToken, quicFramePathChallenge,
		quicFramePathResponse, quicFrameAppClose,
	}
	for _, ft := range disallowed {
		if quicFrameAllowedInSpace(quicSpaceInitial, ft) {
			t.Errorf("frame 0x%x must NOT be allowed in Initial space", ft)
		}
		if quicFrameAllowedInSpace(quicSpaceHandshake, ft) {
			t.Errorf("frame 0x%x must NOT be allowed in Handshake space", ft)
		}
		// Application space permits every frame type.
		if !quicFrameAllowedInSpace(quicSpaceAppData, ft) {
			t.Errorf("frame 0x%x must be allowed in Application space", ft)
		}
	}
}
