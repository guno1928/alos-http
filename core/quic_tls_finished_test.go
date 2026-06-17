package core

import (
	"testing"
)

// newTestFinishedState builds a quicTLSState advanced to the "waiting for
// client Finished" stage with a real cipher suite, a seeded transcript, and a
// client handshake secret, so handleClientFinished reaches the verify_data
// comparison.
func newTestFinishedState(t *testing.T) *quicTLSState {
	t.Helper()

	suite := NegotiateSuite([]uint16{0x1301}) // TLS_AES_128_GCM_SHA256
	if suite == nil {
		t.Fatal("expected suite 0x1301 to be supported")
	}

	ts := newQuicTLSState()
	ts.suite = suite
	ts.hashFn = suite.HashFn
	ts.hashLen = suite.HashLen
	ts.transcript = suite.HashFn()
	ts.transcript.Write([]byte("synthetic transcript through server Finished"))
	ts.clientHSSecret = make([]byte, suite.HashLen)
	for i := range ts.clientHSSecret {
		ts.clientHSSecret[i] = byte(i)
	}
	ts.stage = quicTLSStageWaitFinished
	return ts
}

// expectedClientFinished computes the verify_data the server expects, snapshot
// of the transcript so the caller's later Write does not perturb it.
func expectedClientFinished(ts *quicTLSState) []byte {
	finHash := ts.transcript.Sum(nil)
	return ts.suite.ComputeFinishedTo(ts.clientHSSecret, finHash, nil)
}

func TestHandleClientFinished_RejectsTamperedVerifyData(t *testing.T) {
	ts := newTestFinishedState(t)

	good := expectedClientFinished(ts)
	tampered := make([]byte, len(good))
	copy(tampered, good)
	tampered[len(tampered)-1] ^= 0x01 // flip one bit of an otherwise valid MAC

	qc := &QUICConn{} // success path is never reached, so a bare conn is safe
	ts.handleClientFinished(qc, BuildFinished(tampered))

	if ts.stage != quicTLSStageWaitFinished {
		t.Fatalf("tampered Finished advanced stage to %d; want %d (rejected)",
			ts.stage, quicTLSStageWaitFinished)
	}
	if qc.handshakeDone.Load() {
		t.Fatal("tampered Finished marked handshake done; want rejected")
	}
}

func TestHandleClientFinished_RejectsWrongLength(t *testing.T) {
	ts := newTestFinishedState(t)

	good := expectedClientFinished(ts)
	short := good[:len(good)-1] // truncated verify_data

	qc := &QUICConn{}
	ts.handleClientFinished(qc, BuildFinished(short))

	if ts.stage != quicTLSStageWaitFinished {
		t.Fatalf("short Finished advanced stage to %d; want %d (rejected)",
			ts.stage, quicTLSStageWaitFinished)
	}
	if qc.handshakeDone.Load() {
		t.Fatal("short Finished marked handshake done; want rejected")
	}
}
