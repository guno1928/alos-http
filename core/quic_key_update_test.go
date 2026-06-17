package core

import (
	"crypto/sha256"
	"hash"
	"testing"
)

// buildIncomingAppPacket encrypts a 1-RTT short-header packet the way a peer
// would: AEAD with the given generation's key/iv, header protection with the
// (never-rotated) base hp, and the supplied key phase bit.
func buildIncomingAppPacket(t *testing.T, dcid []byte, aeadKeys *quicKeys, baseHP headerProtector, pn uint64, keyPhase uint8) []byte {
	t.Helper()
	// Pad the payload so the packet is long enough for the 16-byte header
	// protection sample taken at pnOffset+4.
	var frames []byte
	for i := 0; i < 16; i++ {
		frames = append(frames, 0x00) // PADDING
	}
	frames = quicAppendPingFrame(frames)

	k := *aeadKeys
	k.hp = baseHP
	return quicBuildShortPacket(nil, dcid, frames, pn, -1, &k, keyPhase)
}

func newTestAppConn(t *testing.T) (*QUICConn, *quicKeys, []byte, func() hash.Hash, *CipherSuiteConfig) {
	t.Helper()
	h := sha256.New
	cs := FindSuiteByID(0x1301)
	if cs == nil {
		t.Fatal("suite 0x1301 not found")
	}

	clientSecret0 := make([]byte, 32)
	serverSecret0 := make([]byte, 32)
	for i := range clientSecret0 {
		clientSecret0[i] = byte(i + 1)
		serverSecret0[i] = byte(0x80 + i)
	}

	recv0, err := quicDeriveKeys(h, clientSecret0, cs)
	if err != nil {
		t.Fatalf("derive recv keys: %v", err)
	}
	send0, err := quicDeriveKeys(h, serverSecret0, cs)
	if err != nil {
		t.Fatalf("derive send keys: %v", err)
	}

	qc := &QUICConn{
		srcCIDLen:       8,
		loss:            newQuicLossState(),
		streams:         make(map[uint64]*QUICStream),
		done:            make(chan struct{}),
		maxDataLocal:    quicInitialMaxData,
		maxDataRemote:   quicInitialMaxData,
		clientAppSecret: append([]byte(nil), clientSecret0...),
		serverAppSecret: append([]byte(nil), serverSecret0...),
		keyUpdateHash:   h,
		keyUpdateSuite:  cs,
	}
	copy(qc.srcConnID[:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	qc.recvLargest[0], qc.recvLargest[1], qc.recvLargest[2] = -1, -1, -1
	qc.keys[quicSpaceAppData] = recv0
	qc.sendKeys[quicSpaceAppData] = send0
	qc.handshakeDone.Store(true)

	return qc, recv0, clientSecret0, h, cs
}

func TestQUICKeyUpdateReceive(t *testing.T) {
	qc, recv0, clientSecret0, h, cs := newTestAppConn(t)
	dcid := qc.srcCID()
	baseHP := recv0.hp

	// 1. Current-phase (phase 0) packet decrypts and advances recvLargest.
	pkt0 := buildIncomingAppPacket(t, dcid, recv0, baseHP, 0, 0)
	qc.handleShortHeaderPacket(pkt0)
	if qc.recvLargest[quicSpaceAppData] != 0 {
		t.Fatalf("phase-0 packet not processed: recvLargest=%d", qc.recvLargest[quicSpaceAppData])
	}
	if qc.appKeyPhase != 0 {
		t.Fatalf("appKeyPhase changed unexpectedly: %d", qc.appKeyPhase)
	}

	// 2. A phase-1 packet (peer key update) must be decrypted with the derived
	// next-generation keys and commit the update on both receive and send sides.
	clientSecret1 := quicNextKeyUpdateSecret(h, clientSecret0)
	recv1, err := quicDeriveKeys(h, clientSecret1, cs)
	if err != nil {
		t.Fatalf("derive gen1: %v", err)
	}
	pkt1 := buildIncomingAppPacket(t, dcid, recv1, baseHP, 1, 1)
	qc.handleShortHeaderPacket(pkt1)
	if qc.appKeyPhase != 1 {
		t.Fatalf("key update not committed: appKeyPhase=%d", qc.appKeyPhase)
	}
	if qc.recvLargest[quicSpaceAppData] != 1 {
		t.Fatalf("phase-1 packet not processed: recvLargest=%d", qc.recvLargest[quicSpaceAppData])
	}
	if qc.sendKeyPhase != 1 {
		t.Fatalf("send keys not rolled to new phase: sendKeyPhase=%d", qc.sendKeyPhase)
	}
	if qc.prevRecvKeys == nil {
		t.Fatal("previous-generation keys not retained")
	}

	// 3. A reordered phase-0 packet that arrives after the update must still be
	// decryptable via the retained previous keys, without rotating again.
	pkt0Late := buildIncomingAppPacket(t, dcid, recv0, baseHP, 2, 0)
	qc.handleShortHeaderPacket(pkt0Late)
	if qc.recvLargest[quicSpaceAppData] != 2 {
		t.Fatalf("reordered phase-0 packet dropped: recvLargest=%d", qc.recvLargest[quicSpaceAppData])
	}
	if qc.appKeyPhase != 1 {
		t.Fatalf("reordered old packet wrongly rotated keys: appKeyPhase=%d", qc.appKeyPhase)
	}
}

// TestQUICKeyUpdateRejectsForgedPhaseFlip ensures a packet that flips the key
// phase but cannot be decrypted by the next-generation keys is dropped and does
// not rotate keys.
func TestQUICKeyUpdateRejectsForgedPhaseFlip(t *testing.T) {
	qc, recv0, _, _, _ := newTestAppConn(t)
	dcid := qc.srcCID()

	// Encrypt with the WRONG keys (current gen) but set the new-phase bit.
	forged := buildIncomingAppPacket(t, dcid, recv0, recv0.hp, 5, 1)
	qc.handleShortHeaderPacket(forged)

	if qc.appKeyPhase != 0 {
		t.Fatalf("forged phase flip rotated keys: appKeyPhase=%d", qc.appKeyPhase)
	}
	if qc.prevRecvKeys != nil {
		t.Fatal("forged phase flip retained previous keys (should not have rotated)")
	}
}
