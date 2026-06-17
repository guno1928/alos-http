package core

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// serverHelloRandom extracts the 32-byte server_random from a built TLS 1.2
// ServerHello: 4-byte handshake header, 2-byte legacy_version, then random.
func serverHelloRandom(t *testing.T, sh []byte) []byte {
	t.Helper()
	const randomOffset = 6
	if len(sh) < randomOffset+32 {
		t.Fatalf("ServerHello too short: %d bytes", len(sh))
	}
	if sh[0] != 0x02 {
		t.Fatalf("not a ServerHello: handshake type 0x%02x", sh[0])
	}
	return sh[randomOffset : randomOffset+32]
}

// A 1.3-capable server negotiating 1.2 must stamp the RFC 8446 §4.1.3
// downgrade sentinel into the trailing 8 bytes of server_random.
func TestTLS12ServerHelloDowngradeSentinel(t *testing.T) {
	var serverRandom [32]byte
	if _, err := rand.Read(serverRandom[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	setTLS12DowngradeSentinel(serverRandom[:])

	sh := buildTLS12ServerHello(serverRandom[:], 0xc02b, "http/1.1")
	got := serverHelloRandom(t, sh)

	want := []byte{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01}
	if !bytes.Equal(got[24:32], want) {
		t.Fatalf("trailing 8 bytes = % x, want sentinel % x", got[24:32], want)
	}
}

// The leading 24 bytes must remain crypto-random: not all zero, and they must
// differ from run to run (the sentinel only clobbers the trailing 8).
func TestTLS12ServerHelloRandomLeadingBytes(t *testing.T) {
	build := func() []byte {
		var serverRandom [32]byte
		if _, err := rand.Read(serverRandom[:]); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		setTLS12DowngradeSentinel(serverRandom[:])
		return serverHelloRandom(t, buildTLS12ServerHello(serverRandom[:], 0xc02b, "http/1.1"))
	}

	first := build()
	second := build()

	var zero [24]byte
	if bytes.Equal(first[:24], zero[:]) {
		t.Fatal("leading 24 bytes are all zero; server_random is not random")
	}
	if bytes.Equal(first[:24], second[:24]) {
		t.Fatal("leading 24 bytes identical across runs; server_random is not random")
	}
}
