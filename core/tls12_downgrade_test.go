package core

import (
	"bytes"
	"testing"
)

// TestTLS12DowngradeSentinelValue pins the RFC 8446 §4.1.3 sentinel bytes.
func TestTLS12DowngradeSentinelValue(t *testing.T) {
	want := []byte{0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01} // "DOWNGRD\x01"
	if !bytes.Equal(tls12DowngradeSentinel[:], want) {
		t.Fatalf("sentinel = %x, want %x", tls12DowngradeSentinel[:], want)
	}
}

// TestTLS12ServerHelloCarriesDowngradeSentinel verifies a serverRandom whose
// last 8 bytes hold the sentinel lands at the correct offset in ServerHello.random.
func TestTLS12ServerHelloCarriesDowngradeSentinel(t *testing.T) {
	var sr [32]byte
	for i := range sr {
		sr[i] = byte(i)
	}
	copy(sr[24:32], tls12DowngradeSentinel[:])

	sh := buildTLS12ServerHello(sr[:], 0xc02f, "http/1.1")
	// tls12Handshake prepends a 4-byte handshake header; body = 2 bytes version
	// then 32 bytes random, so random is sh[6:38] and its last 8 bytes (the
	// downgrade sentinel) are sh[30:38].
	if len(sh) < 38 {
		t.Fatalf("ServerHello too short: %d", len(sh))
	}
	if !bytes.Equal(sh[30:38], tls12DowngradeSentinel[:]) {
		t.Fatalf("downgrade sentinel not at random[24:32]: got %x", sh[30:38])
	}
}

func BenchmarkBuildTLS12ServerHello(b *testing.B) {
	var sr [32]byte
	copy(sr[24:32], tls12DowngradeSentinel[:])
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildTLS12ServerHello(sr[:], 0xc02f, "http/1.1")
	}
}
