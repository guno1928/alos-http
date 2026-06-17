package core

import (
	"errors"
	"testing"
)

func buildClientHelloWithSessionID(sidLen int) []byte {
	ch := make([]byte, 0, 2+32+1+sidLen)
	ch = append(ch, 0x03, 0x03) // legacy_version TLS 1.2
	ch = append(ch, make([]byte, 32)...)
	ch = append(ch, byte(sidLen))
	ch = append(ch, make([]byte, sidLen)...)
	msgLen := len(ch)
	data := []byte{0x01, byte(msgLen >> 16), byte(msgLen >> 8), byte(msgLen)}
	return append(data, ch...)
}

// TestParseClientHelloRejectsOversizedSessionID ensures an attacker-supplied
// legacy_session_id longer than 32 bytes is rejected at the boundary rather
// than triggering an out-of-range slice panic (sessionIDBuf is [32]byte).
func TestParseClientHelloRejectsOversizedSessionID(t *testing.T) {
	for _, sidLen := range []int{33, 64, 255} {
		data := buildClientHelloWithSessionID(sidLen)
		var result ParsedClientHello
		err := ParseClientHello(data, &result) // must not panic
		if !errors.Is(err, ErrSessionIDTooLong) {
			t.Fatalf("sidLen=%d: err = %v, want ErrSessionIDTooLong", sidLen, err)
		}
	}
}

// TestParseClientHelloAcceptsMaxSessionID confirms a 32-byte session_id (the
// RFC maximum) is still accepted and copied through.
func TestParseClientHelloAcceptsMaxSessionID(t *testing.T) {
	data := buildClientHelloWithSessionID(32)
	var result ParsedClientHello
	err := ParseClientHello(data, &result)
	if errors.Is(err, ErrSessionIDTooLong) {
		t.Fatalf("32-byte session_id wrongly rejected: %v", err)
	}
	if len(result.SessionID) != 32 {
		t.Fatalf("SessionID len = %d, want 32", len(result.SessionID))
	}
}

// BenchmarkParseClientHelloSessionID guards the cost of the session_id parse
// path the bounds check sits on.
func BenchmarkParseClientHelloSessionID(b *testing.B) {
	data := buildClientHelloWithSessionID(32)
	var result ParsedClientHello
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseClientHello(data, &result)
	}
}
