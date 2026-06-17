package core

import (
	"errors"
	"testing"
)

// buildClientHelloWithSessionID constructs a minimal TLS ClientHello handshake
// message whose legacy_session_id field has the given length and that many
// session-id bytes actually present (so the parser reaches the reslice).
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
	// 32-byte session_id is valid; parsing then fails later (no cipher_suites),
	// but it must NOT fail on the session_id length and must not panic.
	if errors.Is(err, ErrSessionIDTooLong) {
		t.Fatalf("32-byte session_id wrongly rejected: %v", err)
	}
	if len(result.SessionID) != 32 {
		t.Fatalf("SessionID len = %d, want 32", len(result.SessionID))
	}
}
