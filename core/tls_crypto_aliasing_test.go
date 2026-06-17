package core

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestTrafficAEADInPlaceRoundTrip exercises the in-place (dst==src) AEAD path
// used by Encrypt/Decrypt for every negotiable suite and asserts the recovered
// plaintext is intact. Run under -race to catch aliasing-induced corruption.
func TestTrafficAEADInPlaceRoundTrip(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand: %v", err)
	}

	for i := range SupportedSuites {
		cs := &SupportedSuites[i]
		t.Run(suiteName(cs.ID), func(t *testing.T) {
			sender, err := NewTrafficAEAD(cs.HashFn, secret, cs)
			if err != nil {
				t.Fatalf("sender NewTrafficAEAD: %v", err)
			}
			receiver, err := NewTrafficAEAD(cs.HashFn, secret, cs)
			if err != nil {
				t.Fatalf("receiver NewTrafficAEAD: %v", err)
			}

			for _, ptLen := range []int{0, 1, 16, 17, 64, 1000} {
				want := make([]byte, ptLen)
				if _, err := rand.Read(want); err != nil {
					t.Fatalf("rand: %v", err)
				}

				// Encrypt seals in place into a buffer with tag headroom.
				ptBuf := make([]byte, ptLen, ptLen+sender.Overhead())
				copy(ptBuf, want)
				ct := sender.Encrypt(ptBuf)

				// Decrypt opens in place, mutating the ciphertext buffer.
				got, err := receiver.Decrypt(ct)
				if err != nil {
					t.Fatalf("len=%d Decrypt: %v", ptLen, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("len=%d in-place round-trip corrupted plaintext:\n got=%x\nwant=%x", ptLen, got, want)
				}
			}
		})
	}
}

// TestAEGISSuiteNotNegotiable guards the H9 fix: the non-standard AEGIS suite
// (0x1306) must never be offered, negotiated, or resolvable.
func TestAEGISSuiteNotNegotiable(t *testing.T) {
	const aegisID = 0x1306

	for i := range SupportedSuites {
		if SupportedSuites[i].ID == aegisID {
			t.Fatalf("AEGIS suite 0x%04x must not be in SupportedSuites", aegisID)
		}
	}

	if cs := NegotiateSuite([]uint16{aegisID}); cs != nil {
		t.Fatalf("NegotiateSuite selected AEGIS 0x%04x; got suite 0x%04x", aegisID, cs.ID)
	}

	if cs := FindSuiteByID(aegisID); cs != nil {
		t.Fatalf("FindSuiteByID resolved AEGIS 0x%04x", aegisID)
	}
}

func suiteName(id uint16) string {
	switch id {
	case 0x1301:
		return "AES_128_GCM"
	case 0x1302:
		return "AES_256_GCM"
	case 0x1303:
		return "CHACHA20_POLY1305"
	default:
		return "unknown"
	}
}
