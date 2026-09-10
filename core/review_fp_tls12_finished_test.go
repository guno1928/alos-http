//go:build linux && amd64

package core

import (
	"crypto/sha256"
	"testing"
)

func TestTLS12BackendShortFinishedIsRejectedNotPanic(t *testing.T) {
	tr := &tlsTransport{
		state:    tls12ExpectFinished,
		hashFn:   sha256.New,
		master12: make([]byte, 48),
	}
	short := [][]byte{
		{tlsHSFinished, 0, 0, 12},
		{tlsHSFinished, 0, 0, 12, 1, 2, 3},
		{tlsHSFinished, 0, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
	}
	for i, plain := range short {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d: handle12Finished panicked on a %d-byte Finished from the backend: %v", i, len(plain), r)
				}
			}()
			if err := tr.handle12Finished(&backendConn{}, plain); err == nil {
				t.Fatalf("case %d: short Finished accepted", i)
			}
		}()
	}
}
