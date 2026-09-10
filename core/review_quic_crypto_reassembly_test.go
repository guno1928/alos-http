package core

import (
	"testing"
	"time"
)

func TestQUICCryptoReassemblyIsLinear(t *testing.T) {
	srv := New(Config{MaxConnsPerIP: -1})
	qc := newTestQUIC(srv)
	qc.tlsState = newQuicTLSState()
	total := int(quicMaxInitialCryptoBuf)
	msg := make([]byte, total)
	msg[0] = 1
	body := total - 4
	msg[1], msg[2], msg[3] = byte(body>>16), byte(body>>8), byte(body)
	start := time.Now()
	for off := 0; off < total-1; off++ {
		qc.handleCryptoFrame(quicSpaceInitial, quicCryptoFrame{offset: uint64(off), data: msg[off : off+1]})
	}
	elapsed := time.Since(start)
	if qc.cryptoContig[quicSpaceInitial] != total-1 {
		t.Fatalf("contiguous prefix %d, want %d", qc.cryptoContig[quicSpaceInitial], total-1)
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("%d one-byte CRYPTO frames took %v; reassembly rescans the whole buffer per frame", total, elapsed)
	}
}
