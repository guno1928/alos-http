package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func newTestTrafficAEAD(t testing.TB) *TrafficAEAD {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{7}, 16))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &TrafficAEAD{aead: gcm, oh: gcm.Overhead(), nonceSize: 12, staticLen: 4}
}

func TestBuildTLS13AppDataRecordsSteadyStateZeroAlloc(t *testing.T) {
	w := newTestTrafficAEAD(t)
	for _, size := range []int{13, 16 << 10, 64 << 10, 256 << 10} {
		payload := bytes.Repeat([]byte{'x'}, size)
		dst := buildTLSAppDataRecords(nil, w, payload)
		got := testing.AllocsPerRun(50, func() {
			dst = buildTLSAppDataRecords(dst[:0], w, payload)
		})
		if got != 0 {
			t.Fatalf("payload %d: buildTLSAppDataRecords allocated %.1f/call in steady state, want 0", size, got)
		}
	}
}

func TestBuildTLS12AppDataRecordsSteadyStateZeroAlloc(t *testing.T) {
	w, _ := newTestTLS12Pair(t)
	for _, size := range []int{13, 16 << 10, 64 << 10, 256 << 10} {
		payload := bytes.Repeat([]byte{'y'}, size)
		dst := buildTLS12AppDataRecords(nil, w, payload)
		got := testing.AllocsPerRun(50, func() {
			dst = buildTLS12AppDataRecords(dst[:0], w, payload)
		})
		if got != 0 {
			t.Fatalf("payload %d: buildTLS12AppDataRecords allocated %.1f/call in steady state, want 0", size, got)
		}
	}
}

func TestEnsureTailCapGrowsGeometrically(t *testing.T) {
	b := make([]byte, 0, 8)
	b = ensureTailCap(b, 100)
	if cap(b) < 100 {
		t.Fatalf("cap after grow = %d, want >= 100", cap(b))
	}
	b = append(b, make([]byte, 60)...)
	firstCap := cap(b)
	b = ensureTailCap(b, firstCap)
	if cap(b) < 2*firstCap {
		t.Fatalf("cap after geometric grow = %d, want >= %d", cap(b), 2*firstCap)
	}
	full := b[:cap(b)]
	b = ensureTailCap(full, 0)
	if cap(b) != cap(full) {
		t.Fatalf("ensureTailCap with need=0 reallocated: cap %d -> %d", cap(full), cap(b))
	}
}

func TestBuildTLS13AppDataRecordsRoundTrip(t *testing.T) {
	w := newTestTrafficAEAD(t)
	r := newTestTrafficAEAD(t)
	for i, size := range []int{1, 16383, 16384, 100000} {
		payload := bytes.Repeat([]byte{byte('A' + i)}, size)
		rec := buildTLSAppDataRecords(nil, w, payload)
		var got []byte
		buf := rec
		for len(buf) > 0 {
			ct, inner, total, ok, err := nextTLSRecord(buf)
			if err != nil || !ok {
				t.Fatalf("size %d: nextTLSRecord ok=%v err=%v", size, ok, err)
			}
			if ct != 0x17 {
				t.Fatalf("size %d: outer type %#x", size, ct)
			}
			pt, err := r.Decrypt(inner)
			if err != nil {
				t.Fatalf("size %d: decrypt: %v", size, err)
			}
			got = append(got, pt[:len(pt)-1]...)
			buf = buf[total:]
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("size %d: round trip mismatch (got %d bytes)", size, len(got))
		}
	}
}
