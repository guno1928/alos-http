package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func newTestTLS12Pair(t testing.TB) (*tls12AEAD, *tls12AEAD) {
	t.Helper()
	key := bytes.Repeat([]byte{7}, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := []byte{1, 2, 3, 4}
	return &tls12AEAD{aead: gcm, iv: iv}, &tls12AEAD{aead: gcm, iv: iv}
}

func TestTLS12SealOpenRoundTrip(t *testing.T) {
	w, r := newTestTLS12Pair(t)
	for i := 0; i < 3; i++ {
		msg := bytes.Repeat([]byte{byte('a' + i)}, 1000+i)
		rec := buildTLS12AppDataRecords(nil, w, msg)
		typ, pt, ok := r.open(rec)
		if !ok || typ != 0x17 || !bytes.Equal(pt, msg) {
			t.Fatalf("round trip %d failed: ok=%v typ=%#x", i, ok, typ)
		}
	}
}

func BenchmarkTLS12SealRecord(b *testing.B) {
	w, _ := newTestTLS12Pair(b)
	msg := bytes.Repeat([]byte{'x'}, 1024)
	dst := make([]byte, 0, 2048)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dst = buildTLS12AppDataRecords(dst[:0], w, msg)
	}
}

func BenchmarkTLS12OpenRecord(b *testing.B) {
	w, r := newTestTLS12Pair(b)
	msg := bytes.Repeat([]byte{'x'}, 1024)
	rec := buildTLS12AppDataRecords(nil, w, msg)
	scratch := make([]byte, len(rec))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		copy(scratch, rec)
		r.seq = 0
		if _, _, ok := r.open(scratch); !ok {
			b.Fatal("open failed")
		}
	}
}
