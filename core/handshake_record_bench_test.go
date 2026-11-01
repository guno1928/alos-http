//go:build linux && amd64

package core

import (
	"io"
	"testing"
)

func benchmarkAppendRecord(b *testing.B, size int) {
	payload := make([]byte, size)
	dst := make([]byte, 0, size+2*tlsRecordHeaderLen)
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = AppendRecord(dst[:0], tlsRecHandshake, payload)
	}
}

func BenchmarkAppendRecordServerHello(b *testing.B) { benchmarkAppendRecord(b, 122) }

func BenchmarkAppendRecordCertificate(b *testing.B) { benchmarkAppendRecord(b, 3000) }

func BenchmarkBuildRedirectResponse(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = io.Discard.Write(buildRedirectResponse("https://example.test/some/path"))
	}
}
