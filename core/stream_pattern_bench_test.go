//go:build linux && amd64

package core

import (
	"crypto/sha256"
	"testing"
)

var ciStreamPatternByte byte
var ciStreamPatternDigest [sha256.Size]byte

func BenchmarkCIStreamPatternFill(b *testing.B) {
	for _, size := range []struct {
		name  string
		bytes int
	}{
		{"32KiB", 32 << 10},
		{"1MiB", 1 << 20},
	} {
		b.Run(size.name, func(b *testing.B) {
			buffer := make([]byte, size.bytes)
			b.SetBytes(int64(len(buffer)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				fillStreamPattern(buffer, i*len(buffer))
			}
			ciStreamPatternByte = buffer[len(buffer)-1]
		})
	}
}

func BenchmarkCIStreamPatternControl(b *testing.B) {
	buffer := make([]byte, 1<<20)
	for i := range buffer {
		buffer[i] = byte(i*31 + i>>11)
	}
	b.SetBytes(int64(len(buffer)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciStreamPatternDigest = sha256.Sum256(buffer)
	}
}
