//go:build amd64

package core

import (
	"bytes"
	"testing"
)

func indexCRLFCRLFStd(b []byte) int {
	return bytes.Index(b, []byte{'\r', '\n', '\r', '\n'})
}

func indexCRLF2Std(b []byte) int {
	return bytes.Index(b, []byte{'\r', '\n'})
}

var crlf2Data = []byte("Host: example.com\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n")

func TestCRLF2Equiv(t *testing.T) {
	inputs := [][]byte{
		crlf2Data, hbSmall, hbLarge, []byte("no crlf here"), []byte("\r\n"),
		[]byte(""), []byte("x"), []byte("\r"), []byte("a\rb\r\nc"),
		bytes.Repeat([]byte("A\r"), 40), []byte("aaaaaaaaaaaaaaa\r\n"),
	}
	for _, in := range inputs {
		want := indexCRLF2Std(in)
		if got := indexCRLF2Swar(in); got != want {
			t.Fatalf("SWAR=%d Std=%d for %q", got, want, in)
		}
		if got := indexCRLF2(in); got != want {
			t.Fatalf("dispatch=%d Std=%d for %q", got, want, in)
		}
	}
}

func BenchmarkCRLF2_Std(b *testing.B)  { for i := 0; i < b.N; i++ { crlfSink = indexCRLF2Std(crlf2Data) } }
func BenchmarkCRLF2_Swar(b *testing.B) { for i := 0; i < b.N; i++ { crlfSink = indexCRLF2Swar(crlf2Data) } }
func BenchmarkCRLF2_Asm(b *testing.B)  { for i := 0; i < b.N; i++ { crlfSink = indexCRLF2(crlf2Data) } }

func makeHeaderBlock(nHeaders int) []byte {
	var b []byte
	b = append(b, "GET / HTTP/1.1\r\n"...)
	for i := 0; i < nHeaders; i++ {
		b = append(b, "X-Some-Header-Name: some-header-value-here\r\n"...)
	}
	b = append(b, "\r\n"...)
	return b
}

var hbSmall = makeHeaderBlock(4)
var hbLarge = makeHeaderBlock(20)
var crlfSink int

func TestCRLFEquiv(t *testing.T) {
	inputs := [][]byte{
		hbSmall, hbLarge, makeHeaderBlock(0), makeHeaderBlock(1),
		[]byte("no terminator here at all"), []byte("\r\n\r\n"), []byte("a\r\n\r\nb"),
		[]byte(""), []byte("abc"), []byte("\r\n\r"), []byte("xxxxxxx\r\n\r\n"),
		[]byte("\r\r\r\r\n\r\n"), bytes.Repeat([]byte("A\r"), 40),
	}
	for _, in := range inputs {
		want := indexCRLFCRLFStd(in)
		if got := indexCRLFCRLFSwar(in); got != want {
			t.Fatalf("SWAR=%d Std=%d for %q", got, want, in)
		}
		if got := indexCRLFCRLF(in); got != want {
			t.Fatalf("dispatch=%d Std=%d for %q", got, want, in)
		}
	}
}

var eqData = []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
var eqSink bool

func TestEqualPrefix16(t *testing.T) {
	if !equalPrefix16(eqData, &rootPrefix16) {
		t.Fatal("equalPrefix16 false on matching data")
	}
	bad := append([]byte(nil), eqData...)
	for i := 0; i < 16; i++ {
		bad[i] ^= 0xFF
		if equalPrefix16(bad, &rootPrefix16) {
			t.Fatalf("equalPrefix16 true with corrupted byte %d", i)
		}
		bad[i] ^= 0xFF
	}
}

func BenchmarkEq16_Std(b *testing.B)  { for i := 0; i < b.N; i++ { eqSink = bytes.Equal(eqData[:16], rootPrefixBytes) } }
func BenchmarkEq16_Fast(b *testing.B) { for i := 0; i < b.N; i++ { eqSink = equalPrefix16(eqData, &rootPrefix16) } }

func BenchmarkCRLF_Std_Small(b *testing.B)  { for i := 0; i < b.N; i++ { crlfSink = indexCRLFCRLFStd(hbSmall) } }
func BenchmarkCRLF_Swar_Small(b *testing.B) { for i := 0; i < b.N; i++ { crlfSink = indexCRLFCRLFSwar(hbSmall) } }
func BenchmarkCRLF_Asm_Small(b *testing.B)  { for i := 0; i < b.N; i++ { crlfSink = indexCRLFCRLF(hbSmall) } }
func BenchmarkCRLF_Std_Large(b *testing.B)  { for i := 0; i < b.N; i++ { crlfSink = indexCRLFCRLFStd(hbLarge) } }
func BenchmarkCRLF_Swar_Large(b *testing.B) { for i := 0; i < b.N; i++ { crlfSink = indexCRLFCRLFSwar(hbLarge) } }
func BenchmarkCRLF_Asm_Large(b *testing.B)  { for i := 0; i < b.N; i++ { crlfSink = indexCRLFCRLF(hbLarge) } }
