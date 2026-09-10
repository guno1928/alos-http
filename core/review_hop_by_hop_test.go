package core

import "testing"

func TestHopByHopMatchersAgree(t *testing.T) {
	names := []string{"connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection", "proxy-authenticate", "proxy-authorization"}
	for _, n := range names {
		if !isHopByHopStr(n) || !isHopByHopBytes([]byte(n)) || !isHopByHopFold(n) {
			t.Fatalf("%q must be hop-by-hop in every matcher", n)
		}
		upper := []byte(n)
		for i := range upper {
			if upper[i] >= 'a' && upper[i] <= 'z' {
				upper[i] -= 'a' - 'A'
			}
		}
		if !isHopByHopFold(string(upper)) {
			t.Fatalf("%q not matched case-insensitively", upper)
		}
	}
	for _, n := range []string{"content-length", "host", "content-type", "x-forwarded-for", "tee", "trailers"} {
		if isHopByHopStr(n) || isHopByHopBytes([]byte(n)) || isHopByHopFold(n) {
			t.Fatalf("%q wrongly treated as hop-by-hop", n)
		}
	}
}

func BenchmarkHopByHopBytes(b *testing.B) {
	name := []byte("content-type")
	for i := 0; i < b.N; i++ {
		if isHopByHopBytes(name) {
			b.Fatal("unexpected")
		}
	}
}

func BenchmarkHopByHopBytesLengthHit(b *testing.B) {
	name := []byte("connection")
	for i := 0; i < b.N; i++ {
		if !isHopByHopBytes(name) {
			b.Fatal("unexpected")
		}
	}
}
