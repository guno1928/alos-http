package core

import "testing"

// TestProxyResponseHasNoBody covers the RFC 9112 §6.3 body-disposition rule
// used to avoid blocking on a non-existent upstream body (which would stall to
// ReadTimeout and discard the pooled connection).
func TestProxyResponseHasNoBody(t *testing.T) {
	cases := []struct {
		method string
		status int
		want   bool
	}{
		{"HEAD", 200, true},
		{"HEAD", 404, true},
		{"GET", 204, true},
		{"GET", 304, true},
		{"GET", 100, true},
		{"GET", 101, true},
		{"GET", 199, true},
		{"GET", 200, false},
		{"GET", 404, false},
		{"POST", 201, false},
		{"GET", 203, false},
	}
	for _, c := range cases {
		if got := proxyResponseHasNoBody(c.method, c.status); got != c.want {
			t.Errorf("proxyResponseHasNoBody(%q, %d) = %v, want %v", c.method, c.status, got, c.want)
		}
	}
}

func BenchmarkProxyResponseHasNoBody(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = proxyResponseHasNoBody("GET", 200)
		_ = proxyResponseHasNoBody("HEAD", 200)
	}
}
