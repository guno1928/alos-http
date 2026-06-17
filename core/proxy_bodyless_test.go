package core

import "testing"

// TestProxyResponseHasNoBody covers the RFC 9112 §6.3 body-disposition rule
// used to avoid blocking on a non-existent upstream body (which would stall
// to ReadTimeout and discard the connection).
func TestProxyResponseHasNoBody(t *testing.T) {
	cases := []struct {
		method string
		status int
		want   bool
	}{
		{"HEAD", 200, true},  // HEAD response never has a body
		{"HEAD", 404, true},  // even with an error status
		{"GET", 204, true},   // No Content
		{"GET", 304, true},   // Not Modified
		{"GET", 100, true},   // Continue (1xx)
		{"GET", 101, true},   // Switching Protocols (1xx)
		{"GET", 199, true},   // upper 1xx boundary
		{"GET", 200, false},  // normal body-bearing response
		{"GET", 404, false},  // error responses do carry a body
		{"POST", 201, false}, // Created with a body
		{"GET", 203, false},  // 2xx other than 204 carry a body
	}
	for _, c := range cases {
		if got := proxyResponseHasNoBody(c.method, c.status); got != c.want {
			t.Errorf("proxyResponseHasNoBody(%q, %d) = %v, want %v", c.method, c.status, got, c.want)
		}
	}
}
