package core

import "testing"

// TestProxyFilterStripsClientForwardingHeaders verifies that client-supplied
// forwarding headers are dropped from outbound proxy requests so the single
// proxy-appended X-Forwarded-For is authoritative (H4: IP spoofing).
func TestProxyFilterStripsClientForwardingHeaders(t *testing.T) {
	filtered := []string{
		"x-forwarded-for", "X-Forwarded-For", "X-FORWARDED-FOR",
		"x-real-ip", "X-Real-IP", "X-REAL-IP",
		"forwarded", "Forwarded", "FORWARDED",
	}
	for _, name := range filtered {
		if !isProxyFilteredHeaderFold(name) {
			t.Errorf("isProxyFilteredHeaderFold(%q) = false, want true (spoofable forwarding header must be stripped)", name)
		}
	}

	// Unrelated headers and the proxy's own additions must survive the filter.
	notFiltered := []string{
		"x-request-id", "x-forwarded-host", "x-forwarded-proto",
		"authorization", "cookie", "user-agent", "accept", "referer",
	}
	for _, name := range notFiltered {
		if isProxyFilteredHeaderFold(name) {
			t.Errorf("isProxyFilteredHeaderFold(%q) = true, want false (legitimate header dropped)", name)
		}
	}
}

// TestProxyDropsSpoofedXFF asserts a spoofed inbound X-Forwarded-For never
// reaches the backend and that the proxy substitutes its own value derived
// from RemoteAddr.
func TestProxyDropsSpoofedXFF(t *testing.T) {
	req := &Request{
		Method:     "GET",
		Path:       "/",
		RemoteAddr: "203.0.113.7:54321",
		Headers: [][2]string{
			{"X-Forwarded-For", "10.0.0.1"},
			{"X-Real-IP", "10.0.0.1"},
			{"Forwarded", "for=10.0.0.1"},
		},
	}

	out := string(buildProxyRequest(nil, req, "backend.internal:80", &DomainConfig{}))

	if contains(out, "10.0.0.1") {
		t.Fatalf("spoofed client IP 10.0.0.1 leaked to backend:\n%s", out)
	}
	if !contains(out, "X-Forwarded-For: 203.0.113.7\r\n") {
		t.Fatalf("proxy did not append authoritative X-Forwarded-For from RemoteAddr:\n%s", out)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
