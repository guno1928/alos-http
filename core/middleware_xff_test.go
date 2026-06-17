package core

import "testing"

// rateLimitKey reproduces the default rate-limiter key derivation
// (RateLimitMiddleware's KeyFunc) after the trusted-proxy gate has run, so
// the tests assert on exactly what the limiter would shard on.
func rateLimitKey(req *Request, matcher trustedProxyMatcher) string {
	applyTrustedRealIP(req, matcher)
	return extractClientIP(req.RemoteAddr)
}

func newXFFRequest(remoteAddr, xff string) *Request {
	return &Request{
		RemoteAddr: remoteAddr,
		Headers:    [][2]string{{"X-Forwarded-For", xff}},
	}
}

// With no trusted proxies configured (the secure default) the matcher is
// inactive, so X-Forwarded-For must be ignored and the key must come from the
// real socket peer regardless of the header.
func TestRateLimitKeyIgnoresXFFWhenUntrusted(t *testing.T) {
	matcher := newTrustedProxyMatcher(nil, false)

	req := newXFFRequest("203.0.113.7:5555", "1.2.3.4")
	if got := rateLimitKey(req, matcher); got != "203.0.113.7" {
		t.Fatalf("untrusted peer: key = %q, want socket peer 203.0.113.7", got)
	}
}

// Spoof path: an attacker rotating X-Forwarded-For from the same socket peer
// must not change the limiter key, otherwise per-IP limits are bypassable.
func TestRateLimitKeyStableUnderXFFRotationWhenUntrusted(t *testing.T) {
	matcher := newTrustedProxyMatcher(nil, false)

	spoofed := []string{"1.1.1.1", "2.2.2.2", "9.9.9.9, 8.8.8.8", "victim.example"}
	want := "198.51.100.42"
	for _, xff := range spoofed {
		req := newXFFRequest(want+":40000", xff)
		if got := rateLimitKey(req, matcher); got != want {
			t.Fatalf("rotating XFF %q changed key: got %q, want %q", xff, got, want)
		}
	}
}

// When the immediate peer is a configured trusted proxy, the header is
// honored and the key is the real client carried in X-Forwarded-For.
func TestRateLimitKeyHonorsXFFFromTrustedProxy(t *testing.T) {
	matcher := newTrustedProxyMatcher([]string{"10.0.0.0/8"}, false)

	req := newXFFRequest("10.0.0.1:443", "203.0.113.99")
	if got := rateLimitKey(req, matcher); got != "203.0.113.99" {
		t.Fatalf("trusted peer: key = %q, want client 203.0.113.99", got)
	}
}

// A peer that does not match the trusted set must not have its header honored,
// even when trusted proxies are configured (fail closed).
func TestRateLimitKeyIgnoresXFFFromUntrustedPeerWhenTrustConfigured(t *testing.T) {
	matcher := newTrustedProxyMatcher([]string{"10.0.0.0/8"}, false)

	req := newXFFRequest("203.0.113.7:5555", "1.2.3.4")
	if got := rateLimitKey(req, matcher); got != "203.0.113.7" {
		t.Fatalf("untrusted peer with trust configured: key = %q, want 203.0.113.7", got)
	}
}

// Entry selection: with a chain of trusted proxies appending on the right, the
// client is the right-most entry that is not itself a trusted proxy, not the
// last entry (which is our own proxy hop).
func TestClientXFFEntryLeftmostUntrusted(t *testing.T) {
	matcher := newTrustedProxyMatcher([]string{"10.0.0.0/8"}, false)

	// real client -> edge proxy (untrusted-looking) -> two internal hops.
	req := newXFFRequest("10.0.0.5:443", "203.0.113.50, 10.1.1.1, 10.0.0.9")
	if got := rateLimitKey(req, matcher); got != "203.0.113.50" {
		t.Fatalf("chain selection: key = %q, want 203.0.113.50", got)
	}
}

// trustAll (ProxyMode) carries no per-hop trust information, so the right-most
// entry is taken as-is.
func TestClientXFFEntryTrustAllTakesRightmost(t *testing.T) {
	matcher := newTrustedProxyMatcher(nil, true)

	req := newXFFRequest("10.0.0.5:443", "203.0.113.50, 198.51.100.7")
	if got := rateLimitKey(req, matcher); got != "198.51.100.7" {
		t.Fatalf("trustAll: key = %q, want rightmost 198.51.100.7", got)
	}
}
