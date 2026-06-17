package core

import (
	"testing"
)

func TestCORSWildcardNeverReflectsOrCredentialsWithWildcard(t *testing.T) {
	ce := NewCORSEngine(CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowCredentials: true,
	})
	req := &Request{Method: "GET", Headers: [][2]string{{"Origin", "https://evil.example"}}}
	resp := &Response{}
	resp.Reset()
	snap := ce.snapshot.Load()
	if snap == nil {
		t.Fatal("nil cors snapshot")
	}
	ce.applyCORS(snap, req, resp)

	for _, h := range resp.Headers {
		if EqualFoldASCII(h[0], "access-control-allow-origin") && h[1] != "*" {
			t.Fatalf("wildcard CORS must emit '*', not reflect origin, got %q", h[1])
		}
		if EqualFoldASCII(h[0], "access-control-allow-credentials") {
			t.Fatalf("must not emit credentials header under wildcard, got %q", h[1])
		}
	}
}

func TestCORSExplicitOriginStillGetsCredentials(t *testing.T) {
	ce := NewCORSEngine(CORSConfig{
		AllowOrigins:     []string{"https://good.example"},
		AllowCredentials: true,
	})
	req := &Request{Method: "GET", Headers: [][2]string{{"Origin", "https://good.example"}}}
	resp := &Response{}
	resp.Reset()
	ce.applyCORS(ce.snapshot.Load(), req, resp)

	var gotOrigin, gotCreds bool
	for _, h := range resp.Headers {
		if EqualFoldASCII(h[0], "access-control-allow-origin") && h[1] == "https://good.example" {
			gotOrigin = true
		}
		if EqualFoldASCII(h[0], "access-control-allow-credentials") && h[1] == "true" {
			gotCreds = true
		}
	}
	if !gotOrigin || !gotCreds {
		t.Fatalf("explicit allow-listed origin should get reflected origin + credentials (origin=%v creds=%v)", gotOrigin, gotCreds)
	}
}

func TestWebSocketOriginSameOrigin(t *testing.T) {
	srv := &Server{}
	srv.config.WebSocketOriginMode = WSOriginSameOrigin

	same := &Request{Host: "app.example.com", server: srv,
		Headers: [][2]string{{"Origin", "https://app.example.com"}}}
	if !checkWebSocketOrigin(same) {
		t.Fatal("same-origin request should be allowed")
	}

	cross := &Request{Host: "app.example.com", server: srv,
		Headers: [][2]string{{"Origin", "https://evil.example.com"}}}
	if checkWebSocketOrigin(cross) {
		t.Fatal("cross-origin request must be rejected in SameOrigin mode")
	}

	noOrigin := &Request{Host: "app.example.com", server: srv}
	if !checkWebSocketOrigin(noOrigin) {
		t.Fatal("non-browser client (no Origin) should be allowed")
	}
}

func TestWebSocketOriginOffIsBackwardCompatible(t *testing.T) {
	srv := &Server{}
	cross := &Request{Host: "app.example.com", server: srv,
		Headers: [][2]string{{"Origin", "https://evil.example.com"}}}
	if !checkWebSocketOrigin(cross) {
		t.Fatal("default WSOriginOff must allow all origins (backward compatible)")
	}
}

func TestCSRFUnsafeMethodDefaultDeny(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "OPTIONS", "TRACE"} {
		if isUnsafeMethod(m) {
			t.Fatalf("%s should be treated as safe", m)
		}
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "POSX", "CONNECT", "FOO", ""} {
		if !isUnsafeMethod(m) {
			t.Fatalf("%q must be treated as unsafe (CSRF token required)", m)
		}
	}
}

func TestWebSocketOriginAllowlist(t *testing.T) {
	srv := &Server{}
	srv.config.WebSocketOriginMode = WSOriginAllowlist
	srv.config.WebSocketAllowedOrigins = []string{"https://trusted.example"}

	ok := &Request{Host: "app.example.com", server: srv,
		Headers: [][2]string{{"Origin", "https://trusted.example"}}}
	if !checkWebSocketOrigin(ok) {
		t.Fatal("allow-listed origin should pass")
	}
	bad := &Request{Host: "app.example.com", server: srv,
		Headers: [][2]string{{"Origin", "https://other.example"}}}
	if checkWebSocketOrigin(bad) {
		t.Fatal("non-allow-listed origin must be rejected")
	}
}
