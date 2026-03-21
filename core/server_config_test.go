package core

import "testing"

func TestNegotiateALPNCanDisableHTTP2(t *testing.T) {
	if got := NegotiateALPN([]string{"h2", "http/1.1"}, false); got != "http/1.1" {
		t.Fatalf("expected HTTP/1.1 when h2 is disabled, got %q", got)
	}
	if got := NegotiateALPN([]string{"h2"}, false); got != "" {
		t.Fatalf("expected no ALPN selection when only h2 is offered and h2 is disabled, got %q", got)
	}
	if got := NegotiateALPN([]string{"h2", "http/1.1"}, true); got != "h2" {
		t.Fatalf("expected h2 when enabled, got %q", got)
	}
}

func TestServerDisableHTTP2RemovesH2Advertisement(t *testing.T) {
	s := New(Config{DisableHTTP2: true})
	s.rebuildFallbackTLSConfig()
	cfg := s.fallbackTLS.Load()
	if cfg == nil {
		t.Fatal("expected fallback TLS config")
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("expected only http/1.1 ALPN advertisement, got %v", cfg.NextProtos)
	}
	s.computeFastDispatch()
	if s.h2RootFast.enabled {
		t.Fatal("expected HTTP/2 fast path to stay disabled when DisableHTTP2 is true")
	}
}
