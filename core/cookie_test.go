package core

import (
	"strings"
	"testing"
)

func TestCookieStringNormalUnchanged(t *testing.T) {
	c := Cookie{
		Name:     "session",
		Value:    "abc123",
		Path:     "/app",
		Domain:   "example.com",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: SameSiteLax,
	}
	got := c.String()
	want := "session=abc123; Path=/app; Domain=example.com; Max-Age=3600; HttpOnly; Secure; SameSite=Lax"
	if got != want {
		t.Fatalf("normal cookie altered:\n got: %q\nwant: %q", got, want)
	}
}

func TestCookieStringValueInjectionStripped(t *testing.T) {
	// A Value carrying "; Domain=evil" must not inject an extra attribute.
	c := Cookie{Name: "session", Value: "x; Domain=victim.com; HttpOnly"}
	got := c.String()
	// The defense is dropping the ';' separator: without it the residual
	// "Domain=victim.com" text stays inside the cookie value and is not
	// parsed as a separate attribute. No legitimate attribute is present,
	// so there must be no ';' in the output at all.
	if strings.Contains(got, ";") {
		t.Fatalf("injected separators survived serialization: %q", got)
	}
	if got != "session=x Domain=victim.com HttpOnly" {
		t.Fatalf("unexpected sanitized output: %q", got)
	}
}

func TestCookieStringControlAndCRLFStripped(t *testing.T) {
	c := Cookie{
		Name:   "a\r\nSet-Cookie: evil=1",
		Value:  "b\x00\x1f",
		Path:   "/p\r\n; Secure",
		Domain: "d\x7f.com",
	}
	got := c.String()
	for _, bad := range []string{"\r", "\n", "\x00", "\x1f", "\x7f"} {
		if strings.Contains(got, bad) {
			t.Fatalf("control byte %q survived: %q", bad, got)
		}
	}
	// The injected "; Secure" in Path must not become a standalone attribute:
	// its leading separator is stripped, so it folds into the Path value.
	if strings.Count(got, ";") != 2 { // only the two legitimate "; Path=" / "; Domain="
		t.Fatalf("unexpected separator count: %q", got)
	}
}
