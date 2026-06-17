package core

import "testing"

func TestSanitizeRequestPathDecodesAndNormalizes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		// Encoded traversal must not survive: %2e%2e decodes to ".." and is
		// stripped by segment normalization rather than passing through raw.
		{"encoded dot-dot segment", "/a/%2e%2e/b", "/b"},
		{"mixed encoded traversal", "/a/..%2fb", "/b"},
		{"fully encoded traversal", "/%2e%2e/%2e%2e/etc/passwd", "/etc/passwd"},
		{"literal dot-dot still normalized", "/a/../b", "/b"},

		// Normal encoded path decodes correctly (space).
		{"encoded space decodes", "/foo%20bar", "/foo bar"},
		{"encoded slash becomes separator", "/a%2Fb", "/a/b"},

		// Normal paths are unchanged.
		{"plain path unchanged", "/api/users", "/api/users"},
		{"root unchanged", "/", "/"},
		{"empty becomes root", "", "/"},

		// Query is dropped, path before it is normalized/decoded.
		{"query stripped", "/a/%2e%2e/b?x=%2e%2e", "/b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sanitizeRequestPath(tt.in)
			if !ok {
				t.Fatalf("sanitizeRequestPath(%q) rejected, want accept -> %q", tt.in, tt.want)
			}
			if got != tt.want {
				t.Fatalf("sanitizeRequestPath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSanitizeRequestPathRejects(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"encoded NUL", "/a/%00/b"},
		{"encoded NUL lowercase hex", "/%00"},
		{"trailing percent", "/a%"},
		{"percent one hex digit", "/a%2"},
		{"invalid hex high nibble", "/a%2g"},
		{"invalid hex low nibble", "/a%g2"},
		{"non-hex after percent", "/%zz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sanitizeRequestPath(tt.in)
			if ok {
				t.Fatalf("sanitizeRequestPath(%q) = %q, ok=true; want reject (fail closed)", tt.in, got)
			}
			if got != "" {
				t.Fatalf("sanitizeRequestPath(%q) rejected but returned %q; want empty", tt.in, got)
			}
		})
	}
}

func TestDecodePercent(t *testing.T) {
	t.Run("no escapes returns input", func(t *testing.T) {
		got, ok := decodePercent("/plain/path")
		if !ok || got != "/plain/path" {
			t.Fatalf("decodePercent = %q, %v; want /plain/path, true", got, ok)
		}
	})

	t.Run("rejects literal NUL with no escapes", func(t *testing.T) {
		if got, ok := decodePercent("/a\x00b"); ok {
			t.Fatalf("decodePercent of literal NUL = %q, ok=true; want reject", got)
		}
	})

	t.Run("rejects decoded NUL", func(t *testing.T) {
		if _, ok := decodePercent("/a%00b"); ok {
			t.Fatal("decodePercent(%00) ok=true; want reject")
		}
	})

	t.Run("decodes uppercase and lowercase hex", func(t *testing.T) {
		got, ok := decodePercent("/%2F%2f")
		if !ok || got != "///" {
			t.Fatalf("decodePercent = %q, %v; want ///, true", got, ok)
		}
	})
}
