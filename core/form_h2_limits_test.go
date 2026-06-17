package core

import (
	"bytes"
	"testing"
)

// TestDefaultMaxBodySizeNonZero guards the H2 fail-open regression: a zero or
// default config must apply a bounded body cap, never unlimited.
func TestDefaultMaxBodySizeNonZero(t *testing.T) {
	if DefaultMaxBodySize <= 0 {
		t.Fatalf("DefaultMaxBodySize must be positive, got %d", DefaultMaxBodySize)
	}
	if got := DefaultConfig().MaxBodySize; got != DefaultMaxBodySize {
		t.Fatalf("DefaultConfig().MaxBodySize = %d, want %d", got, DefaultMaxBodySize)
	}

	// A caller leaving MaxBodySize at the zero value must be normalized to the
	// bounded default rather than treated as unlimited.
	s := New(Config{})
	if s.config.MaxBodySize != DefaultMaxBodySize {
		t.Fatalf("New(Config{}).MaxBodySize = %d, want %d", s.config.MaxBodySize, DefaultMaxBodySize)
	}

	// -1 is the explicit unlimited opt-in and must survive normalization.
	if s := New(Config{MaxBodySize: -1}); s.config.MaxBodySize != -1 {
		t.Fatalf("explicit unlimited (-1) was overwritten: got %d", s.config.MaxBodySize)
	}

	// An explicit positive value must be honored unchanged.
	if s := New(Config{MaxBodySize: 4096}); s.config.MaxBodySize != 4096 {
		t.Fatalf("explicit MaxBodySize overwritten: got %d, want 4096", s.config.MaxBodySize)
	}
}

// TestParseMultipartPartCountBounded ensures a body crafted from far more parts
// than maxMultipartParts does not materialize one parsed value per part. The
// split fan-out is capped, so excess parts are not parsed into the result maps.
func TestParseMultipartPartCountBounded(t *testing.T) {
	const boundary = "X"
	delim := "--" + boundary

	var buf bytes.Buffer
	const parts = maxMultipartParts * 4
	for i := 0; i < parts; i++ {
		buf.WriteString(delim)
		buf.WriteString("\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n")
	}
	buf.WriteString(delim + "--\r\n")

	values, files := parseMultipart(buf.Bytes(), boundary)
	if len(files) != 0 {
		t.Fatalf("expected no files, got %d keys", len(files))
	}
	got := len(values["f"])
	if got > maxMultipartParts {
		t.Fatalf("parsed %d values, exceeds bound of %d", got, maxMultipartParts)
	}
	if got == 0 {
		t.Fatalf("expected some values parsed within the bound, got 0")
	}
}
