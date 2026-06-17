package core

import (
	"bytes"
	"compress/gzip"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
)

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func brotliBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}

// A highly compressible body that inflates well beyond MaxEntrySize must not be
// cached, even though its compressed form passes the pre-decompress size check.
func TestProxyCachePutManual_DecompressionBombRejected(t *testing.T) {
	const maxEntry = 64 << 10 // 64 KiB

	cases := []struct {
		name     string
		encoding string
		compress func(*testing.T, []byte) []byte
	}{
		{"gzip", "gzip", gzipBytes},
		{"brotli", "br", brotliBytes},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc := NewProxyCache(ProxyCacheConfig{
				MaxEntrySize:  maxEntry,
				MaxTotalBytes: 1 << 30,
				MaxEntries:    1024,
			})

			// 1 MiB of zeros inflates from a tiny compressed body — the bomb.
			inflated := make([]byte, 1<<20)
			compressed := tc.compress(t, inflated)
			if int64(len(compressed)) > maxEntry {
				t.Fatalf("compressed body %d should be <= MaxEntrySize %d to exercise the bomb", len(compressed), maxEntry)
			}

			headers := [][2]string{{"content-encoding", tc.encoding}}
			pc.PutManual("GET", "example.com", "/bomb", 200, headers, "text/plain", compressed, time.Hour, 0, false, -1)

			if _, ok := pc.Get("GET", "example.com", "/bomb", nil); ok {
				t.Fatalf("%s bomb (inflates to %d > MaxEntrySize %d) must not be cached", tc.name, len(inflated), maxEntry)
			}

			entries, totalBytes, _, _ := pc.Stats()
			if entries != 0 {
				t.Fatalf("expected 0 cached entries, got %d", entries)
			}
			if totalBytes != 0 {
				t.Fatalf("expected totalBytes 0 after rejecting bomb, got %d", totalBytes)
			}
		})
	}
}

// A legitimate small compressed entry must still inflate and cache normally.
func TestProxyCachePutManual_SmallCompressedStillCaches(t *testing.T) {
	const maxEntry = 64 << 10

	payload := bytes.Repeat([]byte("hello world\n"), 64) // 768 bytes, well under MaxEntrySize
	compressed := gzipBytes(t, payload)

	pc := NewProxyCache(ProxyCacheConfig{
		MaxEntrySize:  maxEntry,
		MaxTotalBytes: 1 << 30,
		MaxEntries:    1024,
	})

	headers := [][2]string{{"content-encoding", "gzip"}}
	pc.PutManual("GET", "example.com", "/ok", 200, headers, "text/plain", compressed, time.Hour, 0, false, -1)

	entry, ok := pc.Get("GET", "example.com", "/ok", nil)
	if !ok {
		t.Fatal("legitimate small entry should be cached")
	}
	if !bytes.Equal(entry.body, payload) {
		t.Fatalf("cached body mismatch: got %d bytes, want %d", len(entry.body), len(payload))
	}
}
