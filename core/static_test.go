package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// captureStreamWriter records everything written so the streaming (large-file)
// path can be exercised without a real network connection.
type captureStreamWriter struct {
	status      int
	contentType string
	headers     [][2]string
	body        bytes.Buffer
	closed      bool
}

func (w *captureStreamWriter) WriteHeader(status int, headers [][2]string, contentType string) error {
	w.status = status
	w.headers = headers
	w.contentType = contentType
	return nil
}

func (w *captureStreamWriter) WriteChunk(data []byte) error {
	w.body.Write(data)
	return nil
}

func (w *captureStreamWriter) Flush() error { return nil }

func (w *captureStreamWriter) Close() error {
	w.closed = true
	return nil
}

func newStaticRequest(path string) *Request {
	return &Request{Path: path}
}

func TestStaticServesNormalFile(t *testing.T) {
	root := t.TempDir()
	want := []byte("hello world\n")
	if err := os.WriteFile(filepath.Join(root, "ok.txt"), want, 0o644); err != nil {
		t.Fatal(err)
	}

	handler := Static("/static", StaticConfig{Root: root})

	resp := &Response{}
	handler(newStaticRequest("/static/ok.txt"), resp)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.GetBody(); !bytes.Equal(got, want) {
		t.Fatalf("body = %q, want %q", got, want)
	}
	if ct := staticHeader(resp, "Content-Type"); ct == "" {
		t.Fatalf("content type not set")
	}
}

func staticHeader(resp *Response, name string) string {
	for _, h := range resp.Headers {
		if h[0] == name {
			return h[1]
		}
	}
	return ""
}

func TestStaticRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	// A secret living outside the served root.
	outside := filepath.Dir(root)
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("top secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(secret) })

	handler := Static("/static", StaticConfig{Root: root})

	// sanitizeStaticPath rejects ".." outright -> 400.
	resp := &Response{}
	handler(newStaticRequest("/static/../secret.txt"), resp)
	if resp.StatusCode != 400 {
		t.Fatalf("traversal: status = %d, want 400", resp.StatusCode)
	}
	if bytes.Contains(resp.GetBody(), []byte("secret")) {
		t.Fatalf("traversal leaked file contents")
	}
}

func TestStaticBlocksSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("top secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A symlink that lives inside the served root but targets a file outside it.
	link := filepath.Join(root, "escape.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	handler := Static("/static", StaticConfig{Root: root})

	resp := &Response{}
	handler(newStaticRequest("/static/escape.txt"), resp)

	// os.Root refuses to follow a symlink pointing outside the root, so the
	// handler must not serve the target's contents.
	if resp.StatusCode == 200 {
		t.Fatalf("symlink escape served (status 200); os.Root should block it")
	}
	if bytes.Contains(resp.GetBody(), []byte("top secret")) {
		t.Fatalf("symlink escape leaked outside-root contents")
	}
}

func TestStaticServesSymlinkInsideRoot(t *testing.T) {
	root := t.TempDir()
	want := []byte("internal payload")
	target := filepath.Join(root, "real.txt")
	if err := os.WriteFile(target, want, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias.txt")
	if err := os.Symlink("real.txt", link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	handler := Static("/static", StaticConfig{Root: root})

	resp := &Response{}
	handler(newStaticRequest("/static/alias.txt"), resp)

	if resp.StatusCode != 200 {
		t.Fatalf("in-root symlink: status = %d, want 200", resp.StatusCode)
	}
	if got := resp.GetBody(); !bytes.Equal(got, want) {
		t.Fatalf("in-root symlink body = %q, want %q", got, want)
	}
}

func TestStaticStreamsLargeFile(t *testing.T) {
	root := t.TempDir()
	want := bytes.Repeat([]byte("A"), staticStreamThreshold+4096)
	if err := os.WriteFile(filepath.Join(root, "big.bin"), want, 0o644); err != nil {
		t.Fatal(err)
	}

	handler := Static("/static", StaticConfig{Root: root})

	cap := &captureStreamWriter{}
	resp := &Response{}
	resp.SetSW(cap)
	handler(newStaticRequest("/static/big.bin"), resp)

	if cap.status != 200 {
		t.Fatalf("stream status = %d, want 200", cap.status)
	}
	if !cap.closed {
		t.Fatalf("stream writer not closed")
	}
	if got := cap.body.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("streamed body len = %d, want %d", len(got), len(want))
	}
	// The buffered body must stay empty: the large file was never read whole
	// into the in-memory response body.
	if len(resp.GetBody()) != 0 {
		t.Fatalf("large file buffered into memory body (len %d)", len(resp.GetBody()))
	}
}
