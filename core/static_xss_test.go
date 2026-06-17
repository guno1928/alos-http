package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStaticBrowseEscapesEntryNames ensures the directory-listing page does not
// reflect attacker-controlled file names or request paths into the HTML output
// without escaping (stored/reflected XSS).
func TestStaticBrowseEscapesEntryNames(t *testing.T) {
	root := t.TempDir()
	// A filename containing HTML metacharacters. The OS allows these bytes in
	// names (NUL and '/' excepted), so a hostile upload can plant one.
	evil := `x"><img src=x onerror=alert(1)>.txt`
	if err := os.WriteFile(filepath.Join(root, evil), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}

	handler := Static("/files", StaticConfig{Root: root, Browse: true})
	resp := &Response{}
	handler(&Request{Path: "/files/"}, resp)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := string(resp.GetBody())

	// The raw breakout sequence must never appear verbatim.
	if strings.Contains(body, `"><img src=x onerror=alert(1)>`) {
		t.Fatalf("unescaped file name leaked into listing:\n%s", body)
	}
	// The escaped form must be present so the entry is still listed.
	if !strings.Contains(body, "&lt;img") && !strings.Contains(body, "&#34;") {
		t.Fatalf("expected escaped entry, listing was:\n%s", body)
	}
}

// TestStaticBrowseEscapesDirPath ensures the request-derived dirURL (title,
// heading, href base) is escaped. A directory whose name contains HTML
// metacharacters survives sanitizeStaticPath and lands in the title.
func TestStaticBrowseEscapesDirPath(t *testing.T) {
	root := t.TempDir()
	// '<' is permitted in a path/file name by sanitizeStaticPath.
	dir := filepath.Join(root, "a<script>b")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	handler := Static("/files", StaticConfig{Root: root, Browse: true})
	resp := &Response{}
	handler(&Request{Path: "/files/a<script>b/"}, resp)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := string(resp.GetBody())
	if strings.Contains(body, "<script>") {
		t.Fatalf("unescaped dir path reflected into listing:\n%s", body)
	}
}
