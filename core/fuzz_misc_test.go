//go:build linux && amd64

package core

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzParseCookieHeader(f *testing.F) {
	f.Add("a=1; b=2")
	f.Add(`session="quoted"; theme=dark;;;  ; =x; y=`)
	f.Fuzz(func(t *testing.T, header string) {
		for _, c := range parseCookieHeader(header) {
			if len(c.Name)+len(c.Value) > len(header) {
				t.Fatalf("cookie %q=%q larger than header", c.Name, c.Value)
			}
		}
	})
}

func FuzzParseQueryString(f *testing.F) {
	f.Add("a=1&b=2&a=3")
	f.Add("%zz=%&&=&x=%E2%82%AC&+=+")
	f.Fuzz(func(t *testing.T, q string) {
		_ = parseQueryString(q)
	})
}

func FuzzParseMultipart(f *testing.F) {
	for _, body := range multipartDifferentialBodies() {
		f.Add([]byte(body), "B")
	}
	f.Add([]byte("--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\nContent-Type: text/plain\r\n\r\nfile\r\n--B--\r\n"), "B")
	f.Add([]byte("--B\r\nContent-Disposition: form-data; filename=\"../../x\"; name=\"f\"\r\n\r\n--B--"), "B")
	f.Fuzz(func(t *testing.T, body []byte, boundary string) {
		if boundary == "" || len(boundary) > maxMultipartBoundary {
			return
		}
		vals, files, err := parseMultipartInMem(body, boundary)
		if err != nil {
			return
		}
		for _, list := range files {
			for _, fh := range list {
				if int(fh.Size) != len(fh.Data) {
					t.Fatalf("file %q size %d != data %d", fh.Filename, fh.Size, len(fh.Data))
				}
				if fh.Filename != sanitizeUploadFilename(fh.Filename) {
					t.Fatalf("filename %q is not sanitised", fh.Filename)
				}
			}
		}
		if hasBareLF(body) {
			return
		}
		refVals, refFiles, refErr := parseMultipartStdlibReference(body, boundary)
		if refErr != nil {
			return
		}
		if !reflect.DeepEqual(vals, refVals) {
			t.Fatalf("values differ: inmem %q stdlib %q", vals, refVals)
		}
		for name, list := range files {
			if len(refFiles[name]) != len(list) {
				t.Fatalf("file count for %q differs", name)
			}
			for i, fh := range list {
				other := refFiles[name][i]
				if fh.Filename != other.Filename || fh.ContentType != other.ContentType || !bytes.Equal(fh.Data, other.Data) {
					t.Fatalf("file %q[%d] differs: %+v vs %+v", name, i, fh, other)
				}
			}
		}
	})
}

func FuzzSanitizeRequestPath(f *testing.F) {
	for _, s := range []string{"/", "/a/b", "/a/../../b", "a/./b//c", "/a\x00b", "/a\rb\x00c", "/%2e%2e/x", "//x", "/a?b/../c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		p := sanitizeRequestPath(raw)
		if p == "" || p[0] != '/' {
			t.Fatalf("sanitize(%q) = %q, want leading slash", raw, p)
		}
		if strings.ContainsAny(p, "\x00\r\n") {
			t.Fatalf("sanitize(%q) = %q still contains NUL/CR/LF", raw, p)
		}
		if strings.Contains(p, "//") {
			t.Fatalf("sanitize(%q) = %q contains an empty segment", raw, p)
		}
		for _, seg := range strings.Split(p[1:], "/") {
			if seg == "." || seg == ".." {
				t.Fatalf("sanitize(%q) = %q contains dot segment", raw, p)
			}
		}
		if again := sanitizeRequestPath(p); again != p {
			t.Fatalf("sanitize not idempotent: %q -> %q -> %q", raw, p, again)
		}
	})
}

func FuzzValidateHost(f *testing.F) {
	for _, s := range []string{"example.com", "example.com:8443", "[::1]:443", "a b", "a\tb", "x@y", "a/b", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, host string) {
		if !ValidateHost(host) {
			return
		}
		for i := 0; i < len(host); i++ {
			if c := host[i]; c <= ' ' || c == 0x7f {
				t.Fatalf("ValidateHost accepted %q containing byte %#x", host, c)
			}
		}
	})
}

func FuzzSanitizeUploadFilename(f *testing.F) {
	for _, s := range []string{"report.pdf", "../../etc/passwd", `C:\Users\x\evil.exe`, "a\x00b\rc\nd", ".", "..", "/", "", strings.Repeat("é", 300), "dir/..", "\x7f"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		got := sanitizeUploadFilename(name)
		if strings.ContainsAny(got, `/\`) || got == "." || got == ".." || len(got) > maxUploadFilenameBytes {
			t.Fatalf("sanitizeUploadFilename(%q) = %q", name, got)
		}
		for i := 0; i < len(got); i++ {
			if got[i] < 0x20 || got[i] == 0x7f {
				t.Fatalf("sanitizeUploadFilename(%q) = %q keeps control byte %#x", name, got, got[i])
			}
		}
		if utf8.ValidString(name) && !utf8.ValidString(got) {
			t.Fatalf("sanitizeUploadFilename(%q) = %q split a UTF-8 sequence", name, got)
		}
		if again := sanitizeUploadFilename(got); again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q", name, got, again)
		}
	})
}
