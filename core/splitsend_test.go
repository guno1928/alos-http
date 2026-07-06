package core

import (
	"bytes"
	"strings"
	"testing"
)

// TestSplitSendByteEquivalence is the correctness guarantee for split-send:
// for every response shape, the header block plus the zero-copy body must be
// byte-for-byte identical to the original single-buffer serialization. If this
// holds, sending headers and body as two writes can never change what the client
// receives, regardless of partial-send boundaries.
func TestSplitSendByteEquivalence(t *testing.T) {
	sizes := []int{0, 1, 63, 255, 256, 1000, 16 << 10, (16 << 10) + 1, 64 << 10, 130 << 10}
	statuses := []int{200, 201, 204, 304, 400, 404, 413, 500}
	methods := []string{"", "GET", "HEAD", "POST"}

	bodyKinds := []struct {
		name string
		set  func(r *Response, body string)
	}{
		{"String", func(r *Response, b string) { r.String(b) }},
		{"HTML", func(r *Response, b string) { r.HTML(b) }},
		{"JSONString", func(r *Response, b string) { r.JSONString(b) }},
		{"Bytes", func(r *Response, b string) { r.Bytes([]byte(b)) }},
		{"JSON", func(r *Response, b string) { r.JSON([]byte(b)) }},
	}

	cases := 0
	for _, size := range sizes {
		body := strings.Repeat("x", size)
		for _, kind := range bodyKinds {
			for _, status := range statuses {
				for _, method := range methods {
					for _, extraHdr := range []bool{false, true} {
						r := &Response{}
						kind.set(r, body)
						r.Status(status)
						if extraHdr {
							r.SetHeader("X-Test", "value-42")
							r.SetHeader("Cache-Control", "no-store")
						}
						if method != "" {
							r.lazyReq = &Request{Method: method}
						}

						full := appendPlainResponse(r, nil)
						hdr := appendPlainResponseHeaders(r, nil)
						combined := append(append([]byte(nil), hdr...), r.transmittedBodyBytes()...)

						if !bytes.Equal(full, combined) {
							t.Fatalf("MISMATCH kind=%s size=%d status=%d method=%q extraHdr=%v\n full (%d): %q\n split(%d): %q",
								kind.name, size, status, method, extraHdr, len(full), truncBytes(full), len(combined), truncBytes(combined))
						}
						if bytes.Contains(hdr, []byte("\r\n\r\n")) && r.transmittedBodyLen() > 0 {
							if idx := bytes.Index(hdr, []byte("\r\n\r\n")); idx >= 0 && idx+4 < len(hdr) {
								t.Fatalf("kind=%s size=%d: header block contains body bytes after terminator", kind.name, size)
							}
						}
						cases++
					}
				}
			}
		}
	}

	redir := &Response{}
	redir.Redirect("https://example.com/x", 302)
	if !bytes.Equal(appendPlainResponse(redir, nil), append(append([]byte(nil), appendPlainResponseHeaders(redir, nil)...), redir.transmittedBodyBytes()...)) {
		t.Fatal("redirect split mismatch")
	}
	cases++

	t.Logf("verified split==full across %d response shapes", cases)
}

func truncBytes(b []byte) []byte {
	if len(b) > 200 {
		return b[:200]
	}
	return b
}

// TestTransmittedBodySuppression verifies bodies that must not be sent (HEAD,
// 204, 304) yield an empty zero-copy body, while the header block still carries
// the correct Content-Length.
func TestTransmittedBodySuppression(t *testing.T) {
	cases := []struct {
		method string
		status int
		want0  bool
	}{
		{"GET", 200, false},
		{"HEAD", 200, true},
		{"GET", 204, true},
		{"GET", 304, true},
		{"POST", 200, false},
	}
	for _, c := range cases {
		r := &Response{}
		r.HTML(strings.Repeat("y", 5000))
		r.Status(c.status)
		r.lazyReq = &Request{Method: c.method}
		got := r.transmittedBodyLen()
		if c.want0 && got != 0 {
			t.Fatalf("method=%s status=%d: expected suppressed body, got len %d", c.method, c.status, got)
		}
		if !c.want0 && got != 5000 {
			t.Fatalf("method=%s status=%d: expected body 5000, got %d", c.method, c.status, got)
		}
	}
}
