package core

import "testing"

// TestParseH1HeaderNameWhitespaceSmuggling covers finding C8: a header name
// with whitespace before the colon (or any non-token byte) must be rejected so
// it cannot hide a framing header (Transfer-Encoding / Content-Length) from the
// fixed-offset header dispatch and cause a TE.CL request-smuggling desync.
func TestParseH1HeaderNameWhitespaceSmuggling(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantReject  bool // expect badTransferEncoding (400 + close)
		wantOK      bool
		checkParsed func(t *testing.T, req *Request, cl int, hasCL, badTE bool)
	}{
		{
			name:       "PROVEN: Transfer-Encoding with trailing space before colon",
			raw:        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding : chunked\r\nContent-Length: 5\r\n\r\nhello",
			wantReject: true,
			wantOK:     true,
		},
		{
			name:       "Content-Length with trailing space before colon",
			raw:        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length : 5\r\n\r\nhello",
			wantReject: true,
			wantOK:     true,
		},
		{
			name:       "trailing HTAB before colon",
			raw:        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding\t: chunked\r\nContent-Length: 5\r\n\r\nhello",
			wantReject: true,
			wantOK:     true,
		},
		{
			name:       "embedded illegal byte in header name",
			raw:        "GET / HTTP/1.1\r\nHost: x\r\nX-Foo\x00Bar: baz\r\n\r\n",
			wantReject: true,
			wantOK:     true,
		},
		{
			name:       "space inside header name",
			raw:        "GET / HTTP/1.1\r\nHost: x\r\nX Foo: baz\r\n\r\n",
			wantReject: true,
			wantOK:     true,
		},
		{
			name:       "well-formed Transfer-Encoding: chunked still detected",
			raw:        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
			wantReject: true, // chunked TE is itself rejected by badTransferEncoding
			wantOK:     true,
			checkParsed: func(t *testing.T, req *Request, cl int, hasCL, badTE bool) {
				if !badTE {
					t.Fatalf("expected legit Transfer-Encoding: chunked to set badTransferEncoding")
				}
			},
		},
		{
			name:       "well-formed Content-Length parses correctly",
			raw:        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
			wantReject: false,
			wantOK:     true,
			checkParsed: func(t *testing.T, req *Request, cl int, hasCL, badTE bool) {
				if !hasCL || cl != 5 {
					t.Fatalf("expected hasCL=true cl=5, got hasCL=%v cl=%d", hasCL, cl)
				}
				if badTE {
					t.Fatalf("well-formed request unexpectedly flagged badTransferEncoding")
				}
			},
		},
		{
			name:       "well-formed plain GET",
			raw:        "GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n",
			wantReject: false,
			wantOK:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var req Request
			req.resetFastH1()
			_, cl, hasCL, _, badTE, ok := ParseH1RequestHead([]byte(tc.raw), &req)

			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if badTE != tc.wantReject {
				t.Fatalf("badTransferEncoding = %v, want %v", badTE, tc.wantReject)
			}
			if tc.checkParsed != nil {
				tc.checkParsed(t, &req, cl, hasCL, badTE)
			}
		})
	}
}

func TestValidH1HeaderName(t *testing.T) {
	valid := []string{"Host", "Content-Length", "X-Forwarded-For", "a", "Sec-WebSocket-Key"}
	for _, n := range valid {
		if !validH1HeaderName([]byte(n)) {
			t.Errorf("validH1HeaderName(%q) = false, want true", n)
		}
	}
	invalid := []string{"", "Transfer-Encoding ", "Content-Length\t", "X Foo", "X\x00Bar", "bad:name", "a b"}
	for _, n := range invalid {
		if validH1HeaderName([]byte(n)) {
			t.Errorf("validH1HeaderName(%q) = true, want false", n)
		}
	}
}

func BenchmarkValidH1HeaderName(b *testing.B) {
	name := []byte("Content-Length")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !validH1HeaderName(name) {
			b.Fatal("unexpected reject")
		}
	}
}
