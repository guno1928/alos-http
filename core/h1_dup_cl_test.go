package core

import "testing"

// TestParseH1RequestHeadDuplicateContentLength covers finding C7: HTTP/1
// request smuggling via duplicate / malformed Content-Length. A duplicate or
// list-valued Content-Length must fail closed (contentLength == -1), which the
// drivers translate into a 400 + connection close.
func TestParseH1RequestHeadDuplicateContentLength(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		wantOK       bool
		wantHasCL    bool
		wantCL       int // meaningful only on the accept case
		wantRejectCL bool
	}{
		{
			name:         "proven smuggling input: conflicting duplicate CL (6 then 0)",
			raw:          "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nContent-Length: 0\r\n\r\nGHIJKL",
			wantOK:       true,
			wantHasCL:    true,
			wantRejectCL: true,
		},
		{
			name:         "same-value duplicate CL",
			raw:          "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nContent-Length: 6\r\n\r\nGHIJKL",
			wantOK:       true,
			wantHasCL:    true,
			wantRejectCL: true,
		},
		{
			name:         "comma list CL value (6, 0)",
			raw:          "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6, 0\r\n\r\nGHIJKL",
			wantOK:       true,
			wantHasCL:    true,
			wantRejectCL: true,
		},
		{
			name:         "non-numeric CL value",
			raw:          "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n",
			wantOK:       true,
			wantHasCL:    true,
			wantRejectCL: true,
		},
		{
			name:      "single valid CL still accepted",
			raw:       "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\n\r\nGHIJKL",
			wantOK:    true,
			wantHasCL: true,
			wantCL:    6,
		},
		{
			name:      "no CL header",
			raw:       "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
			wantOK:    true,
			wantHasCL: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req Request
			_, contentLength, hasCL, _, _, ok := ParseH1RequestHead([]byte(tt.raw), &req)

			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if hasCL != tt.wantHasCL {
				t.Fatalf("hasContentLength = %v, want %v", hasCL, tt.wantHasCL)
			}

			if tt.wantRejectCL {
				if contentLength != -1 {
					t.Fatalf("contentLength = %d, want -1 (rejected)", contentLength)
				}
				return
			}

			if tt.wantHasCL && contentLength != tt.wantCL {
				t.Fatalf("contentLength = %d, want %d", contentLength, tt.wantCL)
			}
		})
	}
}
