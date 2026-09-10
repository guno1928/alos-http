//go:build linux && amd64

package core

import "testing"

func TestBackendResponseConflictingContentLengthRejected(t *testing.T) {
	cases := []struct {
		name    string
		head    string
		wantErr bool
		wantLen int64
	}{
		{"single", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n", false, 5},
		{"identical duplicates", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n", false, 5},
		{"conflicting duplicates", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 500\r\n", true, -1},
		{"chunked wins over length", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n", false, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &h1Parser{}
			_, n, err := p.parseHeaderBlock([]byte(tc.head), "GET")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("conflicting Content-Length values accepted (parsed length %d); backend framing is ambiguous", n)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if n != tc.wantLen {
				t.Fatalf("content length = %d, want %d", n, tc.wantLen)
			}
		})
	}
}
