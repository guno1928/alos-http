//go:build linux && amd64

package core

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

type proxyBufferStreamWriter struct {
	recordingStreamWriter
	headers [][2]string
	status  int
}

func (writer *proxyBufferStreamWriter) WriteHeader(status int, headers [][2]string, _ string) error {
	writer.status = status
	writer.headers = append(writer.headers, headers...)
	return nil
}

func TestFPProxyBufferedResponseLimit(t *testing.T) {
	type responseCase struct {
		framing    string
		size       int
		withWriter bool
	}
	var tests []responseCase
	for _, framing := range []string{"fixed", "chunked", "chunked-cl-zero", "eof"} {
		for _, size := range []int{65536, 65537} {
			for _, withWriter := range []bool{false, true} {
				tests = append(tests, responseCase{framing, size, withWriter})
			}
		}
	}
	tests = append(tests,
		responseCase{"chunked-cl-zero", 67108864, false},
		responseCase{"eof", 67108865, false},
		responseCase{"fixed", 67108865, true},
	)
	for _, test := range tests {
		framing, size, withWriter := test.framing, test.size, test.withWriter
		t.Run(fmt.Sprintf("%s/%d/writer=%t", framing, size, withWriter), func(t *testing.T) {
			body := bytes.Repeat([]byte("b"), size)
			origin := rawOrigin(t, func(conn net.Conn) {
				switch framing {
				case "fixed":
					fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", size)
					_, _ = conn.Write(body)
				case "chunked", "chunked-cl-zero":
					extra := ""
					if framing == "chunked-cl-zero" {
						extra = "Content-Length: 0\r\n"
					}
					fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\n%sTransfer-Encoding: chunked\r\n\r\n", extra)
					for offset := 0; offset < len(body); {
						end := min(offset+16384, len(body))
						if _, err := fmt.Fprintf(conn, "%x\r\n%s\r\n", end-offset, body[offset:end]); err != nil {
							return
						}
						offset = end
					}
					fmt.Fprint(conn, "0\r\n\r\n")
				case "eof":
					fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
					_, _ = conn.Write(body)
					_ = conn.Close()
				}
			})
			req := &Request{Method: "GET", Host: "origin.test", Path: "/"}
			writer := &proxyBufferStreamWriter{}
			if withWriter {
				req.StreamWriter = writer
			}
			resp := &Response{}
			engine := &ProxyEngine{}
			err := engine.forwardRequestFP(req, resp, &backend{Addr: origin}, &DomainConfig{
				ConnectTimeout: time.Second,
				ReadTimeout:    5 * time.Second,
			})
			if !withWriter && size == 67108865 {
				if !errors.Is(err, errFPBodyTooLarge) {
					t.Fatalf("oversized buffered response: err=%v, body=%d bytes; want errFPBodyTooLarge", err, resp.BodyLen())
				}
				if resp.BodyLen() != 0 {
					t.Fatalf("rejected response exposed %d buffered bytes", resp.BodyLen())
				}
				return
			}
			if err != nil {
				t.Fatalf("forward response: %v", err)
			}
			streaming := withWriter && (framing != "fixed" || size > 65536)
			if streaming {
				if writer.status != 200 || !writer.closed || writer.flushes != 1 || !bytes.Equal(writer.out.Bytes(), body) {
					t.Fatalf("stream status=%d closed=%t flushes=%d body=%d, want complete %d-byte response", writer.status, writer.closed, writer.flushes, writer.out.Len(), size)
				}
				for _, header := range writer.headers {
					if strings.EqualFold(header[0], "Content-Length") && framing != "fixed" {
						t.Fatalf("unknown-length stream relayed Content-Length: %s", header[1])
					}
				}
				if resp.BodyLen() != 0 {
					t.Fatalf("stream retained %d buffered bytes", resp.BodyLen())
				}
			} else if resp.StatusCode != 200 || !bytes.Equal(resp.GetBody(), body) || writer.out.Len() != 0 {
				t.Fatalf("buffered status=%d body=%d streamed=%d, want %d intact buffered bytes", resp.StatusCode, resp.BodyLen(), writer.out.Len(), size)
			}
		})
	}
}

func TestFPProxyResponseLengthFraming(t *testing.T) {
	for _, test := range []struct {
		name    string
		headers [][2]string
		want    int64
	}{
		{"zero", [][2]string{{"Content-Length", "0"}}, 0},
		{"positive", [][2]string{{"Content-Length", "65537"}}, 65537},
		{"max-int64", [][2]string{{"Content-Length", "9223372036854775807"}}, 9223372036854775807},
		{"absent", nil, -1},
		{"empty", [][2]string{{"Content-Length", ""}}, -1},
		{"negative", [][2]string{{"Content-Length", "-1"}}, -1},
		{"invalid", [][2]string{{"Content-Length", "1x"}}, -1},
		{"overflow", [][2]string{{"Content-Length", "18446744073709551616"}}, -1},
		{"chunked-first", [][2]string{{"Transfer-Encoding", "chunked"}, {"Content-Length", "0"}}, -1},
		{"chunked-last", [][2]string{{"Content-Length", "0"}, {"Transfer-Encoding", "ChUnKeD"}}, -1},
		{"other-transfer-coding", [][2]string{{"Content-Length", "0"}, {"Transfer-Encoding", "gzip"}}, -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := fpResponseContentLength(test.headers); got != test.want {
				t.Fatalf("effective response length=%d, want %d", got, test.want)
			}
		})
	}
}

func FuzzFPProxyResponseLength(f *testing.F) {
	for _, value := range []string{"0", "65536", "65537", "9223372036854775807", "18446744073709551616", "", "1x", "-1"} {
		f.Add(value, false)
		f.Add(value, true)
	}
	f.Fuzz(func(t *testing.T, value string, chunked bool) {
		headers := [][2]string{{"Content-Length", value}}
		if chunked {
			headers = append(headers, [2]string{"Transfer-Encoding", "chunked"})
		}
		want := int64(-1)
		if length, err := strconv.ParseUint(value, 10, 63); err == nil && !chunked {
			want = int64(length)
		}
		if got := fpResponseContentLength(headers); got != want {
			t.Fatalf("Content-Length %q, chunked=%t: got %d, want %d", value, chunked, got, want)
		}
	})
}

type proxyBufferReadConn struct {
	net.Conn
	remaining int64
	readBytes int64
}

func (conn *proxyBufferReadConn) Read(data []byte) (int, error) {
	if conn.remaining == 0 {
		return 0, io.EOF
	}
	count := int(min(int64(len(data)), conn.remaining))
	for i := range data[:count] {
		data[i] = 'b'
	}
	conn.remaining -= int64(count)
	conn.readBytes += int64(count)
	return count, nil
}

func (conn *proxyBufferReadConn) SetReadDeadline(time.Time) error { return nil }

func TestDeclinedUpgradeBufferedResponseLimit(t *testing.T) {
	for _, test := range []struct {
		name       string
		size       int64
		withWriter bool
	}{
		{"above-stream-threshold", 65537, false},
		{"at-body-limit", 67108864, false},
		{"above-body-limit", 67108866, false},
		{"above-body-limit-streamed", 67108865, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := &proxyBufferReadConn{remaining: test.size}
			var parser h1Parser
			chunked, length, err := parser.parseHeaderBlock([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close"), "GET")
			if err != nil {
				t.Fatalf("parse declined response: %v", err)
			}
			req := &Request{Method: "GET"}
			writer := &proxyBufferStreamWriter{}
			if test.withWriter {
				req.StreamWriter = writer
			}
			resp := &Response{}
			err = relayDeclinedUpgrade(conn, &parser, chunked, length, req, resp, time.Second)
			if test.name == "above-body-limit" {
				if !errors.Is(err, errFPBodyTooLarge) || resp.BodyLen() != 0 {
					t.Fatalf("oversized declined response: err=%v body=%d, want errFPBodyTooLarge and no body", err, resp.BodyLen())
				}
				if conn.readBytes != 67108865 {
					t.Fatalf("read %d bytes, want limit+1 bytes", conn.readBytes)
				}
				return
			}
			if err != nil {
				t.Fatalf("relay declined response: %v", err)
			}
			if test.withWriter {
				if writer.status != 403 || !writer.closed || int64(writer.out.Len()) != test.size || resp.BodyLen() != 0 {
					t.Fatalf("stream status=%d closed=%t streamed=%d buffered=%d, want %d streamed bytes", writer.status, writer.closed, writer.out.Len(), resp.BodyLen(), test.size)
				}
			} else if resp.StatusCode != 403 || int64(resp.BodyLen()) != test.size {
				t.Fatalf("buffered status=%d bytes=%d, want %d intact bytes", resp.StatusCode, resp.BodyLen(), test.size)
			}
			body := resp.GetBody()
			if test.withWriter {
				body = writer.out.Bytes()
			}
			for i, value := range body {
				if value != 'b' {
					t.Fatalf("body byte %d=%d, want b", i, value)
				}
			}
		})
	}
}
