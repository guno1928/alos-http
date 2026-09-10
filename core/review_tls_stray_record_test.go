//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"
)

func startPlainRouteTLSServer(t *testing.T) string {
	t.Helper()
	addr := reserveLocalAddr(t)
	srv := New(Config{
		Addr:          addr,
		HTTPAddr:      "-",
		LogRequests:   false,
		MaxConnsPerIP: -1,
		Certs:         []CertConfig{{Domain: "stray.test", Source: CertSelfSigned}},
	})
	srv.Router.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	srv.Router.POST("/echo", func(req *Request, resp *Response) { resp.Status(200).Bytes(req.Body) })
	go func() { _ = srv.ListenAndServeTLS() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 200 * time.Millisecond}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true, ServerName: "stray.test"})
		if err == nil {
			_ = c.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("TLS server never came up")
	return ""
}

func TestTLSPostHandshakeStrayRecordClosesConnection(t *testing.T) {
	addr := startPlainRouteTLSServer(t)
	cases := []struct {
		name    string
		version uint16
		record  []byte
	}{
		{"tls13 plaintext change_cipher_spec", tls.VersionTLS13, []byte{0x14, 3, 3, 0, 1, 1}},
		{"tls13 unknown record type", tls.VersionTLS13, []byte{0x18, 3, 3, 0, 1, 0}},
		{"tls12 plaintext change_cipher_spec", tls.VersionTLS12, []byte{0x14, 3, 3, 0, 1, 1}},
		{"tls12 unknown record type", tls.VersionTLS12, []byte{0x18, 3, 3, 0, 1, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer raw.Close()
			conn := tls.Client(raw, &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "stray.test",
				MinVersion:         tc.version,
				MaxVersion:         tc.version,
			})
			if err := conn.Handshake(); err != nil {
				t.Fatalf("handshake: %v", err)
			}
			if _, err := raw.Write(tc.record); err != nil {
				t.Fatalf("inject stray record: %v", err)
			}
			if _, err := conn.Write([]byte("GET /ok HTTP/1.1\r\nHost: stray.test\r\n\r\n")); err != nil {
				return
			}
			_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err == nil {
				resp.Body.Close()
				t.Fatalf("server answered %d after a stray post-handshake %#x record; it must abort the connection", resp.StatusCode, tc.record[0])
			}
		})
	}
}
