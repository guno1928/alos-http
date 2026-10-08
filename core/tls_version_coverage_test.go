//go:build linux && amd64

package core

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func startTLSCoverageServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	srv := New(Config{
		Addr: addr, HTTPAddr: "-", LogRequests: false, MaxConnsPerIP: -1, Listeners: 1,
		Certs: []CertConfig{{Domain: "cov.test", Source: CertSelfSigned}},
	})
	srv.Router.GET("/", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	go func() { _ = srv.ListenAndServeTLS() }()
	waitForProxy(t, addr)
	return addr, func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

func TestTLSVersionCoverage(t *testing.T) {
	addr, stop := startTLSCoverageServer(t)
	defer stop()

	cases := []struct {
		name       string
		minV, maxV uint16
		wantOK     bool
		wantVer    uint16
	}{
		{"TLS1.3", tls.VersionTLS13, tls.VersionTLS13, true, tls.VersionTLS13},
		{"TLS1.2", tls.VersionTLS12, tls.VersionTLS12, true, tls.VersionTLS12},
		{"TLS1.1-rejected", tls.VersionTLS11, tls.VersionTLS11, false, 0},
		{"TLS1.0-rejected", tls.VersionTLS10, tls.VersionTLS10, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &net.Dialer{Timeout: 2 * time.Second}
			conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "cov.test",
				MinVersion:         tc.minV,
				MaxVersion:         tc.maxV,
				NextProtos:         []string{"http/1.1"},
			})
			if !tc.wantOK {
				if err == nil {
					_ = conn.Close()
					t.Fatalf("%s: handshake succeeded but should have been rejected", tc.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: handshake failed: %v", tc.name, err)
			}
			defer conn.Close()
			if got := conn.ConnectionState().Version; got != tc.wantVer {
				t.Fatalf("%s: negotiated version %#x, want %#x", tc.name, got, tc.wantVer)
			}
		})
	}
}

func TestTLSLargeResponseIntegrityAcrossProtocols(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	body := make([]byte, 200<<10)
	for i := range body {
		body[i] = byte(i)
	}
	srv := New(Config{
		Addr: addr, HTTPAddr: "-", LogRequests: false, MaxConnsPerIP: -1, Listeners: 1,
		Certs: []CertConfig{{Domain: "cov.test", Source: CertSelfSigned}},
	})
	srv.Router.GET("/big", func(req *Request, resp *Response) { resp.Status(200).Bytes(body) })
	go func() { _ = srv.ListenAndServeTLS() }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	waitForProxy(t, addr)

	for _, proto := range []string{"http/1.1", "h2"} {
		tr := &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: "cov.test", NextProtos: []string{proto}},
			ForceAttemptHTTP2: proto == "h2",
		}
		cl := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		for rep := 0; rep < 3; rep++ {
			resp, err := cl.Get("https://" + addr + "/big")
			if err != nil {
				t.Fatalf("%s rep %d: %v", proto, rep, err)
			}
			got, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != 200 || len(got) != len(body) || string(got) != string(body) {
				t.Fatalf("%s rep %d: status=%d len=%d want %d (integrity mismatch)", proto, rep, resp.StatusCode, len(got), len(body))
			}
		}
		tr.CloseIdleConnections()
	}
}
