//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

const (
	shutdownIdleLimit   = 2 * time.Second
	shutdownIdleBudget  = 500 * time.Millisecond
	shutdownSlowHandler = 150 * time.Millisecond
	h2FrameTypeSettings = 0x4
	h2FrameTypeGoAway   = 0x7
)

func startIdleShutdownServer(t *testing.T, useTLS bool) (*Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	cfg := Config{
		Addr: addr, HTTPAddr: "-",
		LogRequests: false, MaxConnsPerIP: -1, Listeners: 1,
	}
	if useTLS {
		cfg.Certs = []CertConfig{{Domain: "shutdown.test", Source: CertSelfSigned}}
	} else {
		cfg.PlainHTTP = true
	}
	srv := New(cfg)
	srv.Router.GET("/", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	srv.Router.GET("/slow", func(req *Request, resp *Response) {
		time.Sleep(shutdownSlowHandler)
		resp.Status(200).String("slow")
	})
	go func() {
		if useTLS {
			_ = srv.ListenAndServeTLS()
		} else {
			_ = srv.ListenAndServe()
		}
	}()
	waitForProxy(t, addr)
	return srv, addr
}

func shutdownDial(t *testing.T, addr string, useTLS bool, alpn string) net.Conn {
	t.Helper()
	if !useTLS {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return c
	}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: shutdownIdleLimit}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: "shutdown.test", NextProtos: []string{alpn}})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	return c
}

func idleH1Client(t *testing.T, addr string, useTLS bool) net.Conn {
	t.Helper()
	c := shutdownDial(t, addr, useTLS, "http/1.1")
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("first response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return c
}

func idleH2Client(t *testing.T, addr string, useTLS bool) net.Conn {
	t.Helper()
	c := shutdownDial(t, addr, useTLS, "h2")
	fmt.Fprint(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	_, _ = c.Write([]byte{0, 0, 0, h2FrameTypeSettings, 0, 0, 0, 0, 0})
	readFrameType(t, c, h2FrameTypeSettings, "server settings")
	return c
}

func readFrameType(t *testing.T, c net.Conn, want byte, what string) {
	t.Helper()
	var hdr [h2FrameHeaderSize]byte
	_ = c.SetReadDeadline(time.Now().Add(shutdownIdleLimit))
	for {
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		payload := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		if _, err := io.CopyN(io.Discard, c, int64(payload)); err != nil {
			t.Fatalf("%s payload: %v", what, err)
		}
		if hdr[3] == want {
			return
		}
	}
}

func TestShutdownClosesIdleConnectionsPromptly(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "plain"
		if useTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) { testShutdownClosesIdle(t, useTLS) })
	}
}

func testShutdownClosesIdle(t *testing.T, useTLS bool) {
	srv, addr := startIdleShutdownServer(t, useTLS)
	h1 := idleH1Client(t, addr, useTLS)
	defer h1.Close()
	h2 := idleH2Client(t, addr, useTLS)
	defer h2.Close()

	slow := shutdownDial(t, addr, useTLS, "http/1.1")
	defer slow.Close()
	fmt.Fprintf(slow, "GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	time.Sleep(15 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), shutdownIdleLimit)
	defer cancel()
	start := time.Now()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown returned %v after %v", err, time.Since(start))
	}
	if took := time.Since(start); took > shutdownIdleBudget {
		t.Fatalf("shutdown took %v with only idle clients and one slow request", took)
	}

	_ = h1.SetReadDeadline(time.Now().Add(shutdownIdleLimit))
	if _, err := h1.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("idle HTTP/1.1 connection should be closed, read returned %v", err)
	}
	readFrameType(t, h2, h2FrameTypeGoAway, "idle HTTP/2 connection should receive GOAWAY")

	resp, err := http.ReadResponse(bufio.NewReader(slow), nil)
	if err != nil {
		t.Fatalf("in-flight request must complete across shutdown: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "slow" {
		t.Fatalf("in-flight request got %d %q", resp.StatusCode, body)
	}
}
