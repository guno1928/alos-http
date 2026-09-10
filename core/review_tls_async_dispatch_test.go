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
	"sync"
	"testing"
	"time"
)

const tlsSlowHandlerHold = 3 * 150 * time.Millisecond

func startSlowFastTLSServer(t *testing.T) string {
	t.Helper()
	addr := reserveLocalAddr(t)
	srv := New(Config{
		Addr:          addr,
		HTTPAddr:      "-",
		LogRequests:   false,
		MaxConnsPerIP: -1,
		Listeners:     1,
		Certs:         []CertConfig{{Domain: "async.test", Source: CertSelfSigned}},
	})
	srv.Router.GET("/slow", func(req *Request, resp *Response) {
		time.Sleep(tlsSlowHandlerHold)
		resp.Status(200).String("slow")
	})
	srv.Router.GET("/fast", func(req *Request, resp *Response) { resp.Status(200).String("fast") })
	go func() { _ = srv.ListenAndServeTLS() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 200 * time.Millisecond}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true, ServerName: "async.test"})
		if err == nil {
			_ = c.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("TLS server never came up")
	return ""
}

func tlsGet(t *testing.T, addr, path string) (string, time.Duration) {
	t.Helper()
	start := time.Now()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: "async.test"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: async.test\r\nConnection: close\r\n\r\n", path)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(body), time.Since(start)
}

func TestTLSSlowHandlerDoesNotStallOtherTLSConnections(t *testing.T) {
	addr := startSlowFastTLSServer(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		body, _ := tlsGet(t, addr, "/slow")
		if body != "slow" {
			t.Errorf("slow body = %q", body)
		}
	}()
	time.Sleep(50 * time.Millisecond)
	body, took := tlsGet(t, addr, "/fast")
	wg.Wait()
	if body != "fast" {
		t.Fatalf("fast body = %q", body)
	}
	if took > tlsSlowHandlerHold/2 {
		t.Fatalf("/fast over TLS took %v while /slow was in flight on the same worker; the TLS HTTP/1.1 handler runs synchronously on the event loop", took)
	}
}

func TestTLSPipelinedRequestsAfterAsyncDispatch(t *testing.T) {
	addr := startSlowFastTLSServer(t)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: "async.test"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET /fast HTTP/1.1\r\nHost: async.test\r\n\r\nGET /fast HTTP/1.1\r\nHost: async.test\r\n\r\nGET /fast HTTP/1.1\r\nHost: async.test\r\nConnection: close\r\n\r\n")
	br := bufio.NewReader(conn)
	for i := 0; i < 3; i++ {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("pipelined response %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "fast" {
			t.Fatalf("pipelined response %d body = %q", i, body)
		}
	}
}

func TestTLSHijackStillWorksAfterAsyncDispatch(t *testing.T) {
	addr := reserveLocalAddr(t)
	srv := New(Config{
		Addr:          addr,
		HTTPAddr:      "-",
		LogRequests:   false,
		MaxConnsPerIP: -1,
		Listeners:     1,
		Certs:         []CertConfig{{Domain: "async.test", Source: CertSelfSigned}},
	})
	srv.Router.GET("/ws", func(req *Request, resp *Response) {
		ServeWebSocket(req, resp, func(ws *WSConn) {
			defer ws.Close()
			_, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			_ = ws.WriteText("echo:" + string(data))
		})
	})
	go func() { _ = srv.ListenAndServeTLS() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 200 * time.Millisecond}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true, ServerName: "async.test"})
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: "async.test"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET /ws HTTP/1.1\r\nHost: async.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("upgrade response: %v", err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("upgrade status = %d", resp.StatusCode)
	}
	frame := []byte{0x81, 0x85, 1, 2, 3, 4}
	for i, b := range []byte("hello") {
		frame = append(frame, b^frame[2+i%4])
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		t.Fatalf("read echo header: %v", err)
	}
	payload := make([]byte, int(hdr[1]&0x7f))
	if _, err := io.ReadFull(br, payload); err != nil {
		t.Fatalf("read echo payload: %v", err)
	}
	if string(payload) != "echo:hello" {
		t.Fatalf("echo = %q", payload)
	}
}
