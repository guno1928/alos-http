//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestHTTP10RequestWithoutKeepAliveIsClosed(t *testing.T) {
	addr := reserveLocalAddr(t)
	s := New(Config{Addr: addr, PlainHTTP: true, Listeners: 1, MaxConnsPerIP: 1 << 16, HTTPAddr: "-", LogRequests: false})
	s.Router.GET("/ping", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	s.Router.GET("/legacy", func(req *Request, resp *Response) { resp.Status(200).String("proto=" + req.Proto) })
	go func() { _ = s.ListenAndServeEpollH2(addr) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	if !waitServerReady(addr) {
		t.Fatal("server not ready")
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	fmt.Fprint(conn, "GET /legacy HTTP/1.0\r\nHost: t\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "proto=HTTP/1.0" {
		t.Fatalf("body = %q; request Proto is not being recorded", body)
	}
	if !resp.Close {
		t.Fatalf("response to an HTTP/1.0 request without Connection: keep-alive advertised keep-alive (headers %v)", resp.Header)
	}
	_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("connection still open after an HTTP/1.0 response: read returned %v; a 1.0 client waits for EOF forever", err)
	}
}

func TestHTTP10RequestWithKeepAliveStaysOpen(t *testing.T) {
	addr := reserveLocalAddr(t)
	s := New(Config{Addr: addr, PlainHTTP: true, Listeners: 1, MaxConnsPerIP: 1 << 16, HTTPAddr: "-", LogRequests: false})
	s.Router.GET("/ping", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	go func() { _ = s.ListenAndServeEpollH2(addr) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	if !waitServerReady(addr) {
		t.Fatal("server not ready")
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	for i := 0; i < 2; i++ {
		fmt.Fprint(conn, "GET /ping HTTP/1.0\r\nHost: t\r\nConnection: keep-alive\r\n\r\n")
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
	}
}
