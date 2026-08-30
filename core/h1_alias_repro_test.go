//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type retainedHeaders struct {
	mu sync.Mutex
	m  map[string]string
}

func newRetainedHeaders() *retainedHeaders { return &retainedHeaders{m: make(map[string]string)} }

func (r *retainedHeaders) put(id, val string) {
	r.mu.Lock()
	r.m[id] = val
	r.mu.Unlock()
}

func (r *retainedHeaders) get(id string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[id]
}

func rawHeaderValue(req *Request, name string) string {
	for i := range req.Headers {
		if EqualFoldASCII(req.Headers[i][0], name) {
			return req.Headers[i][1]
		}
	}
	return ""
}

func reserveLocalAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func waitServerReady(addr string) bool {
	for i := 0; i < 300; i++ {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			fmt.Fprint(c, "GET /ping HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
			line, _ := bufio.NewReader(c).ReadString('\n')
			_ = c.Close()
			if strings.Contains(line, "200") {
				return true
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	return false
}

func drainResponse(br *bufio.Reader) error {
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

func TestH1HeaderAliasRetention(t *testing.T) {
	retained := newRetainedHeaders()
	addr := reserveLocalAddr(t)
	s := New(Config{
		Addr:          addr,
		PlainHTTP:     true,
		Listeners:     1,
		MaxConnsPerIP: 1 << 16,
		ReadTimeout:   30 * time.Second,
		IdleTimeout:   30 * time.Second,
	})
	s.Router.GET("/ping", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	s.Router.GET("/t", func(req *Request, resp *Response) {
		retained.put(rawHeaderValue(req, "X-Id"), rawHeaderValue(req, "X-Trace"))
		resp.Status(200).String("ok")
	})
	go func() { _ = s.ListenAndServeEpollH2(addr) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	if !waitServerReady(addr) {
		t.Fatalf("server did not come up on %s", addr)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)

	aVal := strings.Repeat("A", 220)
	bVal := strings.Repeat("B", 220)

	fmt.Fprintf(conn, "GET /t HTTP/1.1\r\nHost: t\r\nX-Id: reqA\r\nX-Trace: %s\r\nConnection: keep-alive\r\n\r\n", aVal)
	if err := drainResponse(br); err != nil {
		t.Fatalf("read response A: %v", err)
	}

	fmt.Fprintf(conn, "GET /t HTTP/1.1\r\nHost: t\r\nX-Id: reqB\r\nX-Trace: %s\r\nConnection: close\r\n\r\n", bVal)
	if err := drainResponse(br); err != nil && err != io.EOF {
		t.Fatalf("read response B: %v", err)
	}

	gotA := retained.get("reqA")
	if gotA != aVal {
		preview := gotA
		if len(preview) > 24 {
			preview = preview[:24]
		}
		t.Fatalf("retained request-A X-Trace was mutated by a later keep-alive request on the same connection: got %q (len %d), want %d 'A's; read-buffer aliasing bug", preview, len(gotA), len(aVal))
	}
}
