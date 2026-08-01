//go:build linux

package core

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
)

// rawOrigin runs handle once per request, letting a test drive an upstream at
// the byte level rather than through an HTTP server.
//
// The request MUST be consumed before handle writes and before the connection
// closes. Closing a socket that still has unread data makes the kernel send RST
// rather than FIN, which discards whatever the proxy has not yet read — that
// truncates the response under test and looks exactly like a proxy bug.
func rawOrigin(t *testing.T, handle func(c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					req, rerr := http.ReadRequest(br)
					if rerr != nil {
						return
					}
					if req.ContentLength > 0 {
						_, _ = io.CopyN(io.Discard, req.Body, req.ContentLength)
					}
					handle(c)
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// capturingOrigin answers every request with 200 and publishes the request
// body it received, so a test can assert what actually reached the upstream.
// It reads requests itself rather than going through rawOrigin, because it needs
// the request body and rawOrigin already consumes and discards it.
func capturingOrigin(t *testing.T, got chan<- []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					req, rerr := http.ReadRequest(br)
					if rerr != nil {
						return
					}
					var body []byte
					if req.ContentLength > 0 {
						body, _ = io.ReadAll(io.LimitReader(req.Body, req.ContentLength))
					}
					select {
					case got <- body:
					default:
					}
					if _, werr := io.WriteString(c,
						"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); werr != nil {
						return
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// newLoopForTest builds an eventLoop wired well enough for unit tests that
// exercise exchange and inbound bookkeeping without touching the kernel. The
// real constructor also creates an epoll and an eventfd, which these tests do
// not need; beLoop.init issues no syscalls, so the backend half can be bound on
// its own. The loop is its own sink, exactly as in production.
func newLoopForTest() *eventLoop {
	l := &eventLoop{}
	l.beLoop.init(-1, &fpConfig{}, l)
	return l
}
