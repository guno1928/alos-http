//go:build linux && amd64

package core

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/guno1928/turbo"
)

func TestH1ConnectionsShareBodyBudget(t *testing.T) {
	srv := New(Config{MaxInFlightBodyBytes: 1024, MaxConnsPerIP: -1})
	w := &epollWorker{server: srv}
	a := &epollConn{worker: w}
	b := &epollConn{worker: w}
	if !a.reserveH1BodyBudget(srv, 768) {
		t.Fatal("first H1 body should reserve capacity")
	}
	if b.reserveH1BodyBudget(srv, 257) {
		t.Fatal("second H1 body exceeded the aggregate capacity")
	}
	a.releaseH1BodyBudget()
	if !b.reserveH1BodyBudget(srv, 1024) {
		t.Fatal("released H1 body capacity was not reusable")
	}
	b.releaseH1BodyBudget()
}

func TestChunkedBufferedBodyBoundedBySmallerReadCap(t *testing.T) {
	var srv *Server
	addr := startH2FixServer(t, func(c *Config) {
		c.MaxBodySize = 100 << 20
		c.MaxReadSize = 2 * epollReadBufCap
	}, func(s *Server) {
		srv = s
		s.Router.POST("/body", func(req *Request, resp *Response) { resp.Status(200).String(strconv.Itoa(len(req.Body))) })
	})
	for _, size := range []int{5, 3 * epollReadBufCap} {
		body := strings.Repeat("x", size)
		conn := dialH1Budget(t, addr, fmt.Sprintf("POST /body HTTP/1.1\r\nHost: body.test\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", size, body))
		status, reply := h1BudgetOutcome(conn)
		accepted := status == 200 && reply == strconv.Itoa(size)
		if wantAccepted := size < epollReadBufCap; accepted != wantAccepted {
			t.Fatalf("%d-byte chunked upload with a %d-byte read cap: status %d reply %q", size, 2*epollReadBufCap, status, reply)
		}
		_ = conn.Close()
	}
	start := turbo.Now()
	for srv.inFlightBodyBytes.Load() != 0 && turbo.Since(start) < h2FixCeiling {
		turbo.Sleep(h1BudgetPollPeriod)
	}
	if held := srv.inFlightBodyBytes.Load(); held != 0 {
		t.Fatalf("finished or rejected uploads retained %d body budget bytes", held)
	}
}
