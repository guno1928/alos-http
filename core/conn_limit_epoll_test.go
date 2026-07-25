//go:build linux && amd64

package core

import (
	"net"
	"testing"
)

func xffReq(port, realIP string) *Request {
	return &Request{RemoteAddr: "10.0.0.1:" + port, Headers: [][2]string{{"X-Forwarded-For", realIP}}}
}

func TestHandoffConn_ReleasesIPSlotOnClose(t *testing.T) {
	s := New(Config{MaxConnsPerIP: 1})
	defer s.perIPConnLimiter.Stop()

	if !s.perIPConnLimiter.acquire("203.0.113.5", s.maxConnsPerIP) {
		t.Fatal("first acquire should succeed")
	}

	_, srvSide := net.Pipe()
	tracked := s.trackHandoffConn(srvSide, "203.0.113.5", false)
	if tracked == nil {
		t.Fatal("trackHandoffConn returned nil")
	}

	if s.perIPConnLimiter.acquire("203.0.113.5", s.maxConnsPerIP) {
		t.Fatal("slot must stay held while the streamed connection is alive")
	}

	_ = tracked.Close()

	if !s.perIPConnLimiter.acquire("203.0.113.5", s.maxConnsPerIP) {
		t.Fatal("slot must be released once the streamed connection closes")
	}
}

func TestAcquireIPConn_ProxyModeRewritesRealIPNoLimit(t *testing.T) {
	s := New(Config{ProxyMode: true, MaxConnsPerIP: 2})
	defer s.perIPConnLimiter.Stop()

	req := xffReq("1", "203.0.113.9")
	c1 := &epollConn{}
	if !c1.acquireIPConn(s, req) {
		t.Fatal("conn1 should acquire")
	}
	if req.RemoteAddr != "203.0.113.9" {
		t.Fatalf("RemoteAddr=%q want rewritten real IP 203.0.113.9", req.RemoteAddr)
	}
	for i := 0; i < 10; i++ {
		c := &epollConn{}
		if !c.acquireIPConn(s, xffReq("2", "203.0.113.9")) {
			t.Fatalf("conn %d from same real IP must acquire; the per-conn limit is not enforced behind a trusted proxy", i)
		}
	}
}

func TestAcquireIPConn_NonProxyDeferredToAccept(t *testing.T) {
	s := New(Config{MaxConnsPerIP: 1})
	defer s.perIPConnLimiter.Stop()
	c := &epollConn{}
	if !c.acquireIPConn(s, &Request{RemoteAddr: "10.0.0.1:1"}) {
		t.Fatal("non-proxy acquireIPConn must return true (enforced at accept, not here)")
	}
	if c.ipHeld {
		t.Fatal("non-proxy acquireIPConn must not set ipHeld")
	}
}

func TestAcquireIPConn_ProxyModeNoLimitAcrossConns(t *testing.T) {
	s := New(Config{ProxyMode: true, MaxConnsPerIP: 1})
	defer s.perIPConnLimiter.Stop()
	c := &epollConn{}
	if !c.acquireIPConn(s, xffReq("1", "203.0.113.1")) {
		t.Fatal("first acquire should succeed")
	}
	if !c.acquireIPConn(s, xffReq("1", "203.0.113.1")) {
		t.Fatal("second call on same conn should return true")
	}
	c2 := &epollConn{}
	if !c2.acquireIPConn(s, xffReq("2", "203.0.113.1")) {
		t.Fatal("a new conn from the same real IP must also acquire (no per-conn limit behind a trusted proxy)")
	}
}

func TestAcquireIPConn_DisabledIsNoop(t *testing.T) {
	s := New(Config{ProxyMode: true, MaxConnsPerIP: -1})
	c := &epollConn{}
	for i := 0; i < 100; i++ {
		if !c.acquireIPConn(s, xffReq("1", "203.0.113.1")) {
			t.Fatal("disabled limiter must always allow")
		}
	}
}
