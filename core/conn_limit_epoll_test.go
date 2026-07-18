//go:build linux && amd64

package core

import "testing"

func xffReq(port, realIP string) *Request {
	return &Request{RemoteAddr: "10.0.0.1:" + port, Headers: [][2]string{{"X-Forwarded-For", realIP}}}
}

func TestAcquireIPConn_ProxyModeUsesRealIP(t *testing.T) {
	s := New(Config{ProxyMode: true, MaxConnsPerIP: 2})
	defer s.perIPConnLimiter.Stop()

	c1 := &epollConn{}
	if !c1.acquireIPConn(s, xffReq("1", "203.0.113.9")) {
		t.Fatal("conn1 should acquire")
	}
	if c1.ipKey != "203.0.113.9" {
		t.Fatalf("c1.ipKey=%q want the rewritten real IP 203.0.113.9", c1.ipKey)
	}
	c2 := &epollConn{}
	if !c2.acquireIPConn(s, xffReq("2", "203.0.113.9")) {
		t.Fatal("conn2 should acquire (limit 2)")
	}
	c3 := &epollConn{}
	if c3.acquireIPConn(s, xffReq("3", "203.0.113.9")) {
		t.Fatal("conn3 from same real IP must be rejected at limit 2")
	}
	c4 := &epollConn{}
	if !c4.acquireIPConn(s, xffReq("4", "203.0.113.10")) {
		t.Fatal("a different real IP must have its own budget")
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

func TestAcquireIPConn_IdempotentPerConn(t *testing.T) {
	s := New(Config{ProxyMode: true, MaxConnsPerIP: 1})
	defer s.perIPConnLimiter.Stop()
	c := &epollConn{}
	if !c.acquireIPConn(s, xffReq("1", "203.0.113.1")) {
		t.Fatal("first acquire should succeed")
	}
	if !c.acquireIPConn(s, xffReq("1", "203.0.113.1")) {
		t.Fatal("second call on same conn should return true without double-counting")
	}
	c2 := &epollConn{}
	if c2.acquireIPConn(s, xffReq("2", "203.0.113.1")) {
		t.Fatal("a new conn from same real IP must be rejected (idempotency did not double-count)")
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
