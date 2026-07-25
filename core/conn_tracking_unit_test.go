//go:build linux && amd64

package core

import (
	"strconv"
	"sync"
	"testing"
)

func liveCount(l *perIPConnLimiter, ip string) int64 {
	if c, ok := l.m.Load(ip); ok {
		return c.n.Load()
	}
	return 0
}

func TestCT_PerIPConnLimiter(t *testing.T) {
	t.Run("acquire up to limit then reject", func(t *testing.T) {
		l := newPerIPConnLimiter()
		defer l.Stop()
		for i := 0; i < 5; i++ {
			if !l.acquire("1.1.1.1", 5) {
				t.Fatalf("acquire %d should succeed", i)
			}
		}
		if l.acquire("1.1.1.1", 5) {
			t.Fatal("6th acquire must be rejected at limit 5")
		}
	})
	t.Run("release frees exactly one slot", func(t *testing.T) {
		l := newPerIPConnLimiter()
		defer l.Stop()
		for i := 0; i < 5; i++ {
			l.acquire("1.1.1.1", 5)
		}
		l.release("1.1.1.1")
		if !l.acquire("1.1.1.1", 5) {
			t.Fatal("after one release a new acquire must succeed")
		}
		if l.acquire("1.1.1.1", 5) {
			t.Fatal("only one slot was freed; second acquire must be rejected")
		}
	})
	t.Run("different IPs have independent budgets", func(t *testing.T) {
		l := newPerIPConnLimiter()
		defer l.Stop()
		if !l.acquire("1.1.1.1", 1) {
			t.Fatal("first IP acquire should succeed")
		}
		if l.acquire("1.1.1.1", 1) {
			t.Fatal("first IP already at limit")
		}
		if !l.acquire("2.2.2.2", 1) {
			t.Fatal("a different IP must have its own budget")
		}
	})
	t.Run("empty IP always allowed", func(t *testing.T) {
		l := newPerIPConnLimiter()
		defer l.Stop()
		for i := 0; i < 100; i++ {
			if !l.acquire("", 1) {
				t.Fatal("empty IP must never be limited")
			}
		}
	})
	t.Run("non-positive limit always allowed", func(t *testing.T) {
		l := newPerIPConnLimiter()
		defer l.Stop()
		for i := 0; i < 100; i++ {
			if !l.acquire("x", 0) || !l.acquire("y", -1) {
				t.Fatal("limit <= 0 must never reject")
			}
		}
	})
	t.Run("release below zero does not underflow", func(t *testing.T) {
		l := newPerIPConnLimiter()
		defer l.Stop()
		l.release("z")
		l.release("z")
		l.release("z")
		if !l.acquire("z", 1) {
			t.Fatal("count must not have gone negative")
		}
		if l.acquire("z", 1) {
			t.Fatal("count should be exactly 1 after a single acquire")
		}
	})
	t.Run("nil limiter is a no-op allow", func(t *testing.T) {
		var l *perIPConnLimiter
		if !l.acquire("a", 1) {
			t.Fatal("nil limiter acquire must return true")
		}
		l.release("a")
		l.Stop()
	})
	t.Run("balanced concurrent acquire/release leaves count at zero", func(t *testing.T) {
		l := newPerIPConnLimiter()
		defer l.Stop()
		var wg sync.WaitGroup
		for i := 0; i < 500; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if l.acquire("cc", 1<<30) {
					l.release("cc")
				}
			}()
		}
		wg.Wait()
		if got := liveCount(l, "cc"); got != 0 {
			t.Fatalf("balanced acquire/release left count=%d, want 0", got)
		}
	})
	t.Run("held concurrent acquires all counted", func(t *testing.T) {
		l := newPerIPConnLimiter()
		defer l.Stop()
		var wg sync.WaitGroup
		var ok sync.Map
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				if l.acquire("hh", 50) {
					ok.Store(id, true)
				}
			}(i)
		}
		wg.Wait()
		n := 0
		ok.Range(func(_, _ any) bool { n++; return true })
		if n != 50 {
			t.Fatalf("expected all 50 concurrent acquires to succeed under limit 50, got %d", n)
		}
		if l.acquire("hh", 50) {
			t.Fatal("51st acquire must be rejected")
		}
	})
	t.Run("sweep removes only zero-count entries", func(t *testing.T) {
		l := newPerIPConnLimiter()
		defer l.Stop()
		l.acquire("keep", 10)
		l.acquire("drop", 10)
		l.release("drop")
		l.m.Range(func(key string, c *ipReqCounter) bool {
			if c.n.Load() <= 0 {
				l.m.Delete(key)
			}
			return true
		})
		if _, ok := l.m.Load("drop"); ok {
			t.Fatal("zero-count entry should have been swept")
		}
		if _, ok := l.m.Load("keep"); !ok {
			t.Fatal("nonzero-count entry must be retained")
		}
	})
}

func TestCT_PerIPRequestLimiter(t *testing.T) {
	t.Run("acquire up to limit then reject", func(t *testing.T) {
		l := newPerIPRequestLimiter()
		defer l.Stop()
		for i := 0; i < 3; i++ {
			if !l.acquire("9.9.9.9", 3) {
				t.Fatalf("in-flight acquire %d should succeed", i)
			}
		}
		if l.acquire("9.9.9.9", 3) {
			t.Fatal("4th concurrent request must be rejected at limit 3")
		}
	})
	t.Run("release makes it idle-safe", func(t *testing.T) {
		l := newPerIPRequestLimiter()
		defer l.Stop()
		for i := 0; i < 1000; i++ {
			if !l.acquire("idle", 2) {
				t.Fatalf("request %d should succeed once prior ones are released", i)
			}
			l.release("idle")
		}
	})
	t.Run("different real IPs counted separately", func(t *testing.T) {
		l := newPerIPRequestLimiter()
		defer l.Stop()
		if !l.acquire("203.0.113.1", 1) {
			t.Fatal("first client should acquire")
		}
		if l.acquire("203.0.113.1", 1) {
			t.Fatal("same client at limit 1")
		}
		if !l.acquire("203.0.113.2", 1) {
			t.Fatal("a different client must have its own in-flight budget")
		}
	})
	t.Run("empty IP and non-positive limit never reject", func(t *testing.T) {
		l := newPerIPRequestLimiter()
		defer l.Stop()
		for i := 0; i < 100; i++ {
			if !l.acquire("", 1) || !l.acquire("k", 0) {
				t.Fatal("empty IP or limit<=0 must never reject")
			}
		}
	})
	t.Run("balanced concurrent requests do not leak", func(t *testing.T) {
		l := newPerIPRequestLimiter()
		defer l.Stop()
		var wg sync.WaitGroup
		for i := 0; i < 500; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if l.acquire("rr", 1<<30) {
					l.release("rr")
				}
			}()
		}
		wg.Wait()
		if !l.acquire("rr", 1) {
			t.Fatal("count must be 0 after balanced acquire/release")
		}
		if l.acquire("rr", 1) {
			t.Fatal("count should be exactly 1")
		}
	})
}

func TestCT_AcquireIPConn_ProxyVsDirect(t *testing.T) {
	t.Run("proxy mode rewrites real IP and never limits", func(t *testing.T) {
		s := New(Config{ProxyMode: true, MaxConnsPerIP: 2})
		defer s.perIPConnLimiter.Stop()
		for i := 0; i < 50; i++ {
			req := xffReq(strconv.Itoa(i), "198.51.100.7")
			c := &epollConn{}
			if !c.acquireIPConn(s, req) {
				t.Fatalf("conn %d from same real IP must acquire behind a proxy", i)
			}
			if req.RemoteAddr != "198.51.100.7" {
				t.Fatalf("conn %d RemoteAddr=%q want rewritten real IP", i, req.RemoteAddr)
			}
		}
	})
	t.Run("different XFF IPs on the pooled path each rewrite independently", func(t *testing.T) {
		s := New(Config{ProxyMode: true, MaxConnsPerIP: 1})
		defer s.perIPConnLimiter.Stop()
		a := xffReq("1", "203.0.113.10")
		b := xffReq("2", "203.0.113.11")
		ca, cb := &epollConn{}, &epollConn{}
		if !ca.acquireIPConn(s, a) || !cb.acquireIPConn(s, b) {
			t.Fatal("both conns must acquire behind a proxy regardless of limit")
		}
		if a.RemoteAddr != "203.0.113.10" || b.RemoteAddr != "203.0.113.11" {
			t.Fatalf("real IPs mis-rewritten: a=%q b=%q", a.RemoteAddr, b.RemoteAddr)
		}
	})
	t.Run("non-proxy defers to accept and does not set ipHeld", func(t *testing.T) {
		s := New(Config{MaxConnsPerIP: 1})
		defer s.perIPConnLimiter.Stop()
		c := &epollConn{}
		if !c.acquireIPConn(s, &Request{RemoteAddr: "10.0.0.1:5"}) {
			t.Fatal("non-proxy acquireIPConn must return true")
		}
		if c.ipHeld {
			t.Fatal("non-proxy acquireIPConn must not hold a slot here")
		}
	})
	t.Run("disabled limiter is always a no-op", func(t *testing.T) {
		s := New(Config{ProxyMode: true, MaxConnsPerIP: -1})
		if s.perIPConnLimiter != nil {
			t.Fatal("negative MaxConnsPerIP must disable the connection limiter")
		}
		c := &epollConn{}
		for i := 0; i < 100; i++ {
			if !c.acquireIPConn(s, xffReq("1", "203.0.113.1")) {
				t.Fatal("disabled limiter must always allow")
			}
		}
	})
}

func TestCT_RealIPRewrite(t *testing.T) {
	m := newTrustedProxyMatcher(nil, true)
	cases := []struct {
		name       string
		remote     string
		headers    [][2]string
		wantRemote string
	}{
		{"single xff", "10.0.0.1:1", [][2]string{{"X-Forwarded-For", "203.0.113.9"}}, "203.0.113.9"},
		{"xff chain uses rightmost", "10.0.0.1:1", [][2]string{{"X-Forwarded-For", "1.2.3.4, 203.0.113.9"}}, "203.0.113.9"},
		{"xff spaces trimmed", "10.0.0.1:1", [][2]string{{"X-Forwarded-For", "  203.0.113.9  "}}, "203.0.113.9"},
		{"x-real-ip fallback", "10.0.0.1:1", [][2]string{{"X-Real-IP", "203.0.113.5"}}, "203.0.113.5"},
		{"no headers keeps socket", "10.0.0.1:1", nil, "10.0.0.1:1"},
		{"invalid xff keeps socket", "10.0.0.1:1", [][2]string{{"X-Forwarded-For", "not-an-ip"}}, "10.0.0.1:1"},
		{"ipv6 xff", "10.0.0.1:1", [][2]string{{"X-Forwarded-For", "2001:db8::1"}}, "2001:db8::1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := &Request{RemoteAddr: c.remote, Headers: c.headers}
			applyTrustedRealIP(req, m)
			if req.RemoteAddr != c.wantRemote {
				t.Fatalf("RemoteAddr=%q want %q", req.RemoteAddr, c.wantRemote)
			}
		})
	}
}

func TestCT_ExtractIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.2.3.4:80", "1.2.3.4"},
		{"1.2.3.4", "1.2.3.4"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"", ""},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := extractIP(c.in); got != c.want {
				t.Fatalf("extractIP(%q)=%q want %q", c.in, got, c.want)
			}
		})
	}
}

func TestCT_TrustedProxyMatcher(t *testing.T) {
	t.Run("trust-all accepts any peer", func(t *testing.T) {
		m := newTrustedProxyMatcher(nil, true)
		if !m.active || !m.allows("8.8.8.8:1") {
			t.Fatal("trust-all matcher must accept any peer")
		}
	})
	t.Run("inactive when empty and not trust-all", func(t *testing.T) {
		m := newTrustedProxyMatcher(nil, false)
		if m.active || m.allows("10.0.0.1:1") {
			t.Fatal("empty non-trust-all matcher must be inactive")
		}
	})
	t.Run("cidr membership", func(t *testing.T) {
		m := newTrustedProxyMatcher([]string{"10.0.0.0/8"}, false)
		if !m.allows("10.9.9.9:1") {
			t.Fatal("10.9.9.9 must be inside 10.0.0.0/8")
		}
		if m.allows("11.0.0.1:1") {
			t.Fatal("11.0.0.1 must be outside 10.0.0.0/8")
		}
	})
	t.Run("explicit ip membership", func(t *testing.T) {
		m := newTrustedProxyMatcher([]string{"192.168.1.1"}, false)
		if !m.allows("192.168.1.1:1") {
			t.Fatal("exact IP must match")
		}
		if m.allows("192.168.1.2:1") {
			t.Fatal("non-listed IP must not match")
		}
	})
}
