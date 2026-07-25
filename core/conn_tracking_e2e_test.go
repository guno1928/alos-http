//go:build linux && amd64 && e2e

package core

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var ctPort int32 = 18300

func ctNextAddr() string {
	p := atomic.AddInt32(&ctPort, 1)
	return fmt.Sprintf(":%d", p)
}

func ctRegister(s *Server) {
	s.Router.GET("/x", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	s.Router.GET("/slow", func(req *Request, resp *Response) {
		time.Sleep(700 * time.Millisecond)
		resp.Status(200).String("slow")
	})
	s.Router.GET("/large", func(req *Request, resp *Response) {
		resp.Status(200).String(strings.Repeat("z", 20<<20))
	})
	s.Router.GET("/stream", func(req *Request, resp *Response) {
		sw := resp.EnsureStreamWriter()
		if sw == nil {
			resp.Status(500).String("no sw")
			return
		}
		resp.SetStreamer(sw)
		_ = sw.WriteHeader(200, nil, "text/plain")
		for i := 0; i < 3; i++ {
			_ = sw.WriteChunk([]byte("chunk\n"))
			_ = sw.Flush()
		}
		_ = sw.Close()
	})
	s.Router.GET("/sse", func(req *Request, resp *Response) {
		sse := resp.SSE()
		if sse == nil {
			resp.Status(500).String("no sse")
			return
		}
		_ = sse.Send("tick", "one")
		_ = sse.Close()
	})
	s.Router.GET("/ws", func(req *Request, resp *Response) {
		ServeWebSocket(req, resp, func(ws *WSConn) {
			for {
				_, msg, err := ws.ReadMessage()
				if err != nil {
					return
				}
				if ws.WriteText(string(msg)) != nil {
					return
				}
			}
		})
	})
	s.Router.GET("/hijack", func(req *Request, resp *Response) {
		c := req.HijackConn()
		if c == nil {
			resp.Status(500).String("no hijack")
			return
		}
		go func() {
			defer c.Close()
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi"))
			buf := make([]byte, 64)
			for {
				if _, err := c.Read(buf); err != nil {
					return
				}
			}
		}()
	})
}

func ctWaitReady(addr string) bool {
	for i := 0; i < 250; i++ {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			fmt.Fprint(c, "GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
			line, _ := bufio.NewReader(c).ReadString('\n')
			_ = c.Close()
			if strings.Contains(line, "200") {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func ctStart(t *testing.T, cfg Config) (*Server, string) {
	addr := ctNextAddr()
	cfg.Addr = addr
	cfg.PlainHTTP = true
	cfg.WebSocketOriginMode = WSOriginOff
	s := New(cfg)
	ctRegister(s)
	go func() { _ = s.ListenAndServeEpollH2(addr) }()
	if !ctWaitReady(addr) {
		t.Fatalf("server on %s did not come up", addr)
	}
	if s.perIPConnLimiter != nil {
		ctWaitCount(t, s, ctIP, 0, 5*time.Second, "server baseline must settle to zero after readiness checks")
	}
	return s, addr
}

func ctCount(s *Server, ip string) int64 {
	if s.perIPConnLimiter == nil {
		return -1
	}
	if c, ok := s.perIPConnLimiter.m.Load(ip); ok {
		return c.n.Load()
	}
	return 0
}

func ctWaitCount(t *testing.T, s *Server, ip string, want int64, within time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if ctCount(s, ip) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: count[%s]=%d want %d (after %v)", msg, ip, ctCount(s, ip), want, within)
}

func ctDialReq(t *testing.T, addr, path string) net.Conn {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: t\r\n\r\n", path)
	return conn
}

func ctWSDial(t *testing.T, addr string) net.Conn {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	fmt.Fprint(conn, "GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "101") {
		t.Fatalf("ws upgrade expected 101, got %q err=%v", line, err)
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("ws header read: %v", err)
		}
		if h == "\r\n" || h == "\n" {
			break
		}
	}
	return conn
}

const ctIP = "127.0.0.1"

func TestCTE2E_SlotHeldThenReleasedByType(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 1, MaxConnsPerIP: 1000, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second})

	types := []struct {
		name string
		open func() net.Conn
	}{
		{"plain-keepalive", func() net.Conn {
			c := ctDialReq(t, addr, "/x")
			_, _ = bufio.NewReader(c).ReadString('\n')
			return c
		}},
		{"stream", func() net.Conn {
			c := ctDialReq(t, addr, "/stream")
			_, _ = bufio.NewReader(c).ReadString('\n')
			return c
		}},
		{"sse", func() net.Conn {
			c := ctDialReq(t, addr, "/sse")
			_, _ = bufio.NewReader(c).ReadString('\n')
			return c
		}},
		{"websocket", func() net.Conn { return ctWSDial(t, addr) }},
		{"hijack", func() net.Conn {
			c := ctDialReq(t, addr, "/hijack")
			_, _ = bufio.NewReader(c).ReadString('\n')
			return c
		}},
	}

	for _, tc := range types {
		t.Run(tc.name, func(t *testing.T) {
			ctWaitCount(t, s, ctIP, 0, 3*time.Second, "baseline before "+tc.name)
			conn := tc.open()
			ctWaitCount(t, s, ctIP, 1, 3*time.Second, tc.name+" should hold exactly one slot while alive")
			_ = conn.Close()
			ctWaitCount(t, s, ctIP, 0, 5*time.Second, tc.name+" must release its slot on close")
		})
	}
}

func TestCTE2E_KeepAliveMultiRequestOneSlot(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 1, MaxConnsPerIP: 1000, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second})
	ctWaitCount(t, s, ctIP, 0, 3*time.Second, "baseline")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	for i := 0; i < 5; i++ {
		fmt.Fprint(conn, "GET /x HTTP/1.1\r\nHost: t\r\n\r\n")
		line, err := br.ReadString('\n')
		if err != nil || !strings.Contains(line, "200") {
			t.Fatalf("request %d expected 200, got %q err=%v", i, line, err)
		}
		for {
			h, _ := br.ReadString('\n')
			if h == "\r\n" || h == "\n" || h == "" {
				break
			}
		}
	}
	if got := ctCount(s, ctIP); got != 1 {
		t.Fatalf("keep-alive connection with 5 requests must hold exactly 1 slot, got %d", got)
	}
	_ = conn.Close()
	ctWaitCount(t, s, ctIP, 0, 5*time.Second, "slot released after keep-alive close")
}

func TestCTE2E_NoLeakUnderChurn(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 2, MaxConnsPerIP: 100000, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second})

	churn := []struct {
		name string
		open func() net.Conn
	}{
		{"plain", func() net.Conn {
			c := ctDialReq(t, addr, "/x")
			_, _ = bufio.NewReader(c).ReadString('\n')
			return c
		}},
		{"stream", func() net.Conn {
			c := ctDialReq(t, addr, "/stream")
			_, _ = bufio.NewReader(c).ReadString('\n')
			return c
		}},
		{"sse", func() net.Conn {
			c := ctDialReq(t, addr, "/sse")
			_, _ = bufio.NewReader(c).ReadString('\n')
			return c
		}},
		{"websocket", func() net.Conn { return ctWSDial(t, addr) }},
		{"hijack", func() net.Conn {
			c := ctDialReq(t, addr, "/hijack")
			_, _ = bufio.NewReader(c).ReadString('\n')
			return c
		}},
	}

	for _, tc := range churn {
		t.Run(tc.name, func(t *testing.T) {
			ctWaitCount(t, s, ctIP, 0, 5*time.Second, "baseline before churn "+tc.name)
			for i := 0; i < 40; i++ {
				c := tc.open()
				_ = c.Close()
			}
			ctWaitCount(t, s, ctIP, 0, 8*time.Second, tc.name+": 40 open/close must leave zero leaked slots")
		})
	}
}

func TestCTE2E_IdleTimeoutReapsAndReleases(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 1, MaxConnsPerIP: 1000, ReadTimeout: 30 * time.Second, IdleTimeout: 1 * time.Second})
	ctWaitCount(t, s, ctIP, 0, 3*time.Second, "baseline")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	fmt.Fprint(conn, "GET /x HTTP/1.1\r\nHost: t\r\n\r\n")
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "200") {
		t.Fatalf("expected 200, got %q", line)
	}
	ctWaitCount(t, s, ctIP, 1, 3*time.Second, "slot held while connection is open")
	ctWaitCount(t, s, ctIP, 0, 6*time.Second, "idle timeout must close the idle keep-alive and release its slot")
	_ = conn.Close()
}

func TestCTE2E_ReadTimeoutClosesAndReleases(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 1, MaxConnsPerIP: 1000, ReadTimeout: 1 * time.Second, IdleTimeout: 30 * time.Second})
	ctWaitCount(t, s, ctIP, 0, 3*time.Second, "baseline")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "GET /x HTTP/1.1\r\nHost: t\r\n")
	ctWaitCount(t, s, ctIP, 1, 3*time.Second, "slot held after accept")
	ctWaitCount(t, s, ctIP, 0, 6*time.Second, "read timeout must close the stalled request and release its slot")
	_ = conn.Close()
}

func TestCTE2E_ClientAbortReleases(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 1, MaxConnsPerIP: 1000, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second})
	ctWaitCount(t, s, ctIP, 0, 3*time.Second, "baseline")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctWaitCount(t, s, ctIP, 1, 3*time.Second, "slot held after accept")
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = conn.Close()
	ctWaitCount(t, s, ctIP, 0, 5*time.Second, "abrupt client close (RST) must release the slot")
}

func ctReqStatus(t *testing.T, addr, path, xff string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	req := "GET " + path + " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n"
	if xff != "" {
		req += "X-Forwarded-For: " + xff + "\r\n"
	}
	req += "\r\n"
	fmt.Fprint(c, req)
	line, _ := bufio.NewReader(c).ReadString('\n')
	return line
}

func TestCTE2E_RequestLimiter(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 2, ProxyMode: true, MaxRequestsPerIP: 3, MaxConnsPerIP: -1, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second})
	_ = s

	t.Run("concurrent over limit gets 429, in-flight complete", func(t *testing.T) {
		var wg sync.WaitGroup
		results := make([]string, 3)
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				results[idx] = ctReqStatus(t, addr, "/slow", "203.0.113.30")
			}(i)
		}
		time.Sleep(200 * time.Millisecond)
		over := ctReqStatus(t, addr, "/slow", "203.0.113.30")
		if !strings.Contains(over, "429") {
			t.Fatalf("4th concurrent request from same real IP must be 429, got %q", over)
		}
		wg.Wait()
		for i, r := range results {
			if !strings.Contains(r, "200") {
				t.Fatalf("in-flight request %d should complete 200, got %q", i, r)
			}
		}
	})

	t.Run("different real IP is unaffected", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); ctReqStatus(t, addr, "/slow", "203.0.113.30") }()
		}
		time.Sleep(200 * time.Millisecond)
		if other := ctReqStatus(t, addr, "/x", "203.0.113.31"); !strings.Contains(other, "200") {
			t.Fatalf("a different real IP must not be limited by another IP's in-flight requests, got %q", other)
		}
		wg.Wait()
	})
}

func TestCTE2E_RequestLimiterIdleSafe(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 1, ProxyMode: true, MaxRequestsPerIP: 1, MaxConnsPerIP: -1, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second})
	_ = s
	for i := 0; i < 25; i++ {
		if st := ctReqStatus(t, addr, "/x", "203.0.113.40"); !strings.Contains(st, "200") {
			t.Fatalf("sequential request %d from same real IP must be 200 (limiter releases per request, idle-safe), got %q", i, st)
		}
	}
}

func TestCTE2E_WriteTimeoutClosesAndReleases(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 1, MaxConnsPerIP: 1000, ReadTimeout: 30 * time.Second, WriteTimeout: 1 * time.Second, IdleTimeout: 30 * time.Second})
	ctWaitCount(t, s, ctIP, 0, 3*time.Second, "baseline")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "GET /large HTTP/1.1\r\nHost: t\r\n\r\n")
	ctWaitCount(t, s, ctIP, 1, 3*time.Second, "slot held after requesting a large body")
	ctWaitCount(t, s, ctIP, 0, 8*time.Second, "write timeout on an unread large response must close and release the slot")
	_ = conn.Close()
}

func TestCTE2E_H2ConnectionOneSlot(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 1, MaxConnsPerIP: 1000, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second})
	ctWaitCount(t, s, ctIP, 0, 3*time.Second, "baseline")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	_, _ = conn.Write([]byte{0, 0, 0, 0x4, 0, 0, 0, 0, 0})
	ctWaitCount(t, s, ctIP, 1, 3*time.Second, "an HTTP/2 connection must hold exactly one slot")
	_ = conn.Close()
	ctWaitCount(t, s, ctIP, 0, 5*time.Second, "an HTTP/2 connection must release its slot on close")
}

func TestCTE2E_ConcurrentConnectionsTracked(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 4, MaxConnsPerIP: 100000, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second})

	open := []struct {
		name string
		dial func() net.Conn
	}{
		{"plain", func() net.Conn {
			c := ctDialReq(t, addr, "/x")
			_, _ = bufio.NewReader(c).ReadString('\n')
			return c
		}},
		{"websocket", func() net.Conn { return ctWSDial(t, addr) }},
	}
	for _, tc := range open {
		t.Run(tc.name, func(t *testing.T) {
			ctWaitCount(t, s, ctIP, 0, 5*time.Second, "baseline before "+tc.name)
			const n = 25
			conns := make([]net.Conn, n)
			for i := 0; i < n; i++ {
				conns[i] = tc.dial()
			}
			ctWaitCount(t, s, ctIP, n, 5*time.Second, tc.name+": all concurrent connections must be counted")
			for _, c := range conns {
				_ = c.Close()
			}
			ctWaitCount(t, s, ctIP, 0, 8*time.Second, tc.name+": all slots released after closing every connection")
		})
	}
}

func ctWSDialStatus(t *testing.T, addr, xff string) (net.Conn, string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	req := "GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
	if xff != "" {
		req += "X-Forwarded-For: " + xff + "\r\n"
	}
	req += "\r\n"
	fmt.Fprint(conn, req)
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		_ = conn.Close()
		t.Fatalf("ws status read: %v", err)
	}
	return conn, line
}

func TestCTE2E_ProxyModeInFlightLimitEnforced(t *testing.T) {
	_, addr := ctStart(t, Config{Listeners: 2, ProxyMode: true, MaxConnsPerIP: 3, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second})

	t.Run("sequential requests never exhaust the limit", func(t *testing.T) {
		for i := 0; i < 30; i++ {
			if st := ctReqStatus(t, addr, "/x", "203.0.113.60"); !strings.Contains(st, "200") {
				t.Fatalf("sequential request %d must be 200; each request frees its slot on completion, got %q", i, st)
			}
		}
	})

	t.Run("many pooled connections from one IP all served", func(t *testing.T) {
		var conns []net.Conn
		for i := 0; i < 12; i++ {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("dial %d: %v", i, err)
			}
			fmt.Fprint(c, "GET /x HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: 203.0.113.63\r\n\r\n")
			line, err := bufio.NewReader(c).ReadString('\n')
			if err != nil || !strings.Contains(line, "200") {
				t.Fatalf("pooled conn %d must be 200; idle proxy connections must not consume the client's budget, got %q err=%v", i, line, err)
			}
			conns = append(conns, c)
		}
		for _, c := range conns {
			_ = c.Close()
		}
	})

	t.Run("concurrent long-lived websockets are capped per real IP", func(t *testing.T) {
		var held []net.Conn
		for i := 0; i < 3; i++ {
			c, status := ctWSDialStatus(t, addr, "203.0.113.61")
			if !strings.Contains(status, "101") {
				t.Fatalf("websocket %d within the cap must upgrade (101), got %q", i, status)
			}
			held = append(held, c)
		}
		over, status := ctWSDialStatus(t, addr, "203.0.113.61")
		if !strings.Contains(status, "429") {
			t.Fatalf("a 4th concurrent websocket from the same real IP must be refused with 429, got %q", status)
		}
		_ = over.Close()

		other, otherStatus := ctWSDialStatus(t, addr, "203.0.113.62")
		if !strings.Contains(otherStatus, "101") {
			t.Fatalf("a different real IP must keep its own budget, got %q", otherStatus)
		}
		_ = other.Close()

		_ = held[0].Close()
		reclaimed := false
		for attempt := 0; attempt < 25 && !reclaimed; attempt++ {
			time.Sleep(100 * time.Millisecond)
			c, st := ctWSDialStatus(t, addr, "203.0.113.61")
			if strings.Contains(st, "101") {
				reclaimed = true
				held = append(held, c)
			} else {
				_ = c.Close()
			}
		}
		if !reclaimed {
			t.Fatal("closing a websocket must return its slot to the client's budget")
		}
		for _, c := range held[1:] {
			_ = c.Close()
		}
	})
}
