//go:build linux && amd64 && e2e

package core

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func pxCount(s *Server, ip string) int64 {
	if s.perIPLimiter == nil {
		return -1
	}
	if c, ok := s.perIPLimiter.m.Load(ip); ok {
		return c.n.Load()
	}
	return 0
}

func pxWait(t *testing.T, s *Server, ip string, want int64, within time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if pxCount(s, ip) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: inflight[%s]=%d want %d (after %v)", msg, ip, pxCount(s, ip), want, within)
}

func pxWSOpen(t *testing.T, addr, xff string) (net.Conn, string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: t\r\nX-Forwarded-For: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", xff)
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("ws status read: %v", err)
	}
	if strings.Contains(line, "101") {
		for {
			h, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("ws header read: %v", err)
			}
			if h == "\r\n" || h == "\n" {
				break
			}
		}
	}
	return conn, line
}

func TestPXWS_SlotReleasedOnClose(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 1, ProxyMode: true, MaxConnsPerIP: 1000, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second})
	const ip = "203.0.113.7"
	pxWait(t, s, ip, 0, 3*time.Second, "baseline")
	conn, status := pxWSOpen(t, addr, ip)
	if !strings.Contains(status, "101") {
		t.Fatalf("ws upgrade expected 101, got %q", status)
	}
	pxWait(t, s, ip, 1, 3*time.Second, "live websocket must hold exactly one in-flight slot")
	_ = conn.Close()
	pxWait(t, s, ip, 0, 5*time.Second, "closing the websocket must release its in-flight slot")
}

func TestPXWS_NoLeakUnderChurn(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 2, ProxyMode: true, MaxConnsPerIP: 100000, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second})
	const ip = "198.51.100.22"
	pxWait(t, s, ip, 0, 3*time.Second, "baseline")
	for i := 0; i < 40; i++ {
		c, status := pxWSOpen(t, addr, ip)
		if !strings.Contains(status, "101") {
			t.Fatalf("churn %d expected 101, got %q", i, status)
		}
		_ = c.Close()
	}
	pxWait(t, s, ip, 0, 8*time.Second, "40 websocket open/close from one real IP must leave zero leaked slots")
}

func TestPXWS_InFlightLimitEnforced(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 1, ProxyMode: true, MaxConnsPerIP: 3, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second})
	const ip = "203.0.113.55"
	pxWait(t, s, ip, 0, 3*time.Second, "baseline")
	held := make([]net.Conn, 0, 3)
	for i := 0; i < 3; i++ {
		c, status := pxWSOpen(t, addr, ip)
		if !strings.Contains(status, "101") {
			t.Fatalf("held ws %d expected 101, got %q", i, status)
		}
		held = append(held, c)
	}
	pxWait(t, s, ip, 3, 3*time.Second, "three live websockets must occupy three in-flight slots")
	_, status := pxWSOpen(t, addr, ip)
	if !strings.Contains(status, "429") {
		t.Fatalf("4th websocket from same real IP must be rejected with 429, got %q", status)
	}
	for _, c := range held {
		_ = c.Close()
	}
	pxWait(t, s, ip, 0, 5*time.Second, "closing all websockets must free every slot")
}

func TestPXWS_DistinctRealIPsIndependent(t *testing.T) {
	s, addr := ctStart(t, Config{Listeners: 1, ProxyMode: true, MaxConnsPerIP: 1, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second})
	const ipA = "203.0.113.101"
	const ipB = "203.0.113.102"
	ca, sa := pxWSOpen(t, addr, ipA)
	if !strings.Contains(sa, "101") {
		t.Fatalf("ipA ws expected 101, got %q", sa)
	}
	pxWait(t, s, ipA, 1, 3*time.Second, "ipA holds its only slot")
	cb, sb := pxWSOpen(t, addr, ipB)
	if !strings.Contains(sb, "101") {
		t.Fatalf("ipB ws expected 101 on its own budget, got %q", sb)
	}
	pxWait(t, s, ipB, 1, 3*time.Second, "ipB has an independent budget")
	_, saDup := pxWSOpen(t, addr, ipA)
	if !strings.Contains(saDup, "429") {
		t.Fatalf("second ipA ws must be rejected at limit 1, got %q", saDup)
	}
	_ = ca.Close()
	_ = cb.Close()
	pxWait(t, s, ipA, 0, 5*time.Second, "ipA released")
	pxWait(t, s, ipB, 0, 5*time.Second, "ipB released")
}
