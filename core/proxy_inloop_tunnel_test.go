//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

// inloopEchoUpgradeOrigin accepts an upgrade request and then echoes every byte back,
// so a test can verify the tunnel is transparent in both directions.
func inloopEchoUpgradeOrigin(t *testing.T) *inloopOrigin {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	o := &inloopOrigin{ln: ln}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			o.accepted.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				var sawUpgrade bool
				for {
					line, rerr := br.ReadString('\n')
					if rerr != nil {
						return
					}
					if strings.HasPrefix(strings.ToLower(line), "upgrade:") {
						sawUpgrade = true
					}
					if line == "\r\n" {
						break
					}
				}
				if !sawUpgrade {
					io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
					return
				}
				io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				_, _ = io.Copy(c, br)
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return o
}

func doUpgrade(t *testing.T, addr, host string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	req := "GET /ws HTTP/1.1\r\nHost: " + host +
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 101") {
		t.Fatalf("upgrade was not accepted: %q", status)
	}
	for {
		line, lerr := br.ReadString('\n')
		if lerr != nil {
			t.Fatalf("read upgrade headers: %v", lerr)
		}
		if line == "\r\n" {
			break
		}
	}
	if br.Buffered() > 0 {
		t.Fatalf("unexpected %d bytes buffered after the upgrade headers", br.Buffered())
	}
	return conn
}

// The upgrade must be relayed to the backend, answered with 101, and the
// connection must then carry arbitrary bytes in both directions.
func TestInLoopProxyUpgradeTunnelEchoes(t *testing.T) {
	o := inloopEchoUpgradeOrigin(t)
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "ws.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	conn := doUpgrade(t, addr, "ws.test")
	defer conn.Close()

	for i := 0; i < 200; i++ {
		msg := fmt.Sprintf("frame-%04d-payload", i)
		if _, err := io.WriteString(conn, msg); err != nil {
			t.Fatalf("write frame %d: %v", i, err)
		}
		got := make([]byte, len(msg))
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		if string(got) != msg {
			t.Fatalf("frame %d round-tripped as %q, want %q", i, got, msg)
		}
	}
}

// Binary payloads must survive untouched, including bytes that would look like
// HTTP framing to a parser.
func TestInLoopProxyUpgradeTunnelIsByteTransparent(t *testing.T) {
	o := inloopEchoUpgradeOrigin(t)
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "ws.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	conn := doUpgrade(t, addr, "ws.test")
	defer conn.Close()

	payload := make([]byte, 256<<10)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	copy(payload, []byte("GET / HTTP/1.1\r\nHost: evil\r\n\r\n"))

	done := make(chan []byte, 1)
	go func() {
		got := make([]byte, len(payload))
		conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		if _, err := io.ReadFull(conn, got); err != nil {
			done <- nil
			return
		}
		done <- got
	}()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got := <-done
	if got == nil {
		t.Fatal("tunnel did not return the payload")
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("binary payload was altered in transit")
	}
}

// The in-loop tunnel exists to avoid the goroutines and hijack the old path
// needed, so open sockets must not add goroutines.
func TestInLoopProxyUpgradeTunnelUsesNoGoroutines(t *testing.T) {
	o := inloopEchoUpgradeOrigin(t)
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "ws.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	warm := doUpgrade(t, addr, "ws.test")
	io.WriteString(warm, "x")
	buf := make([]byte, 1)
	io.ReadFull(warm, buf)
	runtime.GC()
	time.Sleep(150 * time.Millisecond)
	before := runtime.NumGoroutine()

	conns := make([]net.Conn, 0, 40)
	for i := 0; i < 40; i++ {
		c := doUpgrade(t, addr, "ws.test")
		io.WriteString(c, "y")
		one := make([]byte, 1)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, one); err != nil {
			t.Fatalf("tunnel %d did not echo: %v", i, err)
		}
		conns = append(conns, c)
	}
	runtime.GC()
	time.Sleep(150 * time.Millisecond)
	after := runtime.NumGoroutine()

	// The origin is in-process and does spawn a goroutine per connection, so
	// only the excess beyond that is attributable to the proxy.
	if after-before > 50 {
		t.Fatalf("40 tunnels added %d goroutines (%d -> %d); the proxy side should add none",
			after-before, before, after)
	}
	for _, c := range conns {
		_ = c.Close()
	}
	_ = warm.Close()
}

// Closing either end must tear down the other rather than leaking it.
func TestInLoopProxyUpgradeTunnelClientCloseReleasesBackend(t *testing.T) {
	o := inloopEchoUpgradeOrigin(t)
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "ws.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)

	for i := 0; i < 25; i++ {
		conn := doUpgrade(t, addr, "ws.test")
		io.WriteString(conn, "ping")
		got := make([]byte, 4)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("tunnel %d echo failed: %v", i, err)
		}
		_ = conn.Close()
	}
	// A leak would show up as the proxy failing to serve further upgrades.
	time.Sleep(150 * time.Millisecond)
	final := doUpgrade(t, addr, "ws.test")
	defer final.Close()
	io.WriteString(final, "still-here")
	got := make([]byte, len("still-here"))
	final.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(final, got); err != nil {
		t.Fatalf("proxy stopped serving upgrades after repeated client closes: %v", err)
	}
}
