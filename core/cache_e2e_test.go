//go:build linux && amd64 && e2e

package core

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func e2eWaitReady(url string) bool {
	for i := 0; i < 200; i++ {
		resp, err := http.Get(url)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

func TestE2E_CacheServesHitsAndGzip(t *testing.T) {
	var calls int32
	srv := New(Config{Addr: ":18091", PlainHTTP: true, MinPrealloc: 16, Listeners: 2})
	srv.Router.Use(Cache(CacheConfig{TTL: time.Minute, Gzip: true, GzipMinBytes: 100}))
	srv.Router.GET("/page", func(req *Request, resp *Response) {
		atomic.AddInt32(&calls, 1)
		resp.Status(200).String(strings.Repeat("hello world ", 300))
	})
	go func() { _ = srv.ListenAndServeEpollH2(":18091") }()
	if !e2eWaitReady("http://127.0.0.1:18091/page") {
		t.Fatal("server did not come up")
	}

	tr := &http.Transport{DisableCompression: true}
	client := &http.Client{Transport: tr}
	do := func() *http.Response {
		req, _ := http.NewRequest("GET", "http://127.0.0.1:18091/page", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		return resp
	}

	r1 := do()
	body1, _ := io.ReadAll(r1.Body)
	r1.Body.Close()
	r2 := do()
	body2, _ := io.ReadAll(r2.Body)
	r2.Body.Close()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("handler ran %d times over 2 requests; cache miss on hit path", got)
	}
	if r2.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("hit not served gzip: Content-Encoding=%q", r2.Header.Get("Content-Encoding"))
	}
	if len(body2) < 2 || body2[0] != 0x1f || body2[1] != 0x8b {
		t.Fatalf("hit body not gzip framed: %x", body2[:min(2, len(body2))])
	}
	gr, err := gzip.NewReader(strings_NewReader(body2))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	dec, _ := io.ReadAll(gr)
	if string(dec) != strings.Repeat("hello world ", 300) {
		t.Fatal("decompressed cached gzip body mismatch")
	}
	_ = body1
	fmt.Printf("E2E cache: handler ran %d time(s) for 2 hits; gzip served + verified\n", calls)
}

func TestE2E_ActiveConnsTracksLiveConnection(t *testing.T) {
	srv := New(Config{Addr: ":18092", PlainHTTP: true, MinPrealloc: 16, Listeners: 2})
	srv.Router.GET("/x", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	go func() { _ = srv.ListenAndServeEpollH2(":18092") }()
	if !e2eWaitReady("http://127.0.0.1:18092/x") {
		t.Fatal("server did not come up")
	}

	start := Stats.ActiveConns.Load()
	conn, err := net.Dial("tcp", "127.0.0.1:18092")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	fmt.Fprint(conn, "GET /x HTTP/1.1\r\nHost: x\r\n\r\n")
	br := bufio.NewReader(conn)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "200") {
		t.Fatalf("unexpected status line: %q", line)
	}

	var peak int64
	for i := 0; i < 40; i++ {
		if v := Stats.ActiveConns.Load(); v > peak {
			peak = v
		}
		time.Sleep(10 * time.Millisecond)
	}
	if peak <= start {
		t.Fatalf("Stats.ActiveConns did not rise with a live connection: start=%d peak=%d", start, peak)
	}
	fmt.Printf("E2E activeConns: start=%d peak-with-live-conn=%d\n", start, peak)

	conn.Close()
	dropped := false
	for i := 0; i < 200; i++ {
		if Stats.ActiveConns.Load() <= start {
			dropped = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !dropped {
		t.Fatalf("Stats.ActiveConns did not return to baseline %d after close (now %d)", start, Stats.ActiveConns.Load())
	}
	fmt.Printf("E2E activeConns: returned to <=%d after close\n", start)
}

func strings_NewReader(b []byte) io.Reader { return strings.NewReader(string(b)) }

func e2eStatusLine(conn net.Conn, xff string) (string, error) {
	req := "GET /x HTTP/1.1\r\nHost: x\r\n"
	if xff != "" {
		req += "X-Forwarded-For: " + xff + "\r\n"
	}
	req += "\r\n"
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprint(conn, req); err != nil {
		return "", err
	}
	return bufio.NewReader(conn).ReadString('\n')
}

func TestE2E_PerIPConnLimit_ProxyMode(t *testing.T) {
	srv := New(Config{Addr: ":18093", PlainHTTP: true, MinPrealloc: 16, Listeners: 2, ProxyMode: true, MaxConnsPerIP: 5})
	srv.Router.GET("/x", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	go func() { _ = srv.ListenAndServeEpollH2(":18093") }()
	if !e2eWaitReady("http://127.0.0.1:18093/x") {
		t.Fatal("server did not come up")
	}

	var held []net.Conn
	for i := 0; i < 5; i++ {
		conn, err := net.Dial("tcp", "127.0.0.1:18093")
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		line, err := e2eStatusLine(conn, "203.0.113.5")
		if err != nil || !strings.Contains(line, "200") {
			t.Fatalf("held conn %d expected 200, got %q err=%v", i, line, err)
		}
		held = append(held, conn)
	}

	over, err := net.Dial("tcp", "127.0.0.1:18093")
	if err != nil {
		t.Fatal(err)
	}
	line, _ := e2eStatusLine(over, "203.0.113.5")
	if !strings.Contains(line, "429") {
		t.Fatalf("6th connection from same real IP expected 429, got %q", line)
	}
	over.Close()

	other, err := net.Dial("tcp", "127.0.0.1:18093")
	if err != nil {
		t.Fatal(err)
	}
	lineO, _ := e2eStatusLine(other, "203.0.113.99")
	if !strings.Contains(lineO, "200") {
		t.Fatalf("different real IP expected 200, got %q", lineO)
	}
	other.Close()

	held[0].Close()
	got200 := false
	for attempt := 0; attempt < 5 && !got200; attempt++ {
		time.Sleep(250 * time.Millisecond)
		reopen, err := net.Dial("tcp", "127.0.0.1:18093")
		if err != nil {
			continue
		}
		lineR, _ := e2eStatusLine(reopen, "203.0.113.5")
		reopen.Close()
		if strings.Contains(lineR, "200") {
			got200 = true
		}
	}
	if !got200 {
		t.Fatal("after releasing a slot, a new connection from the same real IP should be allowed (200)")
	}
	for _, c := range held[1:] {
		c.Close()
	}
	fmt.Printf("E2E per-IP conn limit (ProxyMode): 5 held, 6th=429, other real IP=200, slot freed on close=200\n")
}

func TestE2E_PerIPConnLimit_NonProxyAtAccept(t *testing.T) {
	srv := New(Config{Addr: ":18094", PlainHTTP: true, MinPrealloc: 16, Listeners: 1, MaxConnsPerIP: 5})
	srv.Router.GET("/x", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	go func() { _ = srv.ListenAndServeEpollH2(":18094") }()
	if !e2eWaitReady("http://127.0.0.1:18094/x") {
		t.Fatal("server did not come up")
	}
	time.Sleep(300 * time.Millisecond)

	var held []net.Conn
	ok := 0
	for i := 0; i < 14; i++ {
		conn, err := net.Dial("tcp", "127.0.0.1:18094")
		if err != nil {
			continue
		}
		held = append(held, conn)
		line, err := e2eStatusLine(conn, "")
		if err == nil && strings.Contains(line, "200") {
			ok++
		}
	}
	if ok > 5 {
		t.Fatalf("non-proxy accept limit exceeded: %d connections served, want <= 5", ok)
	}
	if ok == 0 {
		t.Fatal("expected some connections under the limit to succeed")
	}
	for _, c := range held {
		c.Close()
	}
	fmt.Printf("E2E per-IP conn limit (non-proxy, socket IP at accept): %d/14 served, cap 5 held\n", ok)
}
