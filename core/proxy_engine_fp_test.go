//go:build linux

package core

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func engineProxy(t *testing.T, backendAddr string) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv := New(Config{Addr: addr, PlainHTTP: true, HTTPAddr: "-", LogRequests: false})
	srv.AddProxyDomain(DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: backendAddr}},
	})
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("proxy never came up")
	return ""
}

func engineGet(t *testing.T, proxyAddr, path string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest("GET", "http://"+proxyAddr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "origin.test"
	tr := &http.Transport{DisableCompression: true}
	client := &http.Client{Transport: tr, Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, body
}

func TestProxyEngineFPSmallResponse(t *testing.T) {
	backend := rawOrigin(t, func(c net.Conn) {
		fmt.Fprint(c, "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 11\r\n\r\nhello world")
	})
	proxy := engineProxy(t, backend)

	resp, body := engineGet(t, proxy, "/small")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(body) != "hello world" {
		t.Fatalf("body = %q", body)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("content-type = %q", resp.Header.Get("Content-Type"))
	}
}

func TestProxyEngineFPStreamsLargeResponse(t *testing.T) {
	const size = 4 << 20
	block := bytes.Repeat([]byte("w"), 64<<10)
	backend := rawOrigin(t, func(c net.Conn) {
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\ncontent-length: %d\r\n\r\n", size)
		for sent := 0; sent < size; sent += len(block) {
			if _, err := c.Write(block); err != nil {
				return
			}
		}
	})
	proxy := engineProxy(t, backend)

	resp, body := engineGet(t, proxy, "/large")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(body) != size {
		t.Fatalf("body = %d bytes, want %d", len(body), size)
	}
	if !bytes.Equal(body[:64], bytes.Repeat([]byte("w"), 64)) {
		t.Fatal("body content corrupted")
	}
}

func TestProxyEngineFPChunkedResponse(t *testing.T) {
	backend := rawOrigin(t, func(c net.Conn) {
		fmt.Fprint(c, "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
		fmt.Fprint(c, "5\r\nalpha\r\n")
		fmt.Fprint(c, "4\r\nbeta\r\n")
		fmt.Fprint(c, "0\r\n\r\n")
	})
	proxy := engineProxy(t, backend)

	resp, body := engineGet(t, proxy, "/chunked")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(body) != "alphabeta" {
		t.Fatalf("body = %q", body)
	}
}

func TestProxyEngineFPPropagatesStatusAndHeaders(t *testing.T) {
	backend := rawOrigin(t, func(c net.Conn) {
		fmt.Fprint(c, "HTTP/1.1 503 Service Unavailable\r\n"+
			"content-length: 4\r\nx-origin-marker: abc\r\n\r\ndown")
	})
	proxy := engineProxy(t, backend)

	resp, body := engineGet(t, proxy, "/status")
	if resp.StatusCode != 503 {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if string(body) != "down" {
		t.Fatalf("body = %q", body)
	}
	if resp.Header.Get("X-Origin-Marker") != "abc" {
		t.Fatalf("origin header not relayed: %q", resp.Header.Get("X-Origin-Marker"))
	}
}

func TestProxyEngineFPForwardsClientIP(t *testing.T) {
	seen := make(chan string, 1)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				head := string(buf[:n])
				xff := ""
				for _, line := range strings.Split(head, "\r\n") {
					if i := strings.IndexByte(line, ':'); i > 0 &&
						strings.EqualFold(strings.TrimSpace(line[:i]), "x-forwarded-for") {
						xff = strings.TrimSpace(line[i+1:])
					}
				}
				select {
				case seen <- xff:
				default:
				}
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
			}(c)
		}
	}()
	proxy := engineProxy(t, ln.Addr().String())

	if _, body := engineGet(t, proxy, "/ip"); string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
	select {
	case xff := <-seen:
		if xff == "" {
			t.Fatal("backend did not receive X-Forwarded-For")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend never saw the request")
	}
}

func TestProxyEngineFPPostBody(t *testing.T) {
	got := make(chan []byte, 1)
	backend := capturingOrigin(t, got)
	proxy := engineProxy(t, backend)

	req, err := http.NewRequest("POST", "http://"+proxy+"/post",
		strings.NewReader("submitted-data"))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "origin.test"
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	select {
	case body := <-got:
		if string(body) != "submitted-data" {
			t.Fatalf("backend received %q", body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("backend never received the POST")
	}
}

func TestProxyEngineFPKeepAliveReusesBackendConnection(t *testing.T) {
	var conns int
	connCh := make(chan struct{}, 64)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			connCh <- struct{}{}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					for range bytes.Count(buf[:n], []byte("\r\n\r\n")) {
						if _, werr := fmt.Fprint(c,
							"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	proxy := engineProxy(t, ln.Addr().String())

	client := &http.Client{Timeout: 20 * time.Second}
	defer client.CloseIdleConnections()
	for i := 0; i < 25; i++ {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/k%d", proxy, i), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "origin.test"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != "ok" {
			t.Fatalf("request %d: body = %q", i, body)
		}
	}
	time.Sleep(100 * time.Millisecond)
	for {
		select {
		case <-connCh:
			conns++
			continue
		default:
		}
		break
	}
	t.Logf("25 requests opened %d backend connections", conns)
	if conns >= 25 {
		t.Errorf("no backend connection reuse: %d connections for 25 requests", conns)
	}
}
