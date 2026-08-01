//go:build linux

package core

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDoStreamDeliversBodyIncrementally(t *testing.T) {
	release := make(chan struct{})
	backend := rawOrigin(t, func(c net.Conn) {
		fmt.Fprint(c, "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n")
		_, _ = c.Write([]byte("first"))
		<-release
		_, _ = c.Write([]byte("secnd"))
	})

	client, err := NewUpstreamClient(UpstreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var mu sync.Mutex
	var chunks [][]byte
	firstSeen := make(chan struct{})
	var once sync.Once

	done := make(chan error, 1)
	go func() {
		status, err := client.DoStream(&UpstreamRequest{
			Scheme: "http", Authority: backend, Method: "GET", Path: "/s",
		}, &UpstreamStream{
			OnBody: func(chunk []byte) error {
				mu.Lock()
				chunks = append(chunks, append([]byte(nil), chunk...))
				mu.Unlock()
				once.Do(func() { close(firstSeen) })
				return nil
			},
		})
		if status != 200 {
			done <- fmt.Errorf("status %d", status)
			return
		}
		done <- err
	}()

	select {
	case <-firstSeen:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("no chunk delivered before the origin finished writing")
	}
	close(release)

	if err := <-done; err != nil {
		t.Fatalf("DoStream: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(chunks) < 2 {
		t.Fatalf("expected the body to arrive in multiple chunks, got %d", len(chunks))
	}
	if got := bytes.Join(chunks, nil); string(got) != "firstsecnd" {
		t.Fatalf("assembled body = %q", got)
	}
}

func TestDoStreamReportsHeaders(t *testing.T) {
	backend := rawOrigin(t, func(c net.Conn) {
		fmt.Fprint(c, "HTTP/1.1 404 Not Found\r\ncontent-length: 3\r\nx-marker: yes\r\n\r\nabc")
	})
	client, err := NewUpstreamClient(UpstreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var gotStatus int
	var marker string
	status, err := client.DoStream(&UpstreamRequest{
		Scheme: "http", Authority: backend, Method: "GET", Path: "/h",
	}, &UpstreamStream{
		OnHeaders: func(s int, headers [][2]string) error {
			gotStatus = s
			for _, h := range headers {
				if h[0] == "x-marker" {
					marker = h[1]
				}
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if status != 404 || gotStatus != 404 {
		t.Fatalf("status = %d / %d, want 404", status, gotStatus)
	}
	if marker != "yes" {
		t.Fatalf("x-marker = %q", marker)
	}
}

func TestDoStreamHandlesBodyLargerThanBufferCap(t *testing.T) {
	const size = 80 << 20
	block := bytes.Repeat([]byte("q"), 1<<20)
	backend := rawOrigin(t, func(c net.Conn) {
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\ncontent-length: %d\r\n\r\n", size)
		for sent := 0; sent < size; sent += len(block) {
			if _, err := c.Write(block); err != nil {
				return
			}
		}
	})
	client, err := NewUpstreamClient(UpstreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	total := 0
	status, err := client.DoStream(&UpstreamRequest{
		Scheme: "http", Authority: backend, Method: "GET", Path: "/big",
	}, &UpstreamStream{
		OnBody: func(chunk []byte) error {
			total += len(chunk)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("DoStream after %d bytes: %v", total, err)
	}
	if status != 200 {
		t.Fatalf("status = %d", status)
	}
	if total != size {
		t.Fatalf("received %d bytes, want %d", total, size)
	}
}

func TestBufferedDoStillReturnsWholeBody(t *testing.T) {
	backend := rawOrigin(t, func(c net.Conn) {
		fmt.Fprint(c, "HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\nhello world")
	})
	client, err := NewUpstreamClient(UpstreamConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	resp, err := client.Do(&UpstreamRequest{
		Scheme: "http", Authority: backend, Method: "GET", Path: "/b",
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "hello world" {
		t.Fatalf("body = %q", resp.Body)
	}
}
