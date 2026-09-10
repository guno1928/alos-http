//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func startInlineServer(t *testing.T, useTLS bool) string {
	t.Helper()
	addr := reserveLocalAddr(t)
	cfg := Config{
		Addr:           addr,
		HTTPAddr:       "-",
		LogRequests:    false,
		MaxConnsPerIP:  -1,
		Listeners:      1,
		InlineHandlers: true,
	}
	if useTLS {
		cfg.Certs = []CertConfig{{Domain: "inline.test", Source: CertSelfSigned}}
	} else {
		cfg.PlainHTTP = true
	}
	s := New(cfg)
	s.Router.GET("/ping", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	s.Router.GET("/echo/:id", func(req *Request, resp *Response) { resp.Status(200).String("id=" + req.ParamValue("id")) })
	s.Router.POST("/body", func(req *Request, resp *Response) { resp.Status(200).Bytes(req.Body) })
	s.Router.GET("/boom", func(req *Request, resp *Response) { panic("boom") })
	s.Router.GET("/ws", func(req *Request, resp *Response) {
		ServeWebSocket(req, resp, func(ws *WSConn) {
			defer ws.Close()
			_, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			_ = ws.WriteText("echo:" + string(data))
		})
	})
	go func() {
		if useTLS {
			_ = s.ListenAndServeTLS()
		} else {
			_ = s.ListenAndServe()
		}
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := inlineDial(addr, useTLS)
		if err == nil {
			_ = c.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("inline server never came up")
	return ""
}

func inlineDial(addr string, useTLS bool) (net.Conn, error) {
	if useTLS {
		return tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr,
			&tls.Config{InsecureSkipVerify: true, ServerName: "inline.test"})
	}
	return net.DialTimeout("tcp", addr, 2*time.Second)
}

func TestInlineHandlersServeRequests(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "plain"
		if useTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			addr := startInlineServer(t, useTLS)
			conn, err := inlineDial(addr, useTLS)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			br := bufio.NewReader(conn)
			fmt.Fprint(conn, "GET /echo/7 HTTP/1.1\r\nHost: inline.test\r\n\r\nPOST /body HTTP/1.1\r\nHost: inline.test\r\nContent-Length: 5\r\n\r\nhelloGET /boom HTTP/1.1\r\nHost: inline.test\r\n\r\nGET /ping HTTP/1.1\r\nHost: inline.test\r\n\r\n")
			want := []struct {
				status int
				body   string
			}{{200, "id=7"}, {200, "hello"}, {500, ""}, {200, "ok"}}
			for i, w := range want {
				resp, err := http.ReadResponse(br, nil)
				if err != nil {
					t.Fatalf("response %d: %v", i, err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != w.status || (w.body != "" && string(body) != w.body) {
					t.Fatalf("response %d: %d %q, want %d %q", i, resp.StatusCode, body, w.status, w.body)
				}
			}
		})
	}
}

func TestInlineHandlersWebSocketUpgrade(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "plain"
		if useTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			addr := startInlineServer(t, useTLS)
			conn, err := inlineDial(addr, useTLS)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			fmt.Fprint(conn, "GET /ws HTTP/1.1\r\nHost: inline.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("upgrade: %v", err)
			}
			if resp.StatusCode != 101 {
				t.Fatalf("upgrade status = %d", resp.StatusCode)
			}
			frame := []byte{0x81, 0x85, 1, 2, 3, 4}
			for i, b := range []byte("hello") {
				frame = append(frame, b^frame[2+i%4])
			}
			if _, err := conn.Write(frame); err != nil {
				t.Fatal(err)
			}
			hdr := make([]byte, 2)
			if _, err := io.ReadFull(br, hdr); err != nil {
				t.Fatalf("echo header: %v", err)
			}
			payload := make([]byte, int(hdr[1]&0x7f))
			if _, err := io.ReadFull(br, payload); err != nil {
				t.Fatalf("echo payload: %v", err)
			}
			if string(payload) != "echo:hello" {
				t.Fatalf("echo = %q", payload)
			}
			probe, err := inlineDial(addr, useTLS)
			if err != nil {
				t.Fatalf("server unusable after inline upgrade: %v", err)
			}
			defer probe.Close()
			fmt.Fprint(probe, "GET /ping HTTP/1.1\r\nHost: inline.test\r\nConnection: close\r\n\r\n")
			line, _ := bufio.NewReader(probe).ReadString('\n')
			if !strings.Contains(line, "200") {
				t.Fatalf("probe after upgrade: %q", line)
			}
		})
	}
}
