//go:build linux && amd64

package core

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func startSessionServer(t *testing.T, useTLS bool) string {
	t.Helper()
	addr := reserveLocalAddr(t)
	cfg := Config{Addr: addr, HTTPAddr: "-", LogRequests: false, MaxConnsPerIP: -1, Listeners: 1}
	if useTLS {
		cfg.Certs = []CertConfig{{Domain: "sess.test", Source: CertSelfSigned}}
	} else {
		cfg.PlainHTTP = true
	}
	s := New(cfg)
	s.Router.Use(Sessions(SessionConfig{}))
	s.Router.GET("/login", func(req *Request, resp *Response) {
		GetSession(req).Set("user", "u1")
		resp.Status(200).String("ok")
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
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("session server never came up")
	return ""
}

func sessionCookieHeader(t *testing.T, addr string, useTLS bool) string {
	t.Helper()
	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "sess.test"})
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET /login HTTP/1.1\r\nHost: sess.test\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.Header.Get("Set-Cookie")
}

func TestSessionCookieIsSecureOverTLSByDefault(t *testing.T) {
	tlsCookie := sessionCookieHeader(t, startSessionServer(t, true), true)
	if !strings.Contains(strings.ToLower(tlsCookie), "secure") {
		t.Fatalf("session cookie issued over TLS lacks the Secure attribute: %q", tlsCookie)
	}
	plainCookie := sessionCookieHeader(t, startSessionServer(t, false), false)
	if strings.Contains(strings.ToLower(plainCookie), "secure") {
		t.Fatalf("session cookie issued over plain HTTP carries Secure and would be dropped by browsers: %q", plainCookie)
	}
	if plainCookie == "" {
		t.Fatal("no session cookie issued over plain HTTP")
	}
}
