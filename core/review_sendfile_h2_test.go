//go:build linux && amd64

package core

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sendFileTestBody = "<html>sendfile over h2</html>"

func TestSendFileWorksOnEpollHTTP2(t *testing.T) {
	f, err := os.CreateTemp(".", "sendfile-h2-*.html")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	name := filepath.Base(f.Name())
	t.Cleanup(func() { _ = os.Remove(name) })
	if _, err := f.WriteString(sendFileTestBody); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = f.Close()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	srv := New(Config{
		Addr: addr, HTTPAddr: "-", LogRequests: false, MaxConnsPerIP: -1, Listeners: 1,
		Certs: []CertConfig{{Domain: "sendfile.test", Source: CertSelfSigned}},
	})
	srv.Router.GET("/file", func(req *Request, resp *Response) {
		if err := resp.SendFile(name, WithAttachment("page.html")); err != nil {
			resp.Status(500).String("sendfile: " + err.Error())
		}
	})
	go func() { _ = srv.ListenAndServeTLS() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	waitForProxy(t, addr)

	for _, proto := range []string{"http/1.1", "h2"} {
		tr := &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: "sendfile.test", NextProtos: []string{proto}},
			ForceAttemptHTTP2: proto == "h2",
		}
		cl := &http.Client{Transport: tr, Timeout: 2 * time.Second}
		resp, err := cl.Get("https://" + addr + "/file")
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		tr.CloseIdleConnections()
		if resp.StatusCode != 200 || string(body) != sendFileTestBody {
			t.Fatalf("%s (%s): status=%d body=%q", proto, resp.Proto, resp.StatusCode, body)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Fatalf("%s: content-type %q", proto, ct)
		}
		if cd := resp.Header.Get("Content-Disposition"); cd != `attachment; filename="page.html"` {
			t.Fatalf("%s: content-disposition %q", proto, cd)
		}
		if resp.ContentLength != int64(len(sendFileTestBody)) {
			t.Fatalf("%s: content-length %d", proto, resp.ContentLength)
		}
	}
}
