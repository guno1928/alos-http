//go:build linux

package core

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func testMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(200)
		io.WriteString(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("x-method", r.Method)
		w.WriteHeader(201)
		w.Write(b)
	})
	mux.HandleFunc("/chunked", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(200)
		for i := 0; i < 5; i++ {
			io.WriteString(w, fmt.Sprintf("part%d-", i))
			if ok {
				fl.Flush()
			}
		}
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n == 0 {
			n = 100000
		}
		w.WriteHeader(200)
		buf := make([]byte, 1000)
		for i := range buf {
			buf[i] = 'x'
		}
		for written := 0; written < n; written += len(buf) {
			w.Write(buf)
		}
	})
	return mux
}

func mkReq(rawurl, method string, h2 bool, body []byte) *fpRequest {
	u, _ := url.Parse(rawurl)
	authority := u.Host
	path := u.RequestURI()
	req := &fpRequest{
		Scheme:     u.Scheme,
		Authority:  authority,
		Method:     method,
		Path:       path,
		Body:       body,
		SkipVerify: true,
		H2:         h2,
	}
	return req
}

func newTestClient(t *testing.T) *fpClient {
	c, err := fpNew(fpConfig{Loops: 4, RequestTimeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("fpNew: %v", err)
	}
	return c
}

func doOK(t *testing.T, c *fpClient, rawurl, method string, h2 bool, body []byte) *fpResponse {
	t.Helper()
	resp, err := c.Do(mkReq(rawurl, method, h2, body))
	if err != nil {
		t.Fatalf("Do(%s h2=%v): %v", rawurl, h2, err)
	}
	return resp
}

func header(resp *fpResponse, name string) string {
	for _, h := range resp.Headers {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

func runSuite(t *testing.T, base string, h2 bool) {
	c := newTestClient(t)
	defer c.Close()

	resp := doOK(t, c, base+"/json", "GET", h2, nil)
	if resp.Status != 200 || string(resp.Body) != `{"status":"ok"}` {
		t.Fatalf("json: status=%d body=%q", resp.Status, resp.Body)
	}
	if ct := header(resp, "content-type"); ct != "application/json" {
		t.Fatalf("json content-type=%q", ct)
	}

	payload := []byte("hello-body-12345")
	resp = doOK(t, c, base+"/echo", "POST", h2, payload)
	if resp.Status != 201 || string(resp.Body) != string(payload) {
		t.Fatalf("echo: status=%d body=%q", resp.Status, resp.Body)
	}
	if m := header(resp, "x-method"); m != "POST" {
		t.Fatalf("echo x-method=%q", m)
	}

	resp = doOK(t, c, base+"/chunked", "GET", h2, nil)
	if resp.Status != 200 || string(resp.Body) != "part0-part1-part2-part3-part4-" {
		t.Fatalf("chunked: status=%d body=%q", resp.Status, resp.Body)
	}

	resp = doOK(t, c, base+"/big?n=250000", "GET", h2, nil)
	if resp.Status != 200 || len(resp.Body) != 250000 {
		t.Fatalf("big: status=%d len=%d", resp.Status, len(resp.Body))
	}

	for i := 0; i < 20; i++ {
		resp = doOK(t, c, base+"/json", "GET", h2, nil)
		if string(resp.Body) != `{"status":"ok"}` {
			t.Fatalf("reuse %d: body=%q", i, resp.Body)
		}
	}
}

func runConcurrent(t *testing.T, base string, h2 bool, n int) {
	c := newTestClient(t)
	defer c.Close()
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := []byte(fmt.Sprintf("req-%d-payload", i))
			resp, err := c.Do(mkReq(base+"/echo", "POST", h2, body))
			if err != nil {
				errs <- fmt.Errorf("req %d: %v", i, err)
				return
			}
			if resp.Status != 201 || string(resp.Body) != string(body) {
				errs <- fmt.Errorf("req %d: status=%d body=%q", i, resp.Status, resp.Body)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestHTTP1Plain(t *testing.T) {
	srv := httptest.NewServer(testMux())
	defer srv.Close()
	runSuite(t, srv.URL, false)
}

func TestHTTPS1(t *testing.T) {
	srv := httptest.NewUnstartedServer(testMux())
	srv.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	srv.StartTLS()
	defer srv.Close()
	runSuite(t, srv.URL, false)
}

func TestH2TLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(testMux())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	runSuite(t, srv.URL, true)
}

func TestHTTP1Concurrent(t *testing.T) {
	srv := httptest.NewServer(testMux())
	defer srv.Close()
	runConcurrent(t, srv.URL, false, 200)
}

func TestH2Concurrent(t *testing.T) {
	srv := httptest.NewUnstartedServer(testMux())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	runConcurrent(t, srv.URL, true, 200)
}

func TestTLS12(t *testing.T) {
	srv := httptest.NewUnstartedServer(testMux())
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	srv.StartTLS()
	defer srv.Close()
	runSuite(t, srv.URL, false)
}

func TestH2OverTLS12(t *testing.T) {
	srv := httptest.NewUnstartedServer(testMux())
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	srv.StartTLS()
	defer srv.Close()
	runSuite(t, srv.URL, true)
}

func TestH2LargeBody(t *testing.T) {
	srv := httptest.NewUnstartedServer(testMux())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	c := newTestClient(t)
	defer c.Close()
	body := make([]byte, 500000)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	resp := doOK(t, c, srv.URL+"/echo", "POST", true, body)
	if resp.Status != 201 || len(resp.Body) != len(body) || string(resp.Body) != string(body) {
		t.Fatalf("h2 large body: status=%d len=%d want=%d", resp.Status, len(resp.Body), len(body))
	}
}
