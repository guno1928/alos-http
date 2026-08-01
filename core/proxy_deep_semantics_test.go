//go:build linux && amd64

package core

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// dpProxy starts a plaintext proxy in front of a raw origin handler.
func dpProxy(t *testing.T, handler func(req *http.Request, conn net.Conn, br *bufio.Reader)) string {
	t.Helper()
	o := newInloopOrigin(t, handler)
	return startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, nil)
}

// dpRaw sends a raw request and returns the whole raw response.
func dpRaw(t *testing.T, addr, raw string, wait time.Duration) string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(wait))
	out, _ := io.ReadAll(conn)
	return string(out)
}

func dpFixed(body string) func(*http.Request, net.Conn, *bufio.Reader) {
	return func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		if req.ContentLength > 0 {
			io.CopyN(io.Discard, req.Body, req.ContentLength)
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}
}

// ---------- methods ----------

func TestDeepMethodsAreForwarded(t *testing.T) {
	var seen atomic.Value
	seen.Store("")
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		seen.Store(req.Method)
		if req.ContentLength > 0 {
			io.CopyN(io.Discard, req.Body, req.ContentLength)
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})

	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		var body io.Reader
		if m == "POST" || m == "PUT" || m == "PATCH" {
			body = strings.NewReader("x")
		}
		req, _ := http.NewRequest(m, "http://"+addr+"/m", body)
		req.Host = "origin.test"
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if got := seen.Load().(string); got != m {
			t.Errorf("backend saw method %q, want %q", got, m)
		}
	}
}

func TestDeepHeadHasNoBody(t *testing.T) {
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		// A HEAD response carries Content-Length but no body.
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")
	})
	req, _ := http.NewRequest("HEAD", "http://"+addr+"/h", nil)
	req.Host = "origin.test"
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Fatalf("HEAD returned %d body bytes", len(body))
	}
	if resp.ContentLength != 1234 {
		t.Errorf("Content-Length = %d, want 1234", resp.ContentLength)
	}
}

// ---------- status codes ----------

func TestDeepStatusCodesPassThrough(t *testing.T) {
	for _, code := range []int{200, 201, 202, 204, 301, 302, 304, 400, 401, 403, 404, 410, 418, 429, 500, 502, 503} {
		code := code
		addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
			if code == 204 || code == 304 {
				fmt.Fprintf(conn, "HTTP/1.1 %d X\r\n\r\n", code)
				return
			}
			fmt.Fprintf(conn, "HTTP/1.1 %d X\r\nContent-Length: 2\r\n\r\nok", code)
		})
		resp, _ := doProxyGet(t, addr, "/s")
		if resp.StatusCode != code {
			t.Errorf("status = %d, want %d", resp.StatusCode, code)
		}
	}
}

func TestDeepBodylessStatusesHaveNoBody(t *testing.T) {
	for _, code := range []int{204, 304} {
		code := code
		addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
			fmt.Fprintf(conn, "HTTP/1.1 %d X\r\n\r\n", code)
		})
		resp, body := doProxyGet(t, addr, "/e")
		if resp.StatusCode != code {
			t.Fatalf("status = %d, want %d", resp.StatusCode, code)
		}
		if body != "" {
			t.Errorf("%d returned a %d byte body", code, len(body))
		}
	}
}

// ---------- headers ----------

func TestDeepResponseHeadersPreserved(t *testing.T) {
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"+
			"X-One: alpha\r\nX-Two: beta\r\nCache-Control: max-age=60\r\nETag: \"abc\"\r\n\r\nok")
	})
	resp, _ := doProxyGet(t, addr, "/h")
	for name, want := range map[string]string{
		"X-One": "alpha", "X-Two": "beta",
		"Cache-Control": "max-age=60", "Etag": `"abc"`,
	} {
		if got := resp.Header.Get(name); got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}
}

func TestDeepRequestHeadersReachBackend(t *testing.T) {
	got := make(chan http.Header, 1)
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		select {
		case got <- req.Header.Clone():
		default:
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	req, _ := http.NewRequest("GET", "http://"+addr+"/r", nil)
	req.Host = "origin.test"
	req.Header.Set("X-Custom", "value-1")
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	h := <-got
	if h.Get("X-Custom") != "value-1" {
		t.Errorf("X-Custom = %q", h.Get("X-Custom"))
	}
	if h.Get("Authorization") != "Bearer tok" {
		t.Errorf("Authorization = %q", h.Get("Authorization"))
	}
}

func TestDeepRepeatedResponseHeadersPreserved(t *testing.T) {
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"+
			"Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nok")
	})
	resp, _ := doProxyGet(t, addr, "/c")
	if n := len(resp.Header.Values("Set-Cookie")); n != 2 {
		t.Fatalf("got %d Set-Cookie headers, want 2: %v", n, resp.Header.Values("Set-Cookie"))
	}
}

func TestDeepManyResponseHeaders(t *testing.T) {
	const n = 60
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		var sb strings.Builder
		sb.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&sb, "X-H-%d: v%d\r\n", i, i)
		}
		sb.WriteString("\r\nok")
		io.WriteString(conn, sb.String())
	})
	resp, _ := doProxyGet(t, addr, "/many")
	for i := 0; i < n; i++ {
		if got := resp.Header.Get(fmt.Sprintf("X-H-%d", i)); got != fmt.Sprintf("v%d", i) {
			t.Fatalf("header X-H-%d = %q", i, got)
		}
	}
}

func TestDeepLongHeaderValuePreserved(t *testing.T) {
	long := strings.Repeat("z", 3000)
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Long: %s\r\n\r\nok", long)
	})
	resp, _ := doProxyGet(t, addr, "/l")
	if got := resp.Header.Get("X-Long"); got != long {
		t.Fatalf("long header value truncated: got %d bytes, want %d", len(got), len(long))
	}
}

// ---------- bodies ----------

func TestDeepBodySizesAreExact(t *testing.T) {
	for _, size := range []int{0, 1, 255, 1024, 8192, 65535, 65536, 65537, 300000} {
		size := size
		body := strings.Repeat("q", size)
		addr := dpProxy(t, dpFixed(body))
		resp, got := doProxyGet(t, addr, "/b")
		if resp.StatusCode != 200 {
			t.Fatalf("size %d: status %d", size, resp.StatusCode)
		}
		if len(got) != size {
			t.Fatalf("size %d: got %d bytes", size, len(got))
		}
	}
}

func TestDeepBinaryBodyIsUnaltered(t *testing.T) {
	body := make([]byte, 128<<10)
	for i := range body {
		body[i] = byte(i * 7)
	}
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body))
		conn.Write(body)
	})
	_, got := doProxyGet(t, addr, "/bin")
	if len(got) != len(body) {
		t.Fatalf("got %d bytes, want %d", len(got), len(body))
	}
	for i := range body {
		if got[i] != body[i] {
			t.Fatalf("byte %d differs", i)
		}
	}
}

func TestDeepPostBodySizes(t *testing.T) {
	for _, size := range []int{1, 1024, 100000} {
		size := size
		payload := strings.Repeat("p", size)
		gotLen := make(chan int, 1)
		addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
			b, _ := io.ReadAll(io.LimitReader(req.Body, req.ContentLength))
			select {
			case gotLen <- len(b):
			default:
			}
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		})
		req, _ := http.NewRequest("POST", "http://"+addr+"/p", strings.NewReader(payload))
		req.Host = "origin.test"
		resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if n := <-gotLen; n != size {
			t.Fatalf("backend received %d of %d body bytes", n, size)
		}
	}
}

func TestDeepChunkedRequestBodyReachesBackend(t *testing.T) {
	gotBody := make(chan string, 1)
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		b, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		select {
		case gotBody <- string(b):
		default:
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	raw := "POST /chunked HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	dpRaw(t, addr, raw, 3*time.Second)
	select {
	case b := <-gotBody:
		if b != "hello world" {
			t.Fatalf("backend received %q, want %q", b, "hello world")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend never received the chunked body")
	}
}

func TestDeepChunkedRequestBecomesContentLength(t *testing.T) {
	gotTE := make(chan string, 1)
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		te := "none"
		if len(req.TransferEncoding) > 0 {
			te = req.TransferEncoding[0]
		}
		select {
		case gotTE <- fmt.Sprintf("%s/%d", te, req.ContentLength):
		default:
		}
		io.ReadAll(io.LimitReader(req.Body, 1<<20))
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	raw := "POST /c HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"3\r\nabc\r\n0\r\n\r\n"
	dpRaw(t, addr, raw, 3*time.Second)
	select {
	case v := <-gotTE:
		if !strings.HasPrefix(v, "none/") {
			t.Fatalf("backend saw transfer-encoding %q; the proxy should de-chunk to Content-Length", v)
		}
		if !strings.HasSuffix(v, "/3") {
			t.Fatalf("backend saw %q, want Content-Length 3", v)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend never received the request")
	}
}

func TestDeepChunkedResponseWithManyChunks(t *testing.T) {
	const chunks = 200
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
		for i := 0; i < chunks; i++ {
			part := fmt.Sprintf("p%03d", i)
			fmt.Fprintf(conn, "%x\r\n%s\r\n", len(part), part)
		}
		io.WriteString(conn, "0\r\n\r\n")
	})
	_, body := doProxyGet(t, addr, "/mc")
	var want strings.Builder
	for i := 0; i < chunks; i++ {
		fmt.Fprintf(&want, "p%03d", i)
	}
	if body != want.String() {
		t.Fatalf("chunked body mismatch: got %d bytes, want %d", len(body), want.Len())
	}
}

func TestDeepChunkedResponseWithExtensionsAndTrailers(t *testing.T) {
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
		io.WriteString(conn, "5;ext=1\r\nhello\r\n")
		io.WriteString(conn, "0\r\nX-Trailer: done\r\n\r\n")
	})
	resp, body := doProxyGet(t, addr, "/tr")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if body != "hello" {
		t.Fatalf("body = %q, want hello", body)
	}
}

// ---------- targets ----------

func TestDeepQueryStringPreserved(t *testing.T) {
	gotURI := make(chan string, 1)
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		select {
		case gotURI <- req.RequestURI:
		default:
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	dpRaw(t, addr, "GET /search?q=a+b&x=1&empty=&flag HTTP/1.1\r\nHost: origin.test\r\n\r\n", 3*time.Second)
	select {
	case uri := <-gotURI:
		if uri != "/search?q=a+b&x=1&empty=&flag" {
			t.Fatalf("backend saw %q", uri)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no request reached the backend")
	}
}

func TestDeepEncodedPathsPreserved(t *testing.T) {
	for _, target := range []string{
		"/a%2Fb", "/%E2%82%AC", "/sp%20ace", "/tilde~", "/a//b", "/dot./x",
	} {
		target := target
		gotURI := make(chan string, 1)
		addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
			select {
			case gotURI <- req.RequestURI:
			default:
			}
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		})
		dpRaw(t, addr, "GET "+target+" HTTP/1.1\r\nHost: origin.test\r\n\r\n", 3*time.Second)
		select {
		case uri := <-gotURI:
			if uri != target {
				t.Errorf("target %q reached the backend as %q", target, uri)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("target %q never reached the backend", target)
		}
	}
}

// ---------- connection management ----------

func TestDeepPipelinedRequestsAnsweredInOrder(t *testing.T) {
	var n atomic.Int64
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		i := n.Add(1)
		body := fmt.Sprintf("r%d", i)
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	})
	raw := "GET /1 HTTP/1.1\r\nHost: origin.test\r\n\r\n" +
		"GET /2 HTTP/1.1\r\nHost: origin.test\r\n\r\n" +
		"GET /3 HTTP/1.1\r\nHost: origin.test\r\n\r\n"
	out := dpRaw(t, addr, raw, 3*time.Second)
	if got := strings.Count(out, "HTTP/1.1 200"); got != 3 {
		t.Fatalf("got %d responses for 3 pipelined requests:\n%s", got, out)
	}
	i1, i2, i3 := strings.Index(out, "r1"), strings.Index(out, "r2"), strings.Index(out, "r3")
	if i1 < 0 || i2 < 0 || i3 < 0 || !(i1 < i2 && i2 < i3) {
		t.Fatalf("pipelined responses out of order (%d,%d,%d):\n%s", i1, i2, i3, out)
	}
}

func TestDeepKeepAliveManyRequestsOneConn(t *testing.T) {
	addr := dpProxy(t, dpFixed("ok"))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	for i := 0; i < 100; i++ {
		if _, err := io.WriteString(conn, "GET /k HTTP/1.1\r\nHost: origin.test\r\n\r\n"); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, rerr := http.ReadResponse(br, nil)
		if rerr != nil {
			t.Fatalf("response %d: %v", i, rerr)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "ok" {
			t.Fatalf("response %d body = %q", i, body)
		}
	}
}

func TestDeepConnectionCloseClosesClientConn(t *testing.T) {
	addr := dpProxy(t, dpFixed("bye"))
	out := dpRaw(t, addr, "GET /x HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n", 3*time.Second)
	if !strings.Contains(out, "bye") {
		t.Fatalf("response missing body:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "connection: close") {
		t.Errorf("response did not advertise Connection: close:\n%s", out)
	}
}

func TestDeepBackendConnectionCloseIsAbsorbed(t *testing.T) {
	// The backend closes after each response; the client must still get
	// keep-alive and the proxy must transparently redial.
	var conns atomic.Int64
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			conns.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, rerr := http.ReadRequest(br); rerr != nil {
					return
				}
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(c)
		}
	}()
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: ln.Addr().String()}},
	}, nil)

	for i := 0; i < 10; i++ {
		resp, body := doProxyGet(t, addr, "/x")
		if resp.StatusCode != 200 || body != "ok" {
			t.Fatalf("request %d: status=%d body=%q", i, resp.StatusCode, body)
		}
	}
	if conns.Load() < 10 {
		t.Logf("backend opened %d connections for 10 requests (expected ~10 since it closes each)", conns.Load())
	}
}

func TestDeepHTTP10ClientGetsResponse(t *testing.T) {
	addr := dpProxy(t, dpFixed("ten"))
	out := dpRaw(t, addr, "GET /x HTTP/1.0\r\nHost: origin.test\r\n\r\n", 3*time.Second)
	if !strings.Contains(out, "ten") {
		t.Fatalf("HTTP/1.0 client got no body:\n%s", out)
	}
}

func TestDeepUnknownHostIsNotProxied(t *testing.T) {
	o := newInloopOrigin(t, dpFixed("backend"))
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	srv := New(Config{Addr: addr, PlainHTTP: true, HTTPAddr: "-", LogRequests: false, MaxConnsPerIP: -1})
	srv.Router.GET("/x", func(req *Request, resp *Response) {
		resp.Status(200).String("local")
	})
	srv.AddProxyDomain(DomainConfig{Domain: "origin.test", Backends: []BackendConfig{{Addr: o.addr()}}})
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown(contextWithTimeout(t)) })
	waitForPort(t, addr)

	out := dpRaw(t, addr, "GET /x HTTP/1.1\r\nHost: other.test\r\n\r\n", 3*time.Second)
	if !strings.Contains(out, "local") {
		t.Fatalf("an unmatched host was not served locally:\n%s", out)
	}
}

// ---------- content-length integrity ----------

func TestDeepContentLengthMatchesBody(t *testing.T) {
	body := strings.Repeat("m", 5000)
	addr := dpProxy(t, dpFixed(body))
	resp, got := doProxyGet(t, addr, "/cl")
	if resp.ContentLength != int64(len(body)) {
		t.Errorf("Content-Length = %d, want %d", resp.ContentLength, len(body))
	}
	if len(got) != len(body) {
		t.Errorf("body length = %d, want %d", len(got), len(body))
	}
}

func TestDeepNoDuplicateContentLength(t *testing.T) {
	addr := dpProxy(t, dpFixed("dup"))
	out := dpRaw(t, addr, "GET /x HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n", 3*time.Second)
	head := out
	if i := strings.Index(out, "\r\n\r\n"); i >= 0 {
		head = out[:i]
	}
	if n := strings.Count(strings.ToLower(head), "content-length:"); n != 1 {
		t.Fatalf("response head has %d Content-Length headers:\n%s", n, head)
	}
}

func TestDeepNoDuplicateConnectionHeader(t *testing.T) {
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
	})
	out := dpRaw(t, addr, "GET /x HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n", 3*time.Second)
	head := out
	if i := strings.Index(out, "\r\n\r\n"); i >= 0 {
		head = out[:i]
	}
	if n := strings.Count(strings.ToLower(head), "connection:"); n != 1 {
		t.Fatalf("response head has %d Connection headers:\n%s", n, head)
	}
}

func TestDeepStatusTextPresent(t *testing.T) {
	addr := dpProxy(t, dpFixed("ok"))
	out := dpRaw(t, addr, "GET /x HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n", 3*time.Second)
	if !strings.HasPrefix(out, "HTTP/1.1 200 ") {
		t.Fatalf("status line malformed: %q", firstLine(out))
	}
	if strings.HasPrefix(out, "HTTP/1.1 200 \r\n") {
		t.Fatalf("status line has an empty reason phrase: %q", firstLine(out))
	}
}

func firstLine(s string) string {
	if i := strings.Index(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

func TestDeepLargeResponseHeaderBlock(t *testing.T) {
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		var sb strings.Builder
		sb.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n")
		for i := 0; i < 40; i++ {
			sb.WriteString("X-Pad-" + strconv.Itoa(i) + ": " + strings.Repeat("y", 200) + "\r\n")
		}
		sb.WriteString("\r\nok")
		io.WriteString(conn, sb.String())
	})
	resp, body := doProxyGet(t, addr, "/big-head")
	if resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Pad-39"); len(got) != 200 {
		t.Fatalf("last padded header truncated: %d bytes", len(got))
	}
}
