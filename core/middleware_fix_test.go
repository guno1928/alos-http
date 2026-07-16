package core

import (
	"encoding/base64"
	"testing"
	"time"
)

func newTestReq() *Request {
	return &Request{Headers: make([][2]string, 0, 8), Proto: "HTTP/1.1", Method: "GET", Path: "/"}
}

func newTestResp() *Response {
	return &Response{Headers: make([][2]string, 0, 8), body: make([]byte, 0, 4096)}
}

func TestConstantTimeEqualString(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"", "", true},
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"abc", "ab", false},
		{"token123", "token123", true},
		{"token123", "token124", false},
	}
	for _, c := range cases {
		if got := constantTimeEqualString(c.a, c.b); got != c.want {
			t.Errorf("constantTimeEqualString(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestBasicAuthPrecompute(t *testing.T) {
	mw := BasicAuth(BasicAuthConfig{Users: map[string]string{"admin": "secret", "alice": "pw1"}})
	called := false
	h := mw(func(req *Request, resp *Response) { called = true; resp.Status(200).String("ok") })

	check := func(user, pass string, wantStatus int, wantCalled bool) {
		called = false
		req := newTestReq()
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Headers = append(req.Headers, [2]string{"authorization", "Basic " + cred})
		resp := newTestResp()
		h(req, resp)
		if resp.StatusCode != wantStatus || called != wantCalled {
			t.Errorf("auth %s:%s => status=%d called=%v, want status=%d called=%v", user, pass, resp.StatusCode, called, wantStatus, wantCalled)
		}
	}
	check("admin", "secret", 200, true)
	check("alice", "pw1", 200, true)
	check("admin", "wrong", 401, false)
	check("nobody", "secret", 401, false)
	check("alice", "pw2", 401, false)
}

func TestCORSWildcard(t *testing.T) {
	ce := NewCORSEngine(CORSConfig{AllowOrigins: []string{"*"}})
	snap := ce.snapshot.Load()
	req := newTestReq()
	resp := newTestResp()
	ce.applyCORS(snap, req, resp)
	found := false
	for _, h := range resp.Headers {
		if h[0] == "access-control-allow-origin" && h[1] == "*" {
			found = true
		}
	}
	if !found {
		t.Errorf("wildcard CORS did not set allow-origin:* headers=%v", resp.Headers)
	}
}

func TestTimeoutFastAndSlow(t *testing.T) {
	fast := Timeout(300 * time.Millisecond)(func(req *Request, resp *Response) {
		resp.Status(200).String("fast")
	})
	req := newTestReq()
	resp := newTestResp()
	fast(req, resp)
	if resp.StatusCode != 200 {
		t.Errorf("fast handler through Timeout: status=%d want 200", resp.StatusCode)
	}

	slow := Timeout(150 * time.Millisecond)(func(req *Request, resp *Response) {
		time.Sleep(600 * time.Millisecond)
		resp.Status(200).String("slow")
	})
	req2 := newTestReq()
	resp2 := newTestResp()
	start := time.Now()
	slow(req2, resp2)
	elapsed := time.Since(start)
	if resp2.StatusCode != 504 {
		t.Errorf("slow handler through Timeout: status=%d want 504", resp2.StatusCode)
	}
	if elapsed > 400*time.Millisecond {
		t.Errorf("Timeout did not fire promptly: took %v (expected ~150ms)", elapsed)
	}
}

func BenchmarkReleasePooledBuf(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := acquirePooledBuf(&connReadBufPool)
		buf = append(buf, 'x')
		releasePooledBuf(&connReadBufPool, buf, connBufPoolMaxCap)
	}
}

func BenchmarkTimeoutMiddleware_Fast(b *testing.B) {
	h := Timeout(time.Second)(func(req *Request, resp *Response) { resp.Status(200) })
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := newTestReq()
		resp := newTestResp()
		h(req, resp)
	}
}
