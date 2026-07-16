package core

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func authHeader(req *Request, user, pass string) {
	cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	req.Headers = append(req.Headers, [2]string{"authorization", "Basic " + cred})
}

func TestVerify_TokenBucket(t *testing.T) {
	t.Run("AllowWithinBurst", func(t *testing.T) {
		tb := NewTokenBucket(1000, 10)
		if !tb.Allow(5) {
			t.Fatal("expected allow within burst")
		}
	})
	t.Run("AllowExactBurst", func(t *testing.T) {
		tb := NewTokenBucket(1000, 10)
		if !tb.Allow(10) {
			t.Fatal("expected allow exact burst")
		}
	})
	t.Run("AllowExceedsBurst", func(t *testing.T) {
		tb := NewTokenBucket(1000, 10)
		if tb.Allow(11) {
			t.Fatal("expected deny exceeding burst")
		}
	})
	t.Run("AllowZeroTokensAlways", func(t *testing.T) {
		tb := NewTokenBucket(1000, 10)
		if !tb.Allow(0) {
			t.Fatal("zero tokens should always allow")
		}
	})
	t.Run("DenyWhenDrained", func(t *testing.T) {
		tb := NewTokenBucket(1, 5)
		for i := 0; i < 5; i++ {
			tb.Allow(1)
		}
		if tb.Allow(1) {
			t.Fatal("expected deny when drained")
		}
	})
	t.Run("RefillOverTime", func(t *testing.T) {
		tb := NewTokenBucket(100000, 10)
		for i := 0; i < 10; i++ {
			tb.Allow(1)
		}
		time.Sleep(30 * time.Millisecond)
		if !tb.Allow(1) {
			t.Fatal("expected refill to grant a token after sleep")
		}
	})
	t.Run("WaitReturnsFastWhenAvailable", func(t *testing.T) {
		tb := NewTokenBucket(1000, 100)
		start := time.Now()
		tb.Wait(5)
		if time.Since(start) > 50*time.Millisecond {
			t.Fatal("Wait blocked despite available tokens")
		}
	})
	t.Run("WaitWithDeadlineExpires", func(t *testing.T) {
		tb := NewTokenBucket(1, 1)
		tb.Allow(1)
		if tb.WaitWithDeadline(1, time.Now().Add(40*time.Millisecond)) {
			t.Fatal("expected WaitWithDeadline to expire and return false")
		}
	})
}

func TestVerify_RateLimitEngine(t *testing.T) {
	mkEngine := func(rules []RateLimitRule) *RateLimitEngine {
		e := NewRateLimitEngine()
		e.SetRules(rules)
		return e
	}
	t.Run("NoRuleAllowsAll", func(t *testing.T) {
		e := mkEngine(nil)
		for i := 0; i < 100; i++ {
			if ok, _, _ := e.Check("1.1.1.1", "/x"); !ok {
				t.Fatal("no rule should allow all")
			}
		}
		e.Stop()
	})
	t.Run("UnderLimitAllowed", func(t *testing.T) {
		e := mkEngine([]RateLimitRule{{Path: "/api", MaxReqs: 5, Window: time.Second, BlockFor: time.Second}})
		for i := 0; i < 5; i++ {
			if ok, _, _ := e.Check("2.2.2.2", "/api"); !ok {
				t.Fatalf("req %d under limit should pass", i)
			}
		}
		e.Stop()
	})
	t.Run("OverLimitBlocked", func(t *testing.T) {
		e := mkEngine([]RateLimitRule{{Path: "/api", MaxReqs: 3, Window: time.Second, BlockFor: time.Second}})
		for i := 0; i < 3; i++ {
			e.Check("3.3.3.3", "/api")
		}
		if ok, _, _ := e.Check("3.3.3.3", "/api"); ok {
			t.Fatal("4th request over limit should be blocked")
		}
		e.Stop()
	})
	t.Run("DifferentIPsIndependent", func(t *testing.T) {
		e := mkEngine([]RateLimitRule{{Path: "/api", MaxReqs: 2, Window: time.Second, BlockFor: time.Second}})
		e.Check("4.4.4.4", "/api")
		e.Check("4.4.4.4", "/api")
		if ok, _, _ := e.Check("5.5.5.5", "/api"); !ok {
			t.Fatal("different IP should have its own budget")
		}
		e.Stop()
	})
	t.Run("PrefixRuleMatches", func(t *testing.T) {
		e := mkEngine([]RateLimitRule{{Path: "/api/*", MaxReqs: 1, Window: time.Second, BlockFor: time.Second}})
		e.Check("6.6.6.6", "/api/users")
		if ok, _, _ := e.Check("6.6.6.6", "/api/users"); ok {
			t.Fatal("prefix rule should match and block")
		}
		e.Stop()
	})
	t.Run("BlockExpiresAfterWindow", func(t *testing.T) {
		e := mkEngine([]RateLimitRule{{Path: "/z", MaxReqs: 1, Window: 30 * time.Millisecond, BlockFor: 30 * time.Millisecond}})
		e.Check("7.7.7.7", "/z")
		e.Check("7.7.7.7", "/z")
		time.Sleep(80 * time.Millisecond)
		if ok, _, _ := e.Check("7.7.7.7", "/z"); !ok {
			t.Fatal("block should expire after window")
		}
		e.Stop()
	})
}

func TestVerify_BasicAuth(t *testing.T) {
	mw := BasicAuth(BasicAuthConfig{Users: map[string]string{"admin": "secret", "alice": "pw1"}})
	run := func(setup func(*Request), wantStatus int) func(*testing.T) {
		return func(t *testing.T) {
			called := false
			h := mw(func(req *Request, resp *Response) { called = true; resp.Status(200) })
			req := newTestReq()
			setup(req)
			resp := newTestResp()
			h(req, resp)
			if resp.StatusCode != wantStatus {
				t.Fatalf("status=%d want %d (called=%v)", resp.StatusCode, wantStatus, called)
			}
			if wantStatus == 200 && !called {
				t.Fatal("expected handler called on success")
			}
			if wantStatus == 401 && called {
				t.Fatal("handler must not run on auth failure")
			}
		}
	}
	t.Run("ValidAdmin", run(func(r *Request) { authHeader(r, "admin", "secret") }, 200))
	t.Run("ValidAlice", run(func(r *Request) { authHeader(r, "alice", "pw1") }, 200))
	t.Run("WrongPassword", run(func(r *Request) { authHeader(r, "admin", "nope") }, 401))
	t.Run("UnknownUser", run(func(r *Request) { authHeader(r, "ghost", "secret") }, 401))
	t.Run("CrossUserPassword", run(func(r *Request) { authHeader(r, "alice", "secret") }, 401))
	t.Run("MissingHeader", run(func(r *Request) {}, 401))
	t.Run("NonBasicScheme", run(func(r *Request) {
		r.Headers = append(r.Headers, [2]string{"authorization", "Bearer xyz"})
	}, 401))
	t.Run("BadBase64", run(func(r *Request) {
		r.Headers = append(r.Headers, [2]string{"authorization", "Basic !!!notbase64!!!"})
	}, 401))
	t.Run("NoColon", run(func(r *Request) {
		r.Headers = append(r.Headers, [2]string{"authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon"))})
	}, 401))
}

func TestVerify_CSRFCompare(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"Equal", "abcdef", "abcdef", true},
		{"DiffContent", "abcdef", "abcxef", false},
		{"DiffLength", "abcdef", "abcde", false},
		{"BothEmpty", "", "", true},
		{"OneEmpty", "x", "", false},
		{"LongEqual", strings.Repeat("k", 64), strings.Repeat("k", 64), true},
		{"LongDiffLast", strings.Repeat("k", 63) + "a", strings.Repeat("k", 63) + "b", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if constantTimeEqualString(c.a, c.b) != c.want {
				t.Fatalf("got %v want %v", !c.want, c.want)
			}
		})
	}
}

func TestVerify_CORS(t *testing.T) {
	hasHdr := func(resp *Response, k, v string) bool {
		for _, h := range resp.Headers {
			if h[0] == k && h[1] == v {
				return true
			}
		}
		return false
	}
	t.Run("WildcardStar", func(t *testing.T) {
		ce := NewCORSEngine(CORSConfig{AllowOrigins: []string{"*"}})
		req := newTestReq()
		resp := newTestResp()
		ce.applyCORS(ce.snapshot.Load(), req, resp)
		if !hasHdr(resp, "access-control-allow-origin", "*") {
			t.Fatal("wildcard should set allow-origin *")
		}
	})
	t.Run("SpecificAllowed", func(t *testing.T) {
		ce := NewCORSEngine(CORSConfig{AllowOrigins: []string{"https://ok.com"}})
		req := newTestReq()
		req.Headers = append(req.Headers, [2]string{"origin", "https://ok.com"})
		resp := newTestResp()
		ce.applyCORS(ce.snapshot.Load(), req, resp)
		if !hasHdr(resp, "access-control-allow-origin", "https://ok.com") {
			t.Fatal("allowed origin should be echoed")
		}
	})
	t.Run("SpecificRejected", func(t *testing.T) {
		ce := NewCORSEngine(CORSConfig{AllowOrigins: []string{"https://ok.com"}})
		req := newTestReq()
		req.Headers = append(req.Headers, [2]string{"origin", "https://evil.com"})
		resp := newTestResp()
		ce.applyCORS(ce.snapshot.Load(), req, resp)
		for _, h := range resp.Headers {
			if h[0] == "access-control-allow-origin" {
				t.Fatal("disallowed origin must not get allow-origin header")
			}
		}
	})
	t.Run("MethodsAdvertised", func(t *testing.T) {
		ce := NewCORSEngine(CORSConfig{AllowOrigins: []string{"*"}, AllowMethods: []string{"GET", "POST"}})
		req := newTestReq()
		resp := newTestResp()
		ce.applyCORS(ce.snapshot.Load(), req, resp)
		found := false
		for _, h := range resp.Headers {
			if h[0] == "access-control-allow-methods" && strings.Contains(h[1], "POST") {
				found = true
			}
		}
		if !found {
			t.Fatal("expected allow-methods header")
		}
	})
}

func TestVerify_Timeout(t *testing.T) {
	t.Run("FastPasses200", func(t *testing.T) {
		h := Timeout(300 * time.Millisecond)(func(req *Request, resp *Response) { resp.Status(200).String("ok") })
		resp := newTestResp()
		h(newTestReq(), resp)
		if resp.StatusCode != 200 {
			t.Fatalf("status=%d want 200", resp.StatusCode)
		}
	})
	t.Run("SlowReturns504", func(t *testing.T) {
		h := Timeout(120 * time.Millisecond)(func(req *Request, resp *Response) {
			time.Sleep(600 * time.Millisecond)
			resp.Status(200)
		})
		resp := newTestResp()
		h(newTestReq(), resp)
		if resp.StatusCode != 504 {
			t.Fatalf("status=%d want 504", resp.StatusCode)
		}
	})
	t.Run("FiresPromptly", func(t *testing.T) {
		h := Timeout(120 * time.Millisecond)(func(req *Request, resp *Response) {
			time.Sleep(2 * time.Second)
			resp.Status(200)
		})
		start := time.Now()
		resp := newTestResp()
		h(newTestReq(), resp)
		if d := time.Since(start); d > 400*time.Millisecond {
			t.Fatalf("timeout fired late: %v", d)
		}
	})
	t.Run("BodyPassedThrough", func(t *testing.T) {
		h := Timeout(300 * time.Millisecond)(func(req *Request, resp *Response) { resp.Status(201).String("payload-here") })
		resp := newTestResp()
		h(newTestReq(), resp)
		if string(resp.GetBody()) != "payload-here" || resp.StatusCode != 201 {
			t.Fatalf("body/status not passed through: %d %q", resp.StatusCode, resp.GetBody())
		}
	})
}

func TestVerify_Pools(t *testing.T) {
	t.Run("AcquireEmpty", func(t *testing.T) {
		b := acquirePooledBuf(&connReadBufPool)
		if len(b) != 0 {
			t.Fatalf("acquired buffer should be empty, len=%d", len(b))
		}
		releasePooledBuf(&connReadBufPool, b, connBufPoolMaxCap)
	})
	t.Run("ReleaseThenReuseKeepsCap", func(t *testing.T) {
		b := acquirePooledBuf(&connReadBufPool)
		b = append(b, make([]byte, 4096)...)
		releasePooledBuf(&connReadBufPool, b, connBufPoolMaxCap)
		b2 := acquirePooledBuf(&connReadBufPool)
		if cap(b2) < 4096 {
			t.Fatalf("expected reused buffer to retain cap, got %d", cap(b2))
		}
		releasePooledBuf(&connReadBufPool, b2, connBufPoolMaxCap)
	})
	t.Run("OversizedDropped", func(t *testing.T) {
		big := make([]byte, 0, connBufPoolMaxCap*2)
		releasePooledBuf(&connReadBufPool, big, connBufPoolMaxCap)
	})
	t.Run("ManyCyclesNoPanic", func(t *testing.T) {
		for i := 0; i < 10000; i++ {
			b := acquirePooledBuf(&connWriteBufPool)
			b = append(b, 'a', 'b', 'c')
			releasePooledBuf(&connWriteBufPool, b, connBufPoolMaxCap)
		}
	})
}

func TestVerify_PrepareBody(t *testing.T) {
	t.Run("FitsReusesBuffer", func(t *testing.T) {
		r := newTestResp()
		orig := cap(r.body)
		buf := r.prepareBody(orig / 2)
		if len(buf) != orig/2 {
			t.Fatalf("len=%d want %d", len(buf), orig/2)
		}
		if cap(r.body) != orig {
			t.Fatalf("should reuse buffer, cap changed %d->%d", orig, cap(r.body))
		}
	})
	t.Run("ExceedsAllocates", func(t *testing.T) {
		r := newTestResp()
		n := cap(r.body) + 5000
		buf := r.prepareBody(n)
		if len(buf) != n {
			t.Fatalf("len=%d want %d", len(buf), n)
		}
	})
	t.Run("ContentReadable", func(t *testing.T) {
		r := newTestResp()
		buf := r.prepareBody(4)
		copy(buf, "test")
		if string(r.GetBody()) != "test" {
			t.Fatalf("GetBody=%q want test", r.GetBody())
		}
	})
}

func TestVerify_Compress(t *testing.T) {
	t.Run("NegotiateGzip", func(t *testing.T) {
		if negotiateEncoding("gzip, deflate") != encodingGzip {
			t.Fatal("should pick gzip")
		}
	})
	t.Run("NegotiateDeflate", func(t *testing.T) {
		if negotiateEncoding("deflate") != encodingDeflate {
			t.Fatal("should pick deflate")
		}
	})
	t.Run("NegotiateNone", func(t *testing.T) {
		if negotiateEncoding("") != encodingNone {
			t.Fatal("empty should be none")
		}
	})
	t.Run("CompressesLargeBody", func(t *testing.T) {
		req := newTestReq()
		req.Headers = append(req.Headers, [2]string{"accept-encoding", "gzip"})
		resp := newTestResp()
		resp.lazyReq = req
		h := Compress(CompressConfig{Level: 6, MinSize: 256})(func(req *Request, resp *Response) {
			resp.Status(200).String(strings.Repeat("abcd", 1000))
		})
		h(req, resp)
		enc := ""
		for _, hd := range resp.Headers {
			if hd[0] == "Content-Encoding" {
				enc = hd[1]
			}
		}
		if enc != "gzip" {
			t.Fatalf("expected gzip content-encoding, got %q", enc)
		}
		if resp.transmittedBodyLen() >= 4000 {
			t.Fatalf("body not compressed, len=%d", resp.transmittedBodyLen())
		}
	})
	t.Run("SkipsSmallBody", func(t *testing.T) {
		req := newTestReq()
		req.Headers = append(req.Headers, [2]string{"accept-encoding", "gzip"})
		resp := newTestResp()
		resp.lazyReq = req
		h := Compress(CompressConfig{Level: 6, MinSize: 256})(func(req *Request, resp *Response) {
			resp.Status(200).String("tiny")
		})
		h(req, resp)
		for _, hd := range resp.Headers {
			if hd[0] == "Content-Encoding" {
				t.Fatal("small body must not be compressed")
			}
		}
	})
}

func TestVerify_RealIP(t *testing.T) {
	t.Run("TrustAllRewritesFromXFF", func(t *testing.T) {
		h := RealIP()(func(req *Request, resp *Response) { resp.Status(200).String(req.RemoteAddr) })
		req := newTestReq()
		req.RemoteAddr = "1.2.3.4:5678"
		req.Headers = append(req.Headers, [2]string{"x-forwarded-for", "9.8.7.6"})
		resp := newTestResp()
		h(req, resp)
		if req.RemoteAddr != "9.8.7.6" {
			t.Fatalf("expected rewrite to 9.8.7.6, got %s", req.RemoteAddr)
		}
	})
	t.Run("UntrustedPeerNoRewrite", func(t *testing.T) {
		h := RealIP("10.0.0.0/8")(func(req *Request, resp *Response) { resp.Status(200) })
		req := newTestReq()
		req.RemoteAddr = "1.2.3.4:5678"
		req.Headers = append(req.Headers, [2]string{"x-forwarded-for", "9.8.7.6"})
		resp := newTestResp()
		h(req, resp)
		if req.RemoteAddr != "1.2.3.4:5678" {
			t.Fatalf("untrusted peer must not rewrite, got %s", req.RemoteAddr)
		}
	})
	t.Run("TrustedCIDRRewrites", func(t *testing.T) {
		h := RealIP("10.0.0.0/8")(func(req *Request, resp *Response) { resp.Status(200) })
		req := newTestReq()
		req.RemoteAddr = "10.1.2.3:9999"
		req.Headers = append(req.Headers, [2]string{"x-real-ip", "203.0.113.9"})
		resp := newTestResp()
		h(req, resp)
		if req.RemoteAddr != "203.0.113.9" {
			t.Fatalf("trusted CIDR should rewrite from x-real-ip, got %s", req.RemoteAddr)
		}
	})
}

func TestVerify_MiscMiddleware(t *testing.T) {
	t.Run("RequestIDHeaderSet", func(t *testing.T) {
		h := RequestID()(func(req *Request, resp *Response) { resp.Status(200) })
		req := newTestReq()
		resp := newTestResp()
		h(req, resp)
		found := false
		for _, hd := range resp.Headers {
			if hd[0] == "x-request-id" && hd[1] != "" {
				found = true
			}
		}
		if !found {
			t.Fatal("expected x-request-id header")
		}
	})
	t.Run("RecoverCatchesPanic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic escaped Recover: %v", r)
			}
		}()
		h := Recovery()(func(req *Request, resp *Response) { panic("boom") })
		resp := newTestResp()
		h(newTestReq(), resp)
	})
}
