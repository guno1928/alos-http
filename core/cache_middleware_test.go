package core

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

func cReq(method, host, path, query string, hdrs ...[2]string) *Request {
	return &Request{Method: method, Host: host, Path: path, Query: query, Headers: hdrs}
}

func cResp() *Response {
	r := &Response{}
	r.Reset()
	return r
}

func gzHdr() [2]string { return [2]string{"Accept-Encoding", "gzip, deflate"} }

func respHeader(resp *Response, name string) (string, bool) {
	for i := range resp.Headers {
		if EqualFoldASCII(resp.Headers[i][0], name) {
			return resp.Headers[i][1], true
		}
	}
	return "", false
}

func bigBody(n int) string { return strings.Repeat("abcdefgh", n/8+1)[:n] }

func TestCache_MissThenHit_HandlerCalledOnce(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) { atomic.AddInt32(&calls, 1); resp.Status(200).String("hello") }
	for i := 0; i < 5; i++ {
		rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	}
	if calls != 1 {
		t.Fatalf("handler called %d times, want 1", calls)
	}
}

func TestCache_HitReturnsSameBody(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	h := func(req *Request, resp *Response) { resp.Status(200).String("the-body") }
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	r2 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", ""), r2)
	if got := string(r2.transmittedBodyBytes()); got != "the-body" {
		t.Fatalf("hit body=%q want the-body", got)
	}
}

func TestCache_HitPreservesStatus(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, CacheableStatus: func(int) bool { return true }})
	defer rc.Stop()
	h := func(req *Request, resp *Response) { resp.Status(203).String("x") }
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	r2 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", ""), r2)
	if r2.StatusCode != 203 {
		t.Fatalf("status=%d want 203", r2.StatusCode)
	}
}

func TestCache_HitPreservesContentType(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	h := func(req *Request, resp *Response) { resp.Status(200).HTML("<h1>x</h1>") }
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	r2 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", ""), r2)
	if !strings.HasPrefix(r2.ContentType, "text/html") {
		t.Fatalf("content-type=%q want text/html", r2.ContentType)
	}
}

func TestCache_HitPreservesHeaders(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	h := func(req *Request, resp *Response) { resp.Status(200).SetHeaderUnsafe("X-Custom", "yes"); resp.String("x") }
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	r2 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", ""), r2)
	if v, ok := respHeader(r2, "X-Custom"); !ok || v != "yes" {
		t.Fatalf("header X-Custom=%q ok=%v", v, ok)
	}
}

func TestCache_TTLExpiry_HandlerCalledAgain(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: 80 * time.Millisecond})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) { atomic.AddInt32(&calls, 1); resp.Status(200).String("x") }
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	time.Sleep(200 * time.Millisecond)
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	if calls != 2 {
		t.Fatalf("handler called %d times, want 2 after TTL expiry", calls)
	}
}

func TestCache_MethodGETCached(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) { atomic.AddInt32(&calls, 1); resp.Status(200).String("x") }
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	if calls != 1 {
		t.Fatalf("GET not cached: calls=%d", calls)
	}
}

func TestCache_MethodPOSTNotCached_default(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) { atomic.AddInt32(&calls, 1); resp.Status(200).String("x") }
	rc.handle(h, cReq("POST", "x", "/a", ""), cResp())
	rc.handle(h, cReq("POST", "x", "/a", ""), cResp())
	if calls != 2 {
		t.Fatalf("POST should not be cached by default: calls=%d", calls)
	}
}

func TestCache_MethodsMultiple_HEADCached(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, Methods: []string{"GET", "HEAD"}})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) { atomic.AddInt32(&calls, 1); resp.Status(200).String("x") }
	rc.handle(h, cReq("HEAD", "x", "/a", ""), cResp())
	rc.handle(h, cReq("HEAD", "x", "/a", ""), cResp())
	if calls != 1 {
		t.Fatalf("HEAD should be cached: calls=%d", calls)
	}
}

func TestCache_MethodsCustom_POSTCached(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, Methods: []string{"POST"}})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) { atomic.AddInt32(&calls, 1); resp.Status(200).String("x") }
	rc.handle(h, cReq("POST", "x", "/a", ""), cResp())
	rc.handle(h, cReq("POST", "x", "/a", ""), cResp())
	if calls != 1 {
		t.Fatalf("POST should be cached when configured: calls=%d", calls)
	}
}

func TestCache_IgnoreQueryTrue_SharesEntry(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, IgnoreQuery: true})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) { atomic.AddInt32(&calls, 1); resp.Status(200).String("x") }
	rc.handle(h, cReq("GET", "x", "/a", "p=1"), cResp())
	rc.handle(h, cReq("GET", "x", "/a", "p=2"), cResp())
	if calls != 1 {
		t.Fatalf("IgnoreQuery should share entry: calls=%d", calls)
	}
}

func TestCache_IgnoreQueryFalse_SeparateEntries(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, IgnoreQuery: false})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) { atomic.AddInt32(&calls, 1); resp.Status(200).String("x") }
	rc.handle(h, cReq("GET", "x", "/a", "p=1"), cResp())
	rc.handle(h, cReq("GET", "x", "/a", "p=2"), cResp())
	if calls != 2 {
		t.Fatalf("distinct queries should be distinct entries: calls=%d", calls)
	}
}

func TestCache_DifferentPaths_SeparateEntries(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) { atomic.AddInt32(&calls, 1); resp.Status(200).String("x") }
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	rc.handle(h, cReq("GET", "x", "/b", ""), cResp())
	if calls != 2 {
		t.Fatalf("distinct paths should be distinct: calls=%d", calls)
	}
}

func TestCache_DifferentHosts_SeparateEntries(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) { atomic.AddInt32(&calls, 1); resp.Status(200).String("x") }
	rc.handle(h, cReq("GET", "h1", "/a", ""), cResp())
	rc.handle(h, cReq("GET", "h2", "/a", ""), cResp())
	if calls != 2 {
		t.Fatalf("distinct hosts should be distinct: calls=%d", calls)
	}
}

func TestCache_Gzip_ServedToGzipClient(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, Gzip: true, GzipMinBytes: 100})
	defer rc.Stop()
	body := bigBody(2000)
	h := func(req *Request, resp *Response) { resp.Status(200).String(body) }
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), cResp())
	r2 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), r2)
	out := r2.transmittedBodyBytes()
	if len(out) >= len(body) {
		t.Fatalf("gzip body not smaller: %d >= %d", len(out), len(body))
	}
}

func TestCache_Gzip_MagicBytes(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, Gzip: true, GzipMinBytes: 100})
	defer rc.Stop()
	body := bigBody(2000)
	h := func(req *Request, resp *Response) { resp.Status(200).String(body) }
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), cResp())
	r2 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), r2)
	out := r2.transmittedBodyBytes()
	if len(out) < 2 || out[0] != 0x1f || out[1] != 0x8b {
		t.Fatalf("body is not gzip magic: %x", out[:min(2, len(out))])
	}
}

func TestCache_Gzip_ContentEncodingSet(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, Gzip: true, GzipMinBytes: 100})
	defer rc.Stop()
	body := bigBody(2000)
	h := func(req *Request, resp *Response) { resp.Status(200).String(body) }
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), cResp())
	r2 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), r2)
	if v, ok := respHeader(r2, "Content-Encoding"); !ok || v != "gzip" {
		t.Fatalf("Content-Encoding=%q ok=%v", v, ok)
	}
}

func TestCache_Gzip_VaryHeaderSet(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, Gzip: true, GzipMinBytes: 100})
	defer rc.Stop()
	body := bigBody(2000)
	h := func(req *Request, resp *Response) { resp.Status(200).String(body) }
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), cResp())
	r2 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), r2)
	if v, ok := respHeader(r2, "Vary"); !ok || !strings.Contains(v, "Accept-Encoding") {
		t.Fatalf("Vary=%q ok=%v", v, ok)
	}
}

func TestCache_Gzip_IdentityToNonGzipClient(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, Gzip: true, GzipMinBytes: 100})
	defer rc.Stop()
	body := bigBody(2000)
	h := func(req *Request, resp *Response) { resp.Status(200).String(body) }
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), cResp())
	r2 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", ""), r2)
	if got := string(r2.transmittedBodyBytes()); got != body {
		t.Fatalf("non-gzip client got compressed/different body (len %d)", len(got))
	}
	if _, ok := respHeader(r2, "Content-Encoding"); ok {
		t.Fatal("Content-Encoding must not be set for non-gzip client")
	}
}

func TestCache_Gzip_BelowMinNotCompressed(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, Gzip: true, GzipMinBytes: 5000})
	defer rc.Stop()
	body := bigBody(1000)
	h := func(req *Request, resp *Response) { resp.Status(200).String(body) }
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), cResp())
	r2 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), r2)
	if got := string(r2.transmittedBodyBytes()); got != body {
		t.Fatalf("body below GzipMinBytes should be identity")
	}
}

func TestCache_Gzip_Disabled_NoVariant(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, Gzip: false})
	defer rc.Stop()
	body := bigBody(2000)
	h := func(req *Request, resp *Response) { resp.Status(200).String(body) }
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), cResp())
	r2 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), r2)
	if _, ok := respHeader(r2, "Content-Encoding"); ok {
		t.Fatal("gzip disabled but Content-Encoding set")
	}
}

func TestCache_Gzip_ServedIdenticalAcrossHits(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, Gzip: true, GzipMinBytes: 100})
	defer rc.Stop()
	body := bigBody(2000)
	h := func(req *Request, resp *Response) { resp.Status(200).String(body) }
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), cResp())
	r1 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), r1)
	r2 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", "", gzHdr()), r2)
	if string(r1.transmittedBodyBytes()) != string(r2.transmittedBodyBytes()) {
		t.Fatal("gzip output differs across hits (should be compressed once, stored, reused)")
	}
}

func TestCache_Skip_NoStore(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) {
		atomic.AddInt32(&calls, 1)
		resp.Status(200).SetHeaderUnsafe("Cache-Control", "no-store")
		resp.String("x")
	}
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	if calls != 2 {
		t.Fatalf("no-store must not cache: calls=%d", calls)
	}
}

func TestCache_Skip_NoCache(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) {
		atomic.AddInt32(&calls, 1)
		resp.Status(200).SetHeaderUnsafe("Cache-Control", "no-cache")
		resp.String("x")
	}
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	if calls != 2 {
		t.Fatalf("no-cache must not cache: calls=%d", calls)
	}
}

func TestCache_Skip_Private(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) {
		atomic.AddInt32(&calls, 1)
		resp.Status(200).SetHeaderUnsafe("Cache-Control", "private, max-age=60")
		resp.String("x")
	}
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	if calls != 2 {
		t.Fatalf("private must not cache: calls=%d", calls)
	}
}

func TestCache_Skip_SetCookie(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) {
		atomic.AddInt32(&calls, 1)
		resp.Status(200).SetHeaderUnsafe("Set-Cookie", "s=1")
		resp.String("x")
	}
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	if calls != 2 {
		t.Fatalf("Set-Cookie must not cache: calls=%d", calls)
	}
}

func TestCache_Skip_ExistingContentEncoding(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) {
		atomic.AddInt32(&calls, 1)
		resp.Status(200).SetHeaderUnsafe("Content-Encoding", "br")
		resp.String("x")
	}
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	if calls != 2 {
		t.Fatalf("pre-encoded must not cache: calls=%d", calls)
	}
}

func TestCache_Skip_Non200(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) { atomic.AddInt32(&calls, 1); resp.Status(404).String("nope") }
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	if calls != 2 {
		t.Fatalf("404 must not cache by default: calls=%d", calls)
	}
}

func TestCache_CacheableStatusOverride(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, CacheableStatus: func(s int) bool { return s == 404 }})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) { atomic.AddInt32(&calls, 1); resp.Status(404).String("nf") }
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	if calls != 1 {
		t.Fatalf("404 should cache with override: calls=%d", calls)
	}
}

func TestCache_Skip_LargeBody(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, MaxBodyBytes: 100})
	defer rc.Stop()
	var calls int32
	h := func(req *Request, resp *Response) { atomic.AddInt32(&calls, 1); resp.Status(200).String(bigBody(500)) }
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	if calls != 2 {
		t.Fatalf("body over MaxBodyBytes must not cache: calls=%d", calls)
	}
}

func TestCache_Skip_Streamed(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	if rc.captureAndStore("k", nil) != nil {
		t.Fatal("nil resp must not cache")
	}
}

func TestCache_MaxEntries_Bounded(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, MaxEntries: 10})
	defer rc.Stop()
	h := func(req *Request, resp *Response) { resp.Status(200).String("x") }
	for i := 0; i < 200; i++ {
		rc.handle(h, cReq("GET", "x", "/p"+string(rune('A'+i%50)), string(rune('0'+i))), cResp())
	}
	if rc.Len() > 10 {
		t.Fatalf("cache exceeded MaxEntries: Len=%d", rc.Len())
	}
}

func TestCache_EvictOverflow_OldestRemoved(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, MaxEntries: 5})
	defer rc.Stop()
	now := turbo.UnixNano()
	for i := 0; i < 20; i++ {
		rc.store.Store("k"+string(rune('A'+i)), &cachedResponse{storedAtNs: now + int64(i), expiresAtNs: now + int64(time.Hour)})
	}
	rc.evictOverflow()
	if rc.Len() != 5 {
		t.Fatalf("after evictOverflow Len=%d want 5", rc.Len())
	}
	if _, ok := rc.store.Load("kA"); ok {
		t.Fatal("oldest entry kA should have been evicted")
	}
	if _, ok := rc.store.Load("kT"); !ok {
		t.Fatal("newest entry kT should survive")
	}
}

func TestCache_EvictExpired_BySweep(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	now := turbo.UnixNano()
	rc.store.Store("fresh", &cachedResponse{expiresAtNs: now + int64(time.Hour)})
	rc.store.Store("stale", &cachedResponse{expiresAtNs: now - int64(time.Second)})
	rc.evictExpired()
	if _, ok := rc.store.Load("stale"); ok {
		t.Fatal("stale entry should be evicted")
	}
	if _, ok := rc.store.Load("fresh"); !ok {
		t.Fatal("fresh entry should remain")
	}
}

func TestCache_Purge_Empties(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	h := func(req *Request, resp *Response) { resp.Status(200).String("x") }
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	rc.Purge()
	if rc.Len() != 0 {
		t.Fatalf("after Purge Len=%d want 0", rc.Len())
	}
}

func TestCache_Len_Reflects(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	h := func(req *Request, resp *Response) { resp.Status(200).String("x") }
	rc.handle(h, cReq("GET", "x", "/a", ""), cResp())
	rc.handle(h, cReq("GET", "x", "/b", ""), cResp())
	if rc.Len() != 2 {
		t.Fatalf("Len=%d want 2", rc.Len())
	}
}

func TestCache_Concurrent_RaceFree(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, Gzip: true, GzipMinBytes: 10})
	defer rc.Stop()
	h := func(req *Request, resp *Response) { resp.Status(200).String(bigBody(300)) }
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				path := "/p" + string(rune('A'+(i%8)))
				rc.handle(h, cReq("GET", "x", path, "", gzHdr()), cResp())
			}
		}(g)
	}
	wg.Wait()
}

func TestCache_Key_Format(t *testing.T) {
	rc := NewResponseCache(CacheConfig{})
	defer rc.Stop()
	k := rc.key(cReq("GET", "host", "/p", "a=1"))
	if k != "GET host/p?a=1" {
		t.Fatalf("key=%q", k)
	}
	rc.cfg.IgnoreQuery = true
	if k2 := rc.key(cReq("GET", "host", "/p", "a=1")); k2 != "GET host/p" {
		t.Fatalf("ignore-query key=%q", k2)
	}
}

func TestCache_BodyIsolation_CloneNotAliased(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute})
	defer rc.Stop()
	h := func(req *Request, resp *Response) { resp.Status(200).Bytes([]byte("original")) }
	r1 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", ""), r1)
	b := r1.transmittedBodyBytes()
	for i := range b {
		b[i] = 'Z'
	}
	r2 := cResp()
	rc.handle(h, cReq("GET", "x", "/a", ""), r2)
	if got := string(r2.transmittedBodyBytes()); got != "original" {
		t.Fatalf("cache body was aliased/corrupted: %q", got)
	}
}

func TestCache_Defaults_Applied(t *testing.T) {
	rc := NewResponseCache(CacheConfig{})
	defer rc.Stop()
	if rc.cfg.TTL != 60*time.Second || rc.cfg.MaxEntries != 10000 || rc.cfg.MaxBodyBytes != 1<<20 {
		t.Fatalf("defaults wrong: %+v", rc.cfg)
	}
	if _, ok := rc.methods["GET"]; !ok {
		t.Fatal("default method GET missing")
	}
}

func TestCache_Stop_NoPanic(t *testing.T) {
	rc := NewResponseCache(CacheConfig{TTL: time.Minute, SweepInterval: 10 * time.Millisecond})
	rc.Stop()
	rc.Stop()
}

func TestCache_compressibleType(t *testing.T) {
	yes := []string{"", "text/html", "text/plain; charset=utf-8", "application/json", "application/javascript", "image/svg+xml"}
	no := []string{"image/png", "image/jpeg", "video/mp4", "application/octet-stream", "font/woff2"}
	for _, ct := range yes {
		if !compressibleType(ct) {
			t.Fatalf("%q should be compressible", ct)
		}
	}
	for _, ct := range no {
		if compressibleType(ct) {
			t.Fatalf("%q should NOT be compressible", ct)
		}
	}
}

func TestCache_cacheableHeaders(t *testing.T) {
	if !cacheableHeaders([][2]string{{"X-A", "1"}, {"Cache-Control", "max-age=60"}}) {
		t.Fatal("max-age should be cacheable")
	}
	if cacheableHeaders([][2]string{{"Cache-Control", "no-store"}}) {
		t.Fatal("no-store not cacheable")
	}
	if cacheableHeaders([][2]string{{"set-cookie", "x=1"}}) {
		t.Fatal("set-cookie not cacheable")
	}
	if cacheableHeaders([][2]string{{"Content-Encoding", "gzip"}}) {
		t.Fatal("pre-encoded not cacheable")
	}
}

func TestCache_cloneBytes(t *testing.T) {
	src := []byte("hello")
	dst := cloneBytes(src)
	if string(dst) != "hello" {
		t.Fatal("clone mismatch")
	}
	src[0] = 'X'
	if dst[0] == 'X' {
		t.Fatal("clone aliased source")
	}
}
