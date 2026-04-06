package core

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestProxyManualCacheCachesChunkedResponse(t *testing.T) {
	var backendHits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("chunk-"))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = w.Write([]byte("body"))
	}))
	defer backend.Close()

	s := New(Config{})
	s.AddProxyDomain(DomainConfig{
		Domain:   "proxy.local",
		Backends: []BackendConfig{{Addr: backend.URL}},
	})
	s.OnProxyResponse(func(pr *ProxyResponse) {
		if pr.Backend != "cache" {
			pr.CacheThis(time.Minute, 0)
		}
	})
	s.Router.Build()

	resp1 := dispatchProxyRequest(t, s, nil)
	if got := string(resp1.GetBody()); got != "chunk-body" {
		t.Fatalf("expected first response body %q, got %q", "chunk-body", got)
	}
	if got := backendHits.Load(); got != 1 {
		t.Fatalf("expected 1 backend hit after first request, got %d", got)
	}

	resp2 := dispatchProxyRequest(t, s, nil)
	if got := string(resp2.GetBody()); got != "chunk-body" {
		t.Fatalf("expected cached response body %q, got %q", "chunk-body", got)
	}
	if got := backendHits.Load(); got != 1 {
		t.Fatalf("expected cache hit on second request, backend hits=%d", got)
	}
	if got := responseHeaderValue(resp2, "x-cache"); got != "HIT" {
		t.Fatalf("expected x-cache HIT on second request, got %q", got)
	}
}

func TestProxyManualCacheOverridesBrowserBypassHeaders(t *testing.T) {
	var backendHits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	s := New(Config{})
	s.AddProxyDomain(DomainConfig{
		Domain:   "proxy.local",
		Backends: []BackendConfig{{Addr: backend.URL}},
	})
	s.OnProxyResponse(func(pr *ProxyResponse) {
		if pr.Backend != "cache" {
			pr.CacheThis(time.Minute, 0)
		}
	})
	s.Router.Build()

	headers := [][2]string{
		{"Cache-Control", "max-age=0"},
		{"Pragma", "no-cache"},
		{"Cookie", "session=abc"},
	}

	resp1 := dispatchProxyRequest(t, s, headers)
	if got := string(resp1.GetBody()); got != "ok" {
		t.Fatalf("expected first response body %q, got %q", "ok", got)
	}
	if got := backendHits.Load(); got != 1 {
		t.Fatalf("expected 1 backend hit after first request, got %d", got)
	}

	resp2 := dispatchProxyRequest(t, s, headers)
	if got := string(resp2.GetBody()); got != "ok" {
		t.Fatalf("expected cached response body %q, got %q", "ok", got)
	}
	if got := backendHits.Load(); got != 1 {
		t.Fatalf("expected cache hit on second request, backend hits=%d", got)
	}
	if got := responseHeaderValue(resp2, "x-cache"); got != "HIT" {
		t.Fatalf("expected x-cache HIT on second request, got %q", got)
	}
}

func dispatchProxyRequest(t *testing.T, s *Server, headers [][2]string) *Response {
	t.Helper()
	resp := &Response{}
	resp.Reset()
	s.dispatch(&Request{
		Method:     "GET",
		Path:       "/",
		Host:       "proxy.local",
		RemoteAddr: "127.0.0.1:1234",
		Headers:    append([][2]string(nil), headers...),
	}, resp)
	return resp
}

func responseHeaderValue(resp *Response, name string) string {
	for i := range resp.Headers {
		if EqualFoldASCII(resp.Headers[i][0], name) {
			return resp.Headers[i][1]
		}
	}
	return ""
}
