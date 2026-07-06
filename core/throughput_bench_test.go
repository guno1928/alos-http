//go:build linux && amd64

package core

import (
	"strconv"
	"strings"
	"testing"
)

var (
	benchBuf     = make([]byte, 0, 256<<10)
	benchSink    []byte
	benchSinkInt int
	benchH       HandlerFunc
)

func benchResp(body string) *Response {
	r := &Response{}
	r.HTML(body)
	return r
}

func benchRouter() *Router {
	r := NewRouter()
	h := func(req *Request, resp *Response) {}
	for _, p := range []string{
		"/", "/login", "/docs", "/sitemap", "/favicon.ico", "/dashboard",
		"/dashboard/shop", "/dashboard/settings", "/shop", "/api/login",
		"/api/products/buy", "/api/wallet/transfer", "/api/shop/public/products",
		"/aloscaptcha.js", "/api/aloscaptcha/challenge",
	} {
		r.GET(p, h)
	}
	r.Build()
	return r
}

// ===== A. serialization: old full-copy vs split-send, by body size =====
func BenchmarkSerializeFullVsSplit(b *testing.B) {
	for _, sz := range []int{0, 64, 256, 1024, 4096, 16384, 65536, 131072} {
		r := benchResp(strings.Repeat("x", sz))
		b.Run("fullcopy-"+strconv.Itoa(sz), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchSink = appendPlainResponse(r, benchBuf[:0])
			}
		})
		b.Run("split-"+strconv.Itoa(sz), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchSink = appendPlainResponseHeaders(r, benchBuf[:0])
				_ = r.transmittedBodyBytes()
			}
		})
	}
}

// ===== B. header-only serialization (the split-send hot path) =====
func BenchmarkHeaderSerialize(b *testing.B) {
	for _, sz := range []int{100, 4096, 65536, 131072} {
		r := benchResp(strings.Repeat("h", sz))
		b.Run(strconv.Itoa(sz), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchSink = appendPlainResponseHeaders(r, benchBuf[:0])
			}
		})
	}
}

// ===== C. response builders =====
func BenchmarkResponseBuilders(b *testing.B) {
	body := strings.Repeat("y", 4096)
	bb := []byte(body)
	cases := []struct {
		name string
		fn   func(*Response)
	}{
		{"String", func(r *Response) { r.String(body) }},
		{"HTML", func(r *Response) { r.HTML(body) }},
		{"JSONString", func(r *Response) { r.JSONString(body) }},
		{"Bytes", func(r *Response) { r.Bytes(bb) }},
		{"JSON", func(r *Response) { r.JSON(bb) }},
	}
	for _, c := range cases {
		r := &Response{}
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.fn(r)
			}
		})
	}
}

// ===== D. buffer pools =====
func BenchmarkPools(b *testing.B) {
	b.Run("read-acquire-release", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := acquirePooledBuf(&connReadBufPool)
			releasePooledBuf(&connReadBufPool, buf, connBufPoolMaxCap)
		}
	})
	b.Run("write-acquire-release", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := acquirePooledBuf(&connWriteBufPool)
			releasePooledBuf(&connWriteBufPool, buf, connBufPoolMaxCap)
		}
	})
	b.Run("body-acquire-release", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := acquirePooledBuf(&connBodyBufPool)
			releasePooledBuf(&connBodyBufPool, buf, connBufPoolMaxCap)
		}
	})
	b.Run("read-parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf := acquirePooledBuf(&connReadBufPool)
				releasePooledBuf(&connReadBufPool, buf, connBufPoolMaxCap)
			}
		})
	})
	b.Run("write-parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf := acquirePooledBuf(&connWriteBufPool)
				releasePooledBuf(&connWriteBufPool, buf, connBufPoolMaxCap)
			}
		})
	})
	b.Run("oversized-drop", func(b *testing.B) {
		b.ReportAllocs()
		big := make([]byte, 0, connBufPoolMaxCap+1)
		for i := 0; i < b.N; i++ {
			releasePooledBuf(&connWriteBufPool, big, connBufPoolMaxCap)
		}
	})
}

// ===== E. request head parsing =====
func BenchmarkParseRequest(b *testing.B) {
	reqs := map[string]string{
		"simple-get":  "GET / HTTP/1.1\r\nHost: alos.gg\r\n\r\n",
		"typical-get": "GET /dashboard HTTP/1.1\r\nHost: alos.gg\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nAccept-Encoding: gzip\r\nCookie: session=abcdef123456\r\nConnection: keep-alive\r\n\r\n",
		"post-cl":     "POST /api/login HTTP/1.1\r\nHost: alos.gg\r\nContent-Length: 27\r\nContent-Type: application/json\r\n\r\n",
		"many-headers": "GET /shop HTTP/1.1\r\nHost: alos.gg\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\nE: 5\r\nF: 6\r\nG: 7\r\nH: 8\r\nX-Forwarded-For: 1.2.3.4\r\nX-Real-IP: 1.2.3.4\r\n\r\n",
		"keepalive":   "GET /api/wallet/transfer HTTP/1.1\r\nHost: alos.gg\r\nConnection: keep-alive\r\nAuthorization: Bearer xyz\r\n\r\n",
	}
	req := &Request{Headers: make([][2]string, 0, 16)}
	for name, s := range reqs {
		data := []byte(s)
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				req.resetFastH1()
				ParseH1RequestHead(data, req)
			}
		})
	}
}

// ===== F. router lookup =====
func BenchmarkRouterLookup(b *testing.B) {
	router := benchRouter()
	req := &Request{Headers: make([][2]string, 0, 16)}
	for _, p := range []string{"/", "/dashboard", "/dashboard/shop", "/api/products/buy", "/aloscaptcha.js", "/nonexistent/path"} {
		p := p
		b.Run(p, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchH = router.Lookup("GET", p, req)
			}
		})
	}
}

// ===== G. full per-request pipeline (parse -> lookup -> build -> serialize) =====
func BenchmarkFullPipeline(b *testing.B) {
	router := benchRouter()
	req := &Request{Headers: make([][2]string, 0, 16)}
	resp := &Response{}
	for _, tc := range []struct {
		name, raw, body string
	}{
		{"small-html", "GET /dashboard HTTP/1.1\r\nHost: alos.gg\r\nCookie: s=1\r\n\r\n", "<h1>ok</h1>"},
		{"page-20k", "GET / HTTP/1.1\r\nHost: alos.gg\r\n\r\n", strings.Repeat("p", 20<<10)},
		{"page-130k", "GET / HTTP/1.1\r\nHost: alos.gg\r\n\r\n", strings.Repeat("p", 130<<10)},
	} {
		data := []byte(tc.raw)
		body := tc.body
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				req.resetFastH1()
				ParseH1RequestHead(data, req)
				benchH = router.Lookup("GET", req.Path, req)
				resp.resetFastH1()
				resp.HTML(body)
				if resp.transmittedBodyLen() <= splitSendMinBody {
					benchSink = appendPlainResponse(resp, benchBuf[:0])
				} else {
					benchSink = appendPlainResponseHeaders(resp, benchBuf[:0])
					_ = resp.transmittedBodyBytes()
				}
			}
		})
	}
}

// ===== H. parallel throughput (multi-core req/s proxy) =====
func BenchmarkParallelThroughput(b *testing.B) {
	router := benchRouter()
	data := []byte("GET /dashboard HTTP/1.1\r\nHost: alos.gg\r\nCookie: s=1\r\n\r\n")
	body := strings.Repeat("p", 20<<10)
	b.Run("full-pipeline-split", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			req := &Request{Headers: make([][2]string, 0, 16)}
			resp := &Response{}
			buf := make([]byte, 0, 8192)
			for pb.Next() {
				req.resetFastH1()
				ParseH1RequestHead(data, req)
				_ = router.Lookup("GET", req.Path, req)
				resp.resetFastH1()
				resp.HTML(body)
				_ = appendPlainResponseHeaders(resp, buf[:0])
				_ = resp.transmittedBodyBytes()
			}
		})
	})
	b.Run("serialize-only", func(b *testing.B) {
		r := benchResp(strings.Repeat("x", 4096))
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			buf := make([]byte, 0, 8192)
			for pb.Next() {
				_ = appendPlainResponse(r, buf[:0])
			}
		})
	})
	b.Run("pool-cycle", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf := acquirePooledBuf(&connWriteBufPool)
				releasePooledBuf(&connWriteBufPool, buf, connBufPoolMaxCap)
			}
		})
	})
}

// ===== I. extra hot-path coverage (to complete the battery) =====
func BenchmarkExtra(b *testing.B) {
	body := strings.Repeat("z", 8192)
	textResp := &Response{}
	textResp.HTML(body)
	byteResp := &Response{}
	byteResp.Bytes([]byte(body))

	b.Run("transmittedBody-text", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchSink = textResp.transmittedBodyBytes()
		}
	})
	b.Run("transmittedBody-bytes", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchSink = byteResp.transmittedBodyBytes()
		}
	})
	b.Run("transmittedBodyLen", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchSinkInt = textResp.transmittedBodyLen()
		}
	})
	b.Run("resetFastH1-request", func(b *testing.B) {
		req := &Request{Headers: make([][2]string, 0, 16)}
		ParseH1RequestHead([]byte("GET /x HTTP/1.1\r\nHost: a\r\nCookie: s=1\r\n\r\n"), req)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req.resetFastH1()
		}
	})
	b.Run("resetFastH1-response", func(b *testing.B) {
		r := &Response{}
		r.HTML(body)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			r.resetFastH1()
		}
	})
	b.Run("response-Reset", func(b *testing.B) {
		r := &Response{}
		r.HTML(body)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			r.Reset()
		}
	})
	b.Run("SetHeader", func(b *testing.B) {
		r := &Response{}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			r.Headers = r.Headers[:0]
			r.SetHeader("Cache-Control", "no-store")
		}
	})
	b.Run("serialize-keepalive", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchSink = appendPlainResponseMode(textResp, benchBuf[:0], true, false)
		}
	})
	b.Run("serialize-close", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchSink = appendPlainResponseMode(textResp, benchBuf[:0], false, false)
		}
	})
	b.Run("serialize-HEAD-suppress", func(b *testing.B) {
		r := &Response{}
		r.HTML(body)
		r.lazyReq = &Request{Method: "HEAD"}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			benchSink = appendPlainResponseHeaders(r, benchBuf[:0])
			_ = r.transmittedBodyBytes()
		}
	})
	b.Run("parse-parallel", func(b *testing.B) {
		data := []byte("GET /dashboard HTTP/1.1\r\nHost: a\r\nCookie: s=1\r\n\r\n")
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			req := &Request{Headers: make([][2]string, 0, 16)}
			for pb.Next() {
				req.resetFastH1()
				ParseH1RequestHead(data, req)
			}
		})
	})
	b.Run("router-lookup-parallel", func(b *testing.B) {
		router := benchRouter()
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			req := &Request{Headers: make([][2]string, 0, 16)}
			for pb.Next() {
				benchH = router.Lookup("GET", "/dashboard/shop", req)
			}
		})
	})
}
