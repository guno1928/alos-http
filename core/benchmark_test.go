package core

import (
	"testing"
)

func BenchmarkRouterLookup(b *testing.B) {
	r := NewRouter()
	r.Use(Recovery())
	r.GET("/", func(req *Request, resp *Response) {
		resp.Status(200).String("ok")
	})
	r.GET("/json", func(req *Request, resp *Response) {
		resp.Status(200).JSONString(`{"ok":true}`)
	})
	r.GET("/users/:id", func(req *Request, resp *Response) {
		resp.Status(200).String(req.ParamValue("id"))
	})
	r.GET("/api/status", func(req *Request, resp *Response) {
		resp.Status(200).JSONString(`{"api":"v1"}`)
	})
	r.Build()

	req := &Request{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.Lookup("GET", "/", req)
	}
}

func BenchmarkRouterLookupParam(b *testing.B) {
	r := NewRouter()
	r.Use(Recovery())
	r.GET("/users/:id", func(req *Request, resp *Response) {
		resp.Status(200).String(req.ParamValue("id"))
	})
	r.Build()

	req := &Request{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.Lookup("GET", "/users/42", req)
	}
}

func BenchmarkRouterLookupBuiltVsUnbuilt(b *testing.B) {
	setup := func() *Router {
		r := NewRouter()
		r.Use(Recovery())
		r.GET("/", func(req *Request, resp *Response) {
			resp.Status(200).String("ok")
		})
		return r
	}

	b.Run("Unbuilt", func(b *testing.B) {
		r := setup()
		req := &Request{}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = r.Lookup("GET", "/", req)
		}
	})

	b.Run("Built", func(b *testing.B) {
		r := setup()
		r.Build()
		req := &Request{}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = r.Lookup("GET", "/", req)
		}
	})
}

func BenchmarkParseH1Request(b *testing.B) {
	raw := []byte("GET /json HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n")
	req := &Request{
		Headers: make([][2]string, 0, 16),
		Body:    make([]byte, 0, 1024),
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Reset()
		ParseH1Request(raw, req)
	}
}

func BenchmarkParseH1RequestWithBody(b *testing.B) {
	raw := []byte("POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\nHello, World!")
	req := &Request{
		Headers: make([][2]string, 0, 16),
		Body:    make([]byte, 0, 1024),
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Reset()
		ParseH1Request(raw, req)
	}
}

func BenchmarkBuildH1Response(b *testing.B) {
	b.Run("SmallText", func(b *testing.B) {
		resp := &Response{
			Headers: make([][2]string, 0, 8),
			body:    make([]byte, 0, 4096),
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resp.Reset()
			resp.Status(200).String("Hello from ALOS!")
			data, bp := BuildH1Response(resp)
			_ = data
			*bp = (*bp)[:0]
			LargeBufPool.Put(bp)
		}
	})

	b.Run("JSONPayload", func(b *testing.B) {
		resp := &Response{
			Headers: make([][2]string, 0, 8),
			body:    make([]byte, 0, 4096),
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resp.Reset()
			resp.Status(200).JSONString(`{"server":"ALOS","protocol":"HTTP/1.1","method":"GET","path":"/json"}`)
			data, bp := BuildH1Response(resp)
			_ = data
			*bp = (*bp)[:0]
			LargeBufPool.Put(bp)
		}
	})
}

func BenchmarkHeaderLookup(b *testing.B) {
	req := &Request{
		Headers: [][2]string{
			{"Host", "localhost"},
			{"Connection", "keep-alive"},
			{"Accept", "*/*"},
			{"User-Agent", "wrk"},
			{"Content-Type", "application/json"},
			{"Content-Length", "42"},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = req.Header("Content-Length")
	}
}

func BenchmarkEqualFoldASCII(b *testing.B) {
	b.Run("Match", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = EqualFoldASCII("Content-Length", "content-length")
		}
	})
	b.Run("NoMatch", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = EqualFoldASCII("Content-Length", "Connection")
		}
	})
	b.Run("SameCase", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = EqualFoldASCII("connection", "connection")
		}
	})
}

func BenchmarkToLowerASCII(b *testing.B) {
	b.Run("NeedsLower", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = ToLowerASCII("Content-Length")
		}
	})
	b.Run("AlreadyLower", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = ToLowerASCII("content-length")
		}
	})
}

func BenchmarkJSON(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j := AcquireJSON()
		_ = j.Marshal(map[string]any{
			"server":     "ALOS",
			"protocol":   "HTTP/1.1",
			"method":     "GET",
			"path":       "/json",
			"h2_conns":   uint64(0),
			"h1_conns":   uint64(1),
			"total_reqs": uint64(100),
		})
		j.Release()
	}
}

func BenchmarkRequestPoolGetPut(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := RequestPool.Get().(*Request)
		req.Reset()
		RequestPool.Put(req)
	}
}

func BenchmarkResponsePoolGetPut(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := ResponsePool.Get().(*Response)
		resp.Reset()
		ResponsePool.Put(resp)
	}
}

func BenchmarkFullH1CycleNoIO(b *testing.B) {
	r := NewRouter()
	r.Use(Recovery())
	r.GET("/", func(req *Request, resp *Response) {
		resp.Status(200).String("Hello from ALOS custom TLS 1.3 server!\n")
	})
	r.GET("/json", func(req *Request, resp *Response) {
		j := AcquireJSON()
		resp.Status(200).JSON(j.Marshal(map[string]any{
			"server":   "ALOS",
			"protocol": "HTTP/1.1",
			"method":   "GET",
			"path":     "/json",
		}))
		j.Release()
	})
	r.GET("/health", func(req *Request, resp *Response) {
		resp.Status(200).JSONString(`{"status":"ok"}`)
	})
	r.Build()

	rawGet := []byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
	rawJSON := []byte("GET /json HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n")
	rawHealth := []byte("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")

	b.Run("GET_Root", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := RequestPool.Get().(*Request)
			req.Reset()
			req.Proto = "HTTP/1.1"
			ParseH1Request(rawGet, req)

			resp := ResponsePool.Get().(*Response)
			resp.Reset()

			handler := r.Lookup(req.Method, req.Path, req)
			handler(req, resp)

			data, bp := BuildH1Response(resp)
			_ = data
			*bp = (*bp)[:0]
			LargeBufPool.Put(bp)

			RequestPool.Put(req)
			ResponsePool.Put(resp)
		}
	})

	b.Run("GET_JSON", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := RequestPool.Get().(*Request)
			req.Reset()
			req.Proto = "HTTP/1.1"
			ParseH1Request(rawJSON, req)

			resp := ResponsePool.Get().(*Response)
			resp.Reset()

			handler := r.Lookup(req.Method, req.Path, req)
			handler(req, resp)

			data, bp := BuildH1Response(resp)
			_ = data
			*bp = (*bp)[:0]
			LargeBufPool.Put(bp)

			RequestPool.Put(req)
			ResponsePool.Put(resp)
		}
	})

	b.Run("GET_Health", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := RequestPool.Get().(*Request)
			req.Reset()
			req.Proto = "HTTP/1.1"
			ParseH1Request(rawHealth, req)

			resp := ResponsePool.Get().(*Response)
			resp.Reset()

			handler := r.Lookup(req.Method, req.Path, req)
			handler(req, resp)

			data, bp := BuildH1Response(resp)
			_ = data
			*bp = (*bp)[:0]
			LargeBufPool.Put(bp)

			RequestPool.Put(req)
			ResponsePool.Put(resp)
		}
	})
}

func BenchmarkMethodIndex(b *testing.B) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = methodIndex(methods[i%len(methods)])
	}
}

func BenchmarkFindRequestEnd(b *testing.B) {
	data := []byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = findRequestEnd(data)
	}
}

func BenchmarkStatusText(b *testing.B) {
	codes := []int{200, 404, 500, 301, 204}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = StatusText(codes[i%len(codes)])
	}
}
