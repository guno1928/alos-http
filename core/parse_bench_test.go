package core

import (
	"testing"
)

var benchReqTypical = []byte("GET /api/v1/users/12345?filter=active&sort=name HTTP/1.1\r\n" +
	"Host: api.example.com\r\n" +
	"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n" +
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
	"Accept-Language: en-US,en;q=0.5\r\n" +
	"Accept-Encoding: gzip, deflate, br\r\n" +
	"Connection: keep-alive\r\n" +
	"Cookie: session=abc123def456; theme=dark; lang=en\r\n" +
	"Cache-Control: no-cache\r\n" +
	"\r\n")

var benchReqPost = []byte("POST /api/v1/orders HTTP/1.1\r\n" +
	"Host: api.example.com\r\n" +
	"Content-Type: application/json\r\n" +
	"Content-Length: 27\r\n" +
	"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\r\n" +
	"Connection: keep-alive\r\n" +
	"\r\n" +
	`{"item":"widget","qty":3}`)

func BenchmarkParseH1RequestHead_Typical(b *testing.B) {
	var req Request
	req.Headers = make([][2]string, 0, 16)
	b.ReportAllocs()
	b.SetBytes(int64(len(benchReqTypical)))
	for i := 0; i < b.N; i++ {
		req.Headers = req.Headers[:0]
		ParseH1RequestHead(benchReqTypical, &req, 8192, 128)
	}
}

func BenchmarkParseH1RequestHead_Post(b *testing.B) {
	var req Request
	req.Headers = make([][2]string, 0, 16)
	b.ReportAllocs()
	b.SetBytes(int64(len(benchReqPost)))
	for i := 0; i < b.N; i++ {
		req.Headers = req.Headers[:0]
		ParseH1RequestHead(benchReqPost, &req, 8192, 128)
	}
}

