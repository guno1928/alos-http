//go:build linux && amd64

package core

import "testing"

var gateRootFastRequests = []struct {
	name string
	raw  []byte
}{
	{"wrk", []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1:18443\r\n\r\n")},
	{"curl", []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n")},
	{"browser", []byte("GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\nsec-ch-ua: \"Chromium\";v=\"128\", \"Not;A=Brand\";v=\"24\"\r\nsec-ch-ua-mobile: ?0\r\nsec-ch-ua-platform: \"Windows\"\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nSec-Fetch-Site: none\r\nSec-Fetch-Mode: navigate\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: en-US,en;q=0.9\r\n\r\n")},
}

func BenchmarkGatePlainRootFast(b *testing.B) {
	for _, req := range gateRootFastRequests {
		b.Run(req.name, func(b *testing.B) {
			b.SetBytes(int64(len(req.raw)))
			for b.Loop() {
				if _, _, ok, _ := parsePlainFastRootRequest(req.raw, len(rootPrefixBytes), 8192, defaultMaxHeaderCount); !ok {
					b.Fatal("fast path refused the request")
				}
			}
		})
	}
}
