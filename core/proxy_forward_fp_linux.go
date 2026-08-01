//go:build linux

package core

import (
	"strconv"
	"strings"
	"sync"
)

const fpProxyBufferLimit = 65536

var (
	fpProxyOnce   sync.Once
	fpProxyClient *fpClient
	fpProxyErr    error
)

func proxyUpstreamClient() (*fpClient, error) {
	fpProxyOnce.Do(func() {
		fpProxyClient, fpProxyErr = fpNew(fpConfig{})
	})
	return fpProxyClient, fpProxyErr
}

func fpProxyScheme(b *backend) string {
	if b.TLS {
		return "https"
	}
	return "http"
}

func fpProxyAuthority(addr string) string {
	if i := strings.Index(addr, "://"); i >= 0 {
		addr = addr[i+3:]
	}
	return strings.TrimSuffix(addr, "/")
}

func fpProxyPath(req *Request) string {
	if req.Query == "" {
		return req.Path
	}
	return req.Path + "?" + req.Query
}

func fpProxyHostHeader(req *Request, cfg *DomainConfig) string {
	if cfg.HostHeader != "" {
		return cfg.HostHeader
	}
	if cfg.PreserveHost {
		return req.Host
	}
	return ""
}

func fpProxyRequestHeaders(req *Request) [][2]string {
	out := make([][2]string, 0, len(req.Headers)+1)
	for _, h := range req.Headers {
		if isProxyFilteredHeaderFold(h[0]) {
			continue
		}
		out = append(out, h)
	}
	if ip := extractIP(req.RemoteAddr); ip != "" {
		out = append(out, [2]string{"X-Forwarded-For", ip})
	}
	return out
}

func fpResponseContentType(headers [][2]string) string {
	for _, h := range headers {
		if EqualFoldASCII(h[0], "content-type") {
			return h[1]
		}
	}
	return ""
}

func fpResponseContentLength(headers [][2]string) int64 {
	for _, h := range headers {
		if EqualFoldASCII(h[0], "content-length") {
			var n int64
			for i := 0; i < len(h[1]); i++ {
				c := h[1][i]
				if c < '0' || c > '9' {
					return -1
				}
				n = n*10 + int64(c-'0')
			}
			return n
		}
	}
	return -1
}

// forwardRequestFP is the epoll backed replacement for forwardRequest. It
// keeps the same signature so the call site can switch between them.
func (pe *ProxyEngine) forwardRequestFP(req *Request, resp *Response, b *backend, cfg *DomainConfig) error {
	client, err := proxyUpstreamClient()
	if err != nil {
		return err
	}

	host := stripPort(req.Host)
	cachePath := fpProxyPath(req)
	cacheableMethod := req.Method == "GET" || req.Method == "HEAD"
	autoCacheAllowed := cacheableMethod && proxyCacheRequestAllowed(req)

	var (
		status      int
		respHeaders [][2]string
		contentType string
		buffered    []byte
		sw          StreamWriter
		streaming   bool
	)

	sink := &UpstreamStream{
		OnHeaders: func(code int, headers [][2]string) error {
			status = code
			respHeaders = make([][2]string, 0, len(headers))
			for _, h := range headers {
				if isHopByHopFold(h[0]) ||
					EqualFoldASCII(h[0], "content-length") ||
					EqualFoldASCII(h[0], "content-type") {
					continue
				}
				respHeaders = append(respHeaders, [2]string{h[0], h[1]})
			}
			contentType = fpResponseContentType(headers)
			length := fpResponseContentLength(headers)
			if length >= 0 && length <= fpProxyBufferLimit {
				return nil
			}
			w := req.StreamWriter
			if w == nil {
				w = resp.ensureSW()
			}
			if w == nil {
				return nil
			}
			if length >= 0 {
				respHeaders = append(respHeaders,
					[2]string{"Content-Length", strconv.FormatInt(length, 10)})
			}
			sw = w
			streaming = true
			return sw.WriteHeader(status, respHeaders, contentType)
		},
		OnBody: func(chunk []byte) error {
			if streaming {
				return sw.WriteChunk(chunk)
			}
			buffered = append(buffered, chunk...)
			return nil
		},
	}

	if _, err := client.DoStream(&UpstreamRequest{
		Scheme:     fpProxyScheme(b),
		Authority:  fpProxyAuthority(b.Addr),
		Method:     req.Method,
		Path:       fpProxyPath(req),
		HostHeader: fpProxyHostHeader(req, cfg),
		Headers:    fpProxyRequestHeaders(req),
		Body:       req.Body,
		SkipVerify: b.TLSSkipVerify,
	}, sink); err != nil {
		return err
	}

	if streaming {
		if err := sw.Flush(); err != nil {
			return err
		}
		return sw.Close()
	}

	resp.Status(status)
	if contentType != "" {
		resp.ContentType = contentType
	}
	for i := range respHeaders {
		resp.SetHeader(respHeaders[i][0], respHeaders[i][1])
	}
	if len(buffered) > 0 {
		copy(resp.prepareBody(len(buffered)), buffered)
	}

	if autoCacheAllowed && pe.Cache != nil && proxyCacheResponseAllowed(respHeaders) {
		pe.Cache.Put(req.Method, host, cachePath, status, respHeaders, contentType, buffered)
	}
	return nil
}
