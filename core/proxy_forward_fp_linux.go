//go:build linux && amd64

package core

import (
	"errors"
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
	out := make([][2]string, 0, len(req.Headers)+forwardingHeaderCount)
	nominated := connectionNominations(req.Headers)
	for _, h := range req.Headers {
		if isProxyFilteredHeaderFold(h[0]) || isHopByHopFold(h[0]) || nominated.nominates(h[0]) {
			continue
		}
		out = append(out, h)
	}
	return appendForwardingHeaderPairs(out, req)
}

func relayableResponseHeaders(headers [][2]string) [][2]string {
	out := make([][2]string, 0, len(headers))
	for _, h := range headers {
		if isHopByHopFold(h[0]) ||
			EqualFoldASCII(h[0], "content-length") ||
			EqualFoldASCII(h[0], "content-type") {
			continue
		}
		out = append(out, h)
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
	length := int64(-1)
	seen := false
	for _, h := range headers {
		switch len(h[0]) {
		case len("transfer-encoding"):
			if headerNameIs(h[0], "transfer-encoding") {
				return -1
			}
		case len("content-length"):
			if !seen && headerNameIs(h[0], "content-length") {
				seen = true
				length = fpParseContentLength(h[1])
			}
		}
	}
	return length
}

const fpOverflowFreeDigits = 18

func fpParseContentLength(value string) int64 {
	if len(value) == 0 || len(value) > fpOverflowFreeDigits {
		n, err := strconv.ParseUint(value, 10, 63)
		if err != nil {
			return -1
		}
		return int64(n)
	}
	var n int64
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int64(c-'0')
	}
	return n
}

func fpAttemptError(err error, wroteRequest, gotResponse bool) *proxyAttemptError {
	return &proxyAttemptError{
		err:          err,
		wroteRequest: wroteRequest,
		gotResponse:  gotResponse,
		timeout:      errors.Is(err, errFPTimeout),
	}
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
	cache := pe.activeCache()
	cacheGen := cache.purgeGeneration()

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
			respHeaders = relayableResponseHeaders(headers)
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
			if len(chunk) > client.cfg.MaxResponseBody-len(buffered) {
				return errFPBodyTooLarge
			}
			buffered = append(buffered, chunk...)
			return nil
		},
	}

	ex, err := client.exchange(&UpstreamRequest{
		Scheme:      fpProxyScheme(b),
		Authority:   fpProxyAuthority(b.Addr),
		Method:      req.Method,
		Path:        fpProxyPath(req),
		HostHeader:  fpProxyHostHeader(req, cfg),
		Headers:     fpProxyRequestHeaders(req),
		Body:        req.Body,
		SkipVerify:  b.TLSSkipVerify,
		trust:       b.trust,
		DialTimeout: cfg.ConnectTimeout,
		ReadTimeout: cfg.ReadTimeout,
	}, sink)
	if err != nil {
		wrote := ex != nil && ex.wroteRequest
		return fpAttemptError(err, wrote, status != 0)
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

	if autoCacheAllowed && cache != nil && proxyCacheResponseAllowed(respHeaders) {
		cache.put(req.Method, host, cachePath, status, respHeaders, contentType, buffered, cachePutOptions{generation: cacheGen})
	}
	return nil
}
