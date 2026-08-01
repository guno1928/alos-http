//go:build linux && amd64

package core

import (
	"net"
	"strconv"
)

// appendProxyRequest serialises the upstream request for a proxied exchange.
// It is the single place where client-controlled bytes are filtered before
// they reach a backend, so every header name and value is checked for CRLF and
// the hop-by-hop and forwarding headers are rewritten rather than relayed.
func appendProxyRequest(dst []byte, req *Request, hostHeader, clientIP string) []byte {
	dst = append(dst, req.Method...)
	dst = append(dst, ' ')
	dst = append(dst, proxyRequestTarget(req)...)
	dst = append(dst, " HTTP/1.1\r\n"...)

	dst = append(dst, "Host: "...)
	if containsCRLF(hostHeader) {
		hostHeader = ""
	}
	dst = append(dst, hostHeader...)
	dst = append(dst, "\r\n"...)

	for _, h := range req.Headers {
		if isProxyFilteredHeaderFold(h[0]) || isHopByHopFold(h[0]) {
			continue
		}
		// A client must not be able to dictate what the backend believes about
		// the connection, the encoding or the original caller.
		if headerNameIs(h[0], "host") ||
			headerNameIs(h[0], "content-length") ||
			headerNameIs(h[0], "accept-encoding") ||
			fpIsClientForwardedHeader([]byte(h[0])) {
			continue
		}
		if containsCRLF(h[0]) || containsCRLF(h[1]) {
			continue
		}
		dst = append(dst, h[0]...)
		dst = append(dst, ": "...)
		dst = append(dst, h[1]...)
		dst = append(dst, "\r\n"...)
	}

	if clientIP != "" && !containsCRLF(clientIP) {
		dst = append(dst, "X-Forwarded-For: "...)
		dst = append(dst, clientIP...)
		dst = append(dst, "\r\n"...)
	}
	// Responses are relayed byte for byte, so the backend must not compress
	// beyond what this proxy is prepared to forward.
	dst = append(dst, "Accept-Encoding: identity\r\n"...)
	// Connection and Upgrade are hop-by-hop and were filtered above. An upgrade
	// has to be re-stated for this hop or the backend never answers 101 and the
	// tunnel is never established.
	if token := upgradeToken(req); token != "" {
		dst = append(dst, "Connection: Upgrade\r\nUpgrade: "...)
		dst = append(dst, token...)
		dst = append(dst, "\r\n"...)
	} else {
		// The client's own connection choice is never the backend's business:
		// relaying "close" would retire a pooled upstream connection per request.
		dst = append(dst, "Connection: keep-alive\r\n"...)
	}

	if len(req.Body) > 0 || req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH" {
		dst = append(dst, "Content-Length: "...)
		dst = strconv.AppendInt(dst, int64(len(req.Body)), 10)
		dst = append(dst, "\r\n"...)
	}
	dst = append(dst, "\r\n"...)
	return append(dst, req.Body...)
}

// proxyRequestTarget prefers the untouched request target so escaped path
// segments survive the hop, falling back to the parsed path and query.
func proxyRequestTarget(req *Request) string {
	target := req.RawPath
	if target == "" {
		target = req.Path
		if req.Query != "" {
			target = req.Path + "?" + req.Query
		}
	}
	if target == "" || containsCRLF(target) {
		return "/"
	}
	return target
}

// resolveAuthority splits a backend authority into an IPv4 address and port.
func resolveAuthority(authority string) ([4]byte, uint16, error) {
	var ip [4]byte
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		host = authority
		portStr = "80"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return ip, 0, fpErrDialFailed
	}
	ip, err = fpResolveIPv4(host)
	if err != nil {
		return ip, 0, err
	}
	return ip, uint16(port), nil
}

// upgradeToken returns the protocol a client asked to switch to, or "" when it
// did not ask. A request carrying one becomes a byte tunnel once the backend
// agrees with 101.
func upgradeToken(req *Request) string {
	for _, h := range req.Headers {
		if headerNameIs(h[0], "upgrade") && h[1] != "" && !containsCRLF(h[1]) {
			return h[1]
		}
	}
	return ""
}

// headerNameIs compares a header name against a lowercase literal without
// allocating, which strings.EqualFold would not guarantee.
func headerNameIs(name, lower string) bool {
	if len(name) != len(lower) {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}
