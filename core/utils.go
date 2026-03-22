package core

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

type dnsCacheEntry struct {
	ips     []net.IP
	expires int64
	idx     atomic.Uint32
}

var (
	dnsCache    sync.Map
	dnsTTL      = int64(60)
	dnsResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", address)
		},
	}
)

func resolveIPv4(ctx context.Context, host string) (net.IP, error) {
	now := time.Now().Unix()
	if v, ok := dnsCache.Load(host); ok {
		entry := v.(*dnsCacheEntry)
		if now < atomic.LoadInt64(&entry.expires) {
			ips := entry.ips
			idx := entry.idx.Add(1)
			return ips[int(idx)%len(ips)], nil
		}
	}

	ips, err := dnsResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return nil, err
	}

	entry := &dnsCacheEntry{ips: ips}
	atomic.StoreInt64(&entry.expires, now+dnsTTL)
	dnsCache.Store(host, entry)

	return ips[0], nil
}

func DialTCP4(addr string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	if net.ParseIP(host) != nil {
		return dialTCP4Direct(addr, timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ip, err := resolveIPv4(ctx, host)
	if err != nil {
		return nil, err
	}

	resolved := net.JoinHostPort(ip.String(), port)
	return dialTCP4Direct(resolved, timeout)
}

func dialTCP4Direct(addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp4", addr, timeout)
	if err != nil {
		return nil, err
	}
	prepareAcceptedConn(conn)
	wrapped, err := wrapConnectedConnWithIOUring(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return wrapped, nil
}

var asciiLower [256]byte

var digitVal [256]byte

func init() {
	for i := 0; i < 256; i++ {
		asciiLower[i] = byte(i)
		digitVal[i] = 0xFF
	}
	for c := byte('A'); c <= 'Z'; c++ {
		asciiLower[c] = c + 0x20
	}
	for c := byte('0'); c <= '9'; c++ {
		digitVal[c] = c - '0'
	}
}

var commonLowerHeaders map[string]string

func init() {
	commonLowerHeaders = map[string]string{
		"Content-Type":                "content-type",
		"Content-Length":              "content-length",
		"Content-Encoding":            "content-encoding",
		"Content-Disposition":         "content-disposition",
		"Cache-Control":               "cache-control",
		"Set-Cookie":                  "set-cookie",
		"Accept":                      "accept",
		"Accept-Encoding":             "accept-encoding",
		"Accept-Language":             "accept-language",
		"Authorization":               "authorization",
		"Connection":                  "connection",
		"Host":                        "host",
		"Location":                    "location",
		"Server":                      "server",
		"Date":                        "date",
		"ETag":                        "etag",
		"Vary":                        "vary",
		"X-Content-Type-Options":      "x-content-type-options",
		"X-Frame-Options":             "x-frame-options",
		"Access-Control-Allow-Origin": "access-control-allow-origin",
		"Strict-Transport-Security":   "strict-transport-security",
		"Transfer-Encoding":           "transfer-encoding",
		"User-Agent":                  "user-agent",
		"Referer":                     "referer",
		"Cookie":                      "cookie",
		"Upgrade":                     "upgrade",
		"Origin":                      "origin",
		"Sec-WebSocket-Key":           "sec-websocket-key",
		"Sec-WebSocket-Version":       "sec-websocket-version",
	}
}

func commonLowerHeader(s string) (string, bool) {
	if low, ok := commonLowerHeaders[s]; ok {
		return low, true
	}
	return "", false
}

func ToLowerASCII(s string) string {
	if low, ok := commonLowerHeaders[s]; ok {
		return low
	}
	hasUpper := false
	for i := 0; i < len(s); i++ {
		if asciiLower[s[i]] != s[i] {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	var stackBuf [128]byte
	var b []byte
	if len(s) <= len(stackBuf) {
		b = stackBuf[:len(s)]
	} else {
		b = make([]byte, len(s))
	}
	for i := 0; i < len(s); i++ {
		b[i] = asciiLower[s[i]]
	}
	if len(s) <= len(stackBuf) {
		return string(b)
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func EqualFoldASCII(a, b string) bool {
	if a == b {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if asciiLower[a[i]] != asciiLower[b[i]] {
			return false
		}
	}
	return true
}

func UnsafeString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func UnsafeBytes(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func parseUint(s string) (int, bool) {
	if len(s) == 0 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		d := digitVal[s[i]]
		if d == 0xFF {
			return 0, false
		}
		n = n*10 + int(d)
		if n < 0 {
			return 0, false
		}
	}
	return n, true
}

func parseHex64(s string) (int64, bool) {
	if len(s) == 0 {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		var d int64
		switch {
		case c >= '0' && c <= '9':
			d = int64(c - '0')
		case c >= 'a' && c <= 'f':
			d = int64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int64(c-'A') + 10
		default:
			return 0, false
		}
		n = n<<4 | d
		if n < 0 {
			return 0, false
		}
	}
	return n, true
}

func parseHex64Bytes(b []byte) (int64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	var n int64
	for _, c := range b {
		var d int64
		switch {
		case c >= '0' && c <= '9':
			d = int64(c - '0')
		case c >= 'a' && c <= 'f':
			d = int64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int64(c-'A') + 10
		default:
			return 0, false
		}
		n = n<<4 | d
		if n < 0 {
			return 0, false
		}
	}
	return n, true
}

func trimASCIISpaceBytes(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\t' || b[start] == '\r' || b[start] == '\n') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\r' || b[end-1] == '\n') {
		end--
	}
	return b[start:end]
}

func indexByteSlice(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

func trimASCIISpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r' || s[end-1] == '\n') {
		end--
	}
	return s[start:end]
}

func trimRight(s string, cutset byte) string {
	end := len(s)
	for end > 0 && (s[end-1] == cutset || s[end-1] == '\r' || s[end-1] == '\n') {
		end--
	}
	return s[:end]
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func indexCRLF(s string) int {
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '\r' && s[i+1] == '\n' {
			return i
		}
	}
	return -1
}

func appendUint(dst []byte, n int64) []byte {
	var buf [20]byte
	i := len(buf)
	if n == 0 {
		return append(dst, '0')
	}
	for n > 0 {
		i--
		buf[i] = byte(n%10) + '0'
		n /= 10
	}
	return append(dst, buf[i:]...)
}

func appendHex(dst []byte, n int64) []byte {
	var buf [16]byte
	i := len(buf)
	if n == 0 {
		return append(dst, '0')
	}
	for n > 0 {
		i--
		d := byte(n & 0xf)
		if d < 10 {
			buf[i] = d + '0'
		} else {
			buf[i] = d - 10 + 'a'
		}
		n >>= 4
	}
	return append(dst, buf[i:]...)
}

func isValidIP(s string) bool {
	dotCount := 0
	partLen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if partLen == 0 || partLen > 3 {
				return false
			}
			dotCount++
			partLen = 0
		} else if c >= '0' && c <= '9' {
			partLen++
		} else if c == ':' {
			return isValidIPv6(s)
		} else {
			return false
		}
	}
	return dotCount == 3 && partLen > 0 && partLen <= 3
}

func isValidIPv6(s string) bool {
	colonCount := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ':' {
			colonCount++
		} else if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.' {
			continue
		} else {
			return false
		}
	}
	return colonCount >= 2
}

func StatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 204:
		return "No Content"
	case 206:
		return "Partial Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 408:
		return "Request Timeout"
	case 413:
		return "Payload Too Large"
	case 416:
		return "Range Not Satisfiable"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return "Unknown"
	}
}

func HexDigit(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'a' + b - 10
}

func AppendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	last := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		dst = append(dst, s[last:i]...)
		switch c {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			dst = append(dst, '\\', 'u', '0', '0')
			dst = append(dst, HexDigit(c>>4), HexDigit(c&0xf))
		}
		last = i + 1
	}
	dst = append(dst, s[last:]...)
	dst = append(dst, '"')
	return dst
}

func sanitizeRequestPath(path string) string {
	for i := 0; i < len(path); i++ {
		if path[i] == 0 || path[i] == '\r' || path[i] == '\n' {
			path = path[:i]
			break
		}
	}
	if len(path) == 0 {
		return "/"
	}

	queryIdx := -1
	needsSanitize := path[0] != '/'
	for i := 0; i < len(path) && !needsSanitize; i++ {
		c := path[i]
		if c == '?' {
			queryIdx = i
			break
		}
		if c == '/' && i+1 < len(path) {
			next := path[i+1]
			if next == '/' || next == '.' {
				needsSanitize = true
			}
		}
	}
	if !needsSanitize {
		return path
	}

	var query string
	p := path
	if queryIdx < 0 {
		for i := 0; i < len(path); i++ {
			if path[i] == '?' {
				queryIdx = i
				break
			}
		}
	}
	if queryIdx >= 0 {
		query = path[queryIdx:]
		p = path[:queryIdx]
	}
	if len(p) == 0 || p[0] != '/' {
		p = "/" + p
	}
	segments := make([]string, 0, 8)
	start := 1
	for i := 1; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' {
			seg := p[start:i]
			start = i + 1
			if seg == "." || seg == "" {
				continue
			}
			if seg == ".." {
				if len(segments) > 0 {
					segments = segments[:len(segments)-1]
				}
				continue
			}
			segments = append(segments, seg)
		}
	}
	if len(segments) == 0 {
		return "/" + query
	}
	clean := make([]byte, 0, len(p))
	for _, seg := range segments {
		clean = append(clean, '/')
		clean = append(clean, seg...)
	}
	return string(clean) + query
}

func ValidateHost(host string) bool {
	if host == "" {
		return true
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c == '/' || c == '\\' || c == '\r' || c == '\n' || c == 0 {
			return false
		}
	}
	return true
}

func containsCRLF(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' {
			return true
		}
	}
	return false
}

var coarseNow atomic.Int64

func init() {
	coarseNow.Store(time.Now().UnixNano())
	go func() {
		ticker := time.NewTicker(time.Millisecond)
		for range ticker.C {
			coarseNow.Store(time.Now().UnixNano())
		}
	}()
}

func CoarseNanotime() int64 {
	return coarseNow.Load()
}
