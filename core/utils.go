package core

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/guno1928/alosmap"
)

type dnsCacheEntry struct {
	ips []net.IP
	idx atomic.Uint32
}

var (
	dnsCache    = alosmap.NewTypedSized[string, *dnsCacheEntry](1024, 0, alosmap.WithCleanupInterval(30*time.Second)).Prealloc(256)
	dnsTTL      = int64(60)
	dnsResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialTCP4Direct(address, timeoutFromContext(ctx, 5*time.Second))
		},
	}
)

func timeoutFromContext(ctx context.Context, fallback time.Duration) time.Duration {
	if ctx == nil {
		return fallback
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 {
			return remaining
		}
		return time.Millisecond
	}
	return fallback
}

func resolveIPv4(ctx context.Context, host string) (net.IP, error) {
	if entry, ok := dnsCache.Load(host); ok {
		ips := entry.ips
		idx := entry.idx.Add(1)
		return ips[int(idx)%len(ips)], nil
	}

	ips, err := dnsResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return nil, err
	}

	entry := &dnsCacheEntry{ips: ips}
	dnsCache.StoreWithTTL(host, entry, time.Duration(dnsTTL)*time.Second)

	return ips[0], nil
}

// DialTCP4 dials addr over TCP/IPv4 within timeout, resolving hostnames through the internal DNS cache, and tunes the resulting connection's socket options.
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
	return conn, nil
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

// ToLowerASCII returns s with ASCII uppercase letters folded to lowercase, using a fast path for common HTTP header names.
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

// EqualFoldASCII reports whether a and b are equal under ASCII case-insensitive comparison.
func EqualFoldASCII(a, b string) bool {
	if a == b {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	n := len(a)
	i := 0
	for ; i+8 <= n; i += 8 {
		if asciiLower[a[i]] != asciiLower[b[i]] ||
			asciiLower[a[i+1]] != asciiLower[b[i+1]] ||
			asciiLower[a[i+2]] != asciiLower[b[i+2]] ||
			asciiLower[a[i+3]] != asciiLower[b[i+3]] ||
			asciiLower[a[i+4]] != asciiLower[b[i+4]] ||
			asciiLower[a[i+5]] != asciiLower[b[i+5]] ||
			asciiLower[a[i+6]] != asciiLower[b[i+6]] ||
			asciiLower[a[i+7]] != asciiLower[b[i+7]] {
			return false
		}
	}
	for ; i < n; i++ {
		if asciiLower[a[i]] != asciiLower[b[i]] {
			return false
		}
	}
	return true
}

// UnsafeString converts b to a string without copying, by reinterpreting its backing array. The returned string is only valid as long as b is not mutated.
func UnsafeString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// UnsafeBytes converts s to a byte slice without copying, by reinterpreting its backing array. The caller must not mutate the returned slice.
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

var hexLookup = [256]uint8{
	'0': 0x00, '1': 0x01, '2': 0x02, '3': 0x03, '4': 0x04,
	'5': 0x05, '6': 0x06, '7': 0x07, '8': 0x08, '9': 0x09,
	'a': 0x0a, 'b': 0x0b, 'c': 0x0c, 'd': 0x0d, 'e': 0x0e, 'f': 0x0f,
	'A': 0x0a, 'B': 0x0b, 'C': 0x0c, 'D': 0x0d, 'E': 0x0e, 'F': 0x0f,
}

var hexValid = [256]bool{
	'0': true, '1': true, '2': true, '3': true, '4': true,
	'5': true, '6': true, '7': true, '8': true, '9': true,
	'a': true, 'b': true, 'c': true, 'd': true, 'e': true, 'f': true,
	'A': true, 'B': true, 'C': true, 'D': true, 'E': true, 'F': true,
}

func parseHex64(s string) (int64, bool) {
	if len(s) == 0 {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !hexValid[c] {
			return 0, false
		}
		n = n<<4 | int64(hexLookup[c])
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
		if !hexValid[c] {
			return 0, false
		}
		n = n<<4 | int64(hexLookup[c])
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
	return bytes.IndexByte(b, c)
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
	return strings.IndexByte(s, c)
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if asciiLower[s[i]] != asciiLower[prefix[i]] {
			return false
		}
	}
	return true
}

func indexCRLF(s string) int {
	return strings.Index(s, "\r\n")
}

var digitPairs = [100]uint16{
	0x3030, 0x3130, 0x3230, 0x3330, 0x3430, 0x3530, 0x3630, 0x3730, 0x3830, 0x3930,
	0x3031, 0x3131, 0x3231, 0x3331, 0x3431, 0x3531, 0x3631, 0x3731, 0x3831, 0x3931,
	0x3032, 0x3132, 0x3232, 0x3332, 0x3432, 0x3532, 0x3632, 0x3732, 0x3832, 0x3932,
	0x3033, 0x3133, 0x3233, 0x3333, 0x3433, 0x3533, 0x3633, 0x3733, 0x3833, 0x3933,
	0x3034, 0x3134, 0x3234, 0x3334, 0x3434, 0x3534, 0x3634, 0x3734, 0x3834, 0x3934,
	0x3035, 0x3135, 0x3235, 0x3335, 0x3435, 0x3535, 0x3635, 0x3735, 0x3835, 0x3935,
	0x3036, 0x3136, 0x3236, 0x3336, 0x3436, 0x3536, 0x3636, 0x3736, 0x3836, 0x3936,
	0x3037, 0x3137, 0x3237, 0x3337, 0x3437, 0x3537, 0x3637, 0x3737, 0x3837, 0x3937,
	0x3038, 0x3138, 0x3238, 0x3338, 0x3438, 0x3538, 0x3638, 0x3738, 0x3838, 0x3938,
	0x3039, 0x3139, 0x3239, 0x3339, 0x3439, 0x3539, 0x3639, 0x3739, 0x3839, 0x3939,
}

func appendUint(dst []byte, n int64) []byte {
	var buf [20]byte
	i := len(buf)
	if n == 0 {
		return append(dst, '0')
	}
	for n >= 100 {
		d := n % 100
		n /= 100
		i -= 2
		*(*uint16)(unsafe.Pointer(&buf[i])) = digitPairs[d]
	}
	if n >= 10 {
		i -= 2
		*(*uint16)(unsafe.Pointer(&buf[i])) = digitPairs[n]
	} else {
		i--
		buf[i] = byte(n) + '0'
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

// StatusText returns the standard reason phrase for the given HTTP status code, or "Unknown" if code is not recognized.
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
	case 431:
		return "Request Header Fields Too Large"
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

// HexDigit returns the lowercase hex character for the nibble value b (0-15).
func HexDigit(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'a' + b - 10
}

// AppendJSONString appends s to dst as a double-quoted, JSON-escaped string, escaping control characters, quotes, and backslashes.
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

func splitPathQuery(raw string) (string, string) {
	for i := 0; i < len(raw); i++ {
		if raw[i] == '?' {
			return raw[:i], raw[i+1:]
		}
	}
	return raw, ""
}

func sanitizeRequestPath(path string) string {
	if nul := strings.IndexByte(path, 0); nul >= 0 {
		path = path[:nul]
	} else if cr := strings.IndexByte(path, '\r'); cr >= 0 {
		path = path[:cr]
	} else if lf := strings.IndexByte(path, '\n'); lf >= 0 {
		path = path[:lf]
	}
	if len(path) == 0 {
		return "/"
	}

	p, _ := splitPathQuery(path)
	if len(p) == 0 {
		return "/"
	}

	if p[0] == '/' && strings.IndexByte(p, '.') < 0 && !strings.Contains(p, "//") {
		return p
	}

	needsSanitize := p[0] != '/'
	for i := 0; i < len(p) && !needsSanitize; i++ {
		if p[i] == '/' && i+1 < len(p) {
			next := p[i+1]
			if next == '/' || next == '.' {
				needsSanitize = true
			}
		}
	}
	if !needsSanitize {
		return p
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
		return "/"
	}
	clean := make([]byte, 0, len(p))
	for _, seg := range segments {
		clean = append(clean, '/')
		clean = append(clean, seg...)
	}
	return string(clean)
}

var badHostChar [256]bool

func init() {
	badHostChar['/'] = true
	badHostChar['\\'] = true
	badHostChar['\r'] = true
	badHostChar['\n'] = true
	badHostChar[0] = true
}

// ValidateHost reports whether host contains none of the disallowed characters: path separators, CR, LF, or NUL.
func ValidateHost(host string) bool {
	for i := 0; i < len(host); i++ {
		if badHostChar[host[i]] {
			return false
		}
	}
	return true
}

func containsCRLF(s string) bool {
	return strings.IndexByte(s, '\r') >= 0 || strings.IndexByte(s, '\n') >= 0
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

// CoarseNanotime returns a coarse-grained current time in Unix nanoseconds, refreshed by a background ticker roughly once per millisecond.
func CoarseNanotime() int64 {
	return coarseNow.Load()
}
