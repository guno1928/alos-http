//go:build linux && amd64

package core

import (
	"net/netip"
	"strconv"
	"time"

	"github.com/guno1928/alosmap"
)

// RateLimitMiddlewareConfig configures the RateLimitMiddleware.
//
// MaxRequests is the maximum number of requests allowed per key within Window; defaults to 100 when <= 0.
//
//	Example: MaxRequests: 1000 allows 1000 requests per window.
//	Example: MaxRequests: 0 uses the default of 100.
//
// Window is the duration of the rate-limit window; defaults to time.Minute when <= 0.
//
//	Example: Window: time.Second allows MaxRequests per second.
//	Example: Window: 0 uses the default of one minute.
//
// KeyFunc derives the rate-limit key from a request; defaults to the client IP parsed from RemoteAddr when nil.
//
//	Example: KeyFunc: nil keys by client IP.
//	Example: KeyFunc: func(r *Request) string { return r.Header("X-API-Key") } keys by API key.
//
// OnLimit is called when a request is rejected; returning true means the callback wrote the response, otherwise a 429 with a Retry-After header is sent.
//
//	Example: OnLimit: nil sends a default 429 "Too Many Requests".
//	Example: OnLimit: func(ev RateLimitEvent, req *Request, resp *Response) bool { resp.Status(429).JSONString(`{"error":"slow down"}`); return true } sends a custom response.
type RateLimitMiddlewareConfig struct {
	MaxRequests int64
	Window      time.Duration
	KeyFunc     func(*Request) string
	OnLimit     RateLimitFunc
	StopCh      <-chan struct{}
}

const (
	rateLimitBlockFor       = 30 * time.Second
	rateLimitIPv6PrefixBits = 64
)

func isIPv4Text(ip string) bool {
	return len(ip) > 3 && (ip[3] == '.' || ip[2] == '.' || ip[1] == '.')
}

func rateLimitKeyForIP(ip string) string {
	if isIPv4Text(ip) || indexByte(ip, ':') < 0 {
		return ip
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Is4In6() {
		return ip
	}
	prefix, err := addr.WithZone("").Prefix(rateLimitIPv6PrefixBits)
	if err != nil {
		return ip
	}
	return prefix.String()
}

type rateLimitMWEntry struct {
	rlCounter
}

func extractClientIP(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	if remoteAddr[0] == '[' {
		for i := 1; i < len(remoteAddr); i++ {
			if remoteAddr[i] == ']' {
				return remoteAddr[1:i]
			}
		}
		return remoteAddr
	}
	lastColon := -1
	colonCount := 0
	for i := len(remoteAddr) - 1; i >= 0; i-- {
		if remoteAddr[i] == ':' {
			colonCount++
			if lastColon == -1 {
				lastColon = i
			}
		}
	}
	if colonCount > 1 {
		return remoteAddr
	}
	if lastColon >= 0 {
		return remoteAddr[:lastColon]
	}
	return remoteAddr
}

// RateLimitMiddleware returns middleware that limits requests per key to cfg.MaxRequests within cfg.Window, blocking offending keys for a fixed cooldown and responding 429 with a Retry-After header. See RateLimitMiddlewareConfig for defaults.
//
// Example: app.Use(RateLimitMiddleware(RateLimitMiddlewareConfig{}))
// Example: app.Use(RateLimitMiddleware(RateLimitMiddlewareConfig{MaxRequests: 10, Window: time.Second}))
// Example: app.Use(RateLimitMiddleware(RateLimitMiddlewareConfig{KeyFunc: func(r *Request) string { return r.Header("X-API-Key") }}))
func RateLimitMiddleware(cfg RateLimitMiddlewareConfig) MiddlewareFunc {
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = 100
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	keyFunc := cfg.KeyFunc
	if keyFunc == nil {
		keyFunc = func(req *Request) string {
			ip := extractClientIP(req.RemoteAddr)
			if !isIPv4Text(ip) {
				ip = rateLimitKeyForIP(ip)
			}
			return ip
		}
	}

	windowNanos := cfg.Window.Nanoseconds()
	blockNanos := rateLimitBlockFor.Nanoseconds()
	entries := alosmap.NewTypedSized[string, *rateLimitMWEntry](1024, 0).Prealloc(256)

	stopCh := cfg.StopCh
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						Dbg("[ratelimit cleanup] recovered panic: %v", r)
					}
				}()
				retireIdleRateLimitEntries(entries, CoarseNanotime(), 0)
			}()
		}
	}()

	reject := func(req *Request, resp *Response, retryAfterSecs int64) {
		if cfg.OnLimit != nil {
			ev := RateLimitEvent{
				IP:   extractClientIP(req.RemoteAddr),
				Path: req.Path,
				Rule: RateLimitRule{
					Path:     req.Path,
					MaxReqs:  cfg.MaxRequests,
					Window:   cfg.Window,
					BlockFor: rateLimitBlockFor,
				},
				RetryAfter: time.Duration(retryAfterSecs) * time.Second,
			}
			if cfg.OnLimit(ev, req, resp) {
				return
			}
		}
		resp.Status(429).
			SetHeaderUnsafe("Retry-After", strconv.FormatInt(retryAfterSecs, 10)).
			String("Too Many Requests")
	}

	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			key := keyFunc(req)
			now := CoarseNanotime()

			entry, ok := entries.Load(key)
			if !ok {
				entry, _ = entries.LoadOrStore(key, &rateLimitMWEntry{})
			}

			outcome, retryAfter := entry.admit(now, windowNanos, cfg.MaxRequests, blockNanos)
			for outcome == rlRetired {
				entries.CompareAndDelete(key, entry)
				entry, _ = entries.LoadOrStore(key, &rateLimitMWEntry{})
				outcome, retryAfter = entry.admit(now, windowNanos, cfg.MaxRequests, blockNanos)
			}
			if outcome == rlLimited {
				reject(req, resp, max(int64(retryAfter/time.Second), 1))
				return
			}

			next(req, resp)
		}
	}
}
