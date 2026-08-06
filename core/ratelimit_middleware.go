package core

import (
	"strconv"
	"sync/atomic"
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

const rateLimitBlockFor = 30 * time.Second

type rateLimitMWEntry struct {
	state        atomic.Uint64
	resetAt      atomic.Int64
	blockedUntil atomic.Int64
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
	useResolvedIP := cfg.KeyFunc == nil
	keyFunc := cfg.KeyFunc
	if keyFunc == nil {
		keyFunc = func(req *Request) string {
			return extractClientIP(req.RemoteAddr)
		}
	}

	windowNanos := cfg.Window.Nanoseconds()
	blockNanos := rateLimitBlockFor.Nanoseconds()
	blockSecs := int64(rateLimitBlockFor / time.Second)
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
				now := CoarseNanotime()
				entries.Range(func(key string, entry *rateLimitMWEntry) bool {
					if entry.resetAt.Load() < now && entry.blockedUntil.Load() < now {
						entries.Delete(key)
					}
					return true
				})
			}()
		}
	}()

	reject := func(req *Request, resp *Response, key string, retryAfterSecs int64) {
		if cfg.OnLimit != nil {
			ip := key
			if !useResolvedIP {
				ip = extractClientIP(req.RemoteAddr)
			}
			ev := RateLimitEvent{
				IP:   ip,
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

			blockedUntil := entry.blockedUntil.Load()
			if blockedUntil != 0 {
				if now < blockedUntil {
					retryAfterSecs := (blockedUntil - now) / 1_000_000_000
					if retryAfterSecs < 1 {
						retryAfterSecs = 1
					}
					reject(req, resp, key, retryAfterSecs)
					return
				}
				if entry.blockedUntil.CompareAndSwap(blockedUntil, 0) {
					entry.state.Store(rlEpochOf(now, windowNanos))
					entry.resetAt.Store(now + windowNanos)
				}
			}

			count := rlBumpCount(&entry.state, now, windowNanos)
			if count == 1 {
				entry.resetAt.Store(now + windowNanos)
			}
			if count > cfg.MaxRequests {
				entry.blockedUntil.Store(now + blockNanos)
				reject(req, resp, key, blockSecs)
				return
			}

			next(req, resp)
		}
	}
}
