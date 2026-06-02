package core

import (
	"strconv"
	"sync/atomic"
	"time"
)

type RateLimitMiddlewareConfig struct {
	MaxRequests int64
	Window      time.Duration
	KeyFunc     func(*Request) string
	OnLimit     RateLimitFunc
}

const rateLimitBlockFor = 30 * time.Second

type rateLimitMWEntry struct {
	count        atomic.Int64
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
	entries := NewShardedMap[string, *rateLimitMWEntry](StringHash)

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		for range ticker.C {
			now := CoarseNanotime()
			entries.Range(func(key string, entry *rateLimitMWEntry) bool {
				if entry.resetAt.Load() < now && entry.blockedUntil.Load() < now {
					entries.Delete(key)
				}
				return true
			})
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

			entry, _ := entries.LoadOrStore(key, &rateLimitMWEntry{})

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
				entry.blockedUntil.Store(0)
				entry.count.Store(0)
				entry.resetAt.Store(now + windowNanos)
			}

			resetAt := entry.resetAt.Load()
			if resetAt == 0 || now >= resetAt {
				entry.count.Store(0)
				entry.resetAt.Store(now + windowNanos)
			}

			count := entry.count.Add(1)
			if count > cfg.MaxRequests {
				entry.blockedUntil.Store(now + blockNanos)
				reject(req, resp, key, blockSecs)
				return
			}

			next(req, resp)
		}
	}
}
