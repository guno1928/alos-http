package core

import "time"

// Route is the handle returned by route-registration methods, used to attach
// per-route configuration such as rate limits.
type Route struct {
	node   *node
	router *Router
	method string
	path   string
}

// Limit applies a per-route rate limit keyed by client IP, returning the Route
// for chaining. Values <= 0 fall back to defaults (100 requests, 1 minute).
//
// Example: r.GET("/api", h).Limit(100, time.Minute)
// Example: r.POST("/upload", h).Limit(10, 10*time.Second)
func (rt *Route) Limit(maxRequests int64, window time.Duration) *Route {
	if rt.node == nil || rt.node.handler == nil {
		return rt
	}
	if maxRequests <= 0 {
		maxRequests = 100
	}
	if window <= 0 {
		window = time.Minute
	}

	cfg := RateLimitMiddlewareConfig{
		MaxRequests: maxRequests,
		Window:      window,
	}
	rt.applyServerRateLimitDefaults(&cfg)

	limiter := RateLimitMiddleware(cfg)

	rt.node.handler = limiter(rt.node.handler)
	return rt
}

// LimitByKey applies a per-route rate limit using keyFunc to derive the limiter
// key from each request, returning the Route for chaining. Values <= 0 fall back
// to defaults (100 requests, 1 minute).
//
// Example: r.GET("/api", h).LimitByKey(100, time.Minute, func(req *core.Request) string { return req.Header("X-API-Key") })
// Example: r.GET("/u/:id", h).LimitByKey(5, time.Second, func(req *core.Request) string { return req.Param("id") })
func (rt *Route) LimitByKey(maxRequests int64, window time.Duration, keyFunc func(*Request) string) *Route {
	if rt.node == nil || rt.node.handler == nil {
		return rt
	}
	if maxRequests <= 0 {
		maxRequests = 100
	}
	if window <= 0 {
		window = time.Minute
	}

	cfg := RateLimitMiddlewareConfig{
		MaxRequests: maxRequests,
		Window:      window,
		KeyFunc:     keyFunc,
	}
	rt.applyServerRateLimitDefaults(&cfg)

	limiter := RateLimitMiddleware(cfg)

	rt.node.handler = limiter(rt.node.handler)
	return rt
}

func (rt *Route) applyServerRateLimitDefaults(cfg *RateLimitMiddlewareConfig) {
	if rt.router == nil || rt.router.server == nil {
		return
	}
	s := rt.router.server
	cfg.OnLimit = func(event RateLimitEvent, req *Request, resp *Response) bool {
		if s.RateLimit != nil && s.RateLimit.OnLimit != nil {
			return s.RateLimit.OnLimit(event, req, resp)
		}
		return false
	}
}
