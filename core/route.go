package core

import "time"

type Route struct {
	node   *node
	router *Router
	method string
	path   string
}

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
