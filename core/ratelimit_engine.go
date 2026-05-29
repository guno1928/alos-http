package core

import (
	"log"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/guno1928/alosmap"
)

// RateLimitEvent is passed to the OnLimit callback when a request is rate-limited.
// It contains the client IP, request path, the matched rule, and how long the
// client should wait before retrying.
type RateLimitEvent struct {
	IP         string
	Path       string
	Rule       RateLimitRule
	RetryAfter time.Duration
}

// RateLimitFunc is the callback signature for custom rate-limit handling.
// Return true if the response has been fully handled, or false to fall
// through to the default 429 Too Many Requests response.
type RateLimitFunc func(event RateLimitEvent, req *Request, resp *Response) bool

type matchType uint8

const (
	matchExact  matchType = 0
	matchPrefix matchType = 1
	matchRegex  matchType = 2
)

// RateLimitRule defines a rate limit for a specific path pattern. Path can be an
// exact path, a prefix ending in * (wildcard), or a regex prefixed with ~.
//
//	// Exact path: 100 requests per minute, block for 5 minutes on exceed
//	core.RateLimitRule{
//	    Path:     "/api/login",
//	    MaxReqs:  100,
//	    Window:   time.Minute,
//	    BlockFor: 5 * time.Minute,
//	}
//
//	// Prefix wildcard: anything under /api/
//	core.RateLimitRule{
//	    Path:    "/api/*",
//	    MaxReqs: 1000,
//	    Window:  time.Minute,
//	}
//
//	// Regex: match /users/{digits}
//	core.RateLimitRule{
//	    Path:    "~^/users/[0-9]+$",
//	    MaxReqs: 50,
//	    Window:  time.Minute,
//	}
type RateLimitRule struct {
	Path     string
	MaxReqs  int64
	Window   time.Duration
	BlockFor time.Duration
	OnLimit  RateLimitFunc
}

type compiledRule struct {
	rule    RateLimitRule
	kind    matchType
	exact   string
	prefix  string
	re      *regexp.Regexp
	keyBase string
}

type rlEntry struct {
	count   atomic.Int64
	reset   atomic.Int64
	blocked atomic.Int64
	_       [CacheLineSize - 24]byte
}

// RateLimitEngine tracks per-client request counts against configured rules.
// It uses lock-free atomics for counters and a sharded map for client state.
// The engine runs a background goroutine that cleans up stale entries every
// 30 seconds.
type RateLimitEngine struct {
	rules   atomic.Pointer[[]compiledRule]
	clients *alosmap.Map
	stopCh  chan struct{}
	OnLimit RateLimitFunc
}

// NewRateLimitEngine creates a new rate limiter with an empty rule set and starts
// the background cleanup goroutine. Call Stop when the engine is no longer needed.
func NewRateLimitEngine() *RateLimitEngine {
	rle := &RateLimitEngine{
		clients: alosmap.New(alosmap.WithCapacity(10000), alosmap.WithoutCleanup()),
		stopCh:  make(chan struct{}),
	}
	empty := make([]compiledRule, 0)
	rle.rules.Store(&empty)
	go rle.cleanupLoop()
	return rle
}

func compileRule(rule RateLimitRule) compiledRule {
	cr := compiledRule{rule: rule, keyBase: rule.Path}
	path := rule.Path

	if len(path) > 0 && path[0] == '~' {
		cr.kind = matchRegex
		var err error
		cr.re, err = regexp.Compile(path[1:])
		if err != nil {
			log.Printf("[RATELIMIT] invalid regex pattern %q: %v", path[1:], err)
		}
		return cr
	}

	if len(path) > 0 && path[len(path)-1] == '*' {
		cr.kind = matchPrefix
		cr.prefix = path[:len(path)-1]
		return cr
	}

	cr.kind = matchExact
	cr.exact = path
	return cr
}

func (cr *compiledRule) match(path string) bool {
	switch cr.kind {
	case matchExact:
		return path == cr.exact
	case matchPrefix:
		return len(path) >= len(cr.prefix) && path[:len(cr.prefix)] == cr.prefix
	case matchRegex:
		if cr.re == nil {
			return false
		}
		return cr.re.MatchString(path)
	}
	return false
}

func (cr *compiledRule) specificity() int {
	switch cr.kind {
	case matchExact:
		return len(cr.exact) + 10000
	case matchPrefix:
		return len(cr.prefix)
	case matchRegex:
		return len(cr.rule.Path)
	}
	return 0
}

func (rle *RateLimitEngine) SetRules(rules []RateLimitRule) {
	compiled := make([]compiledRule, len(rules))
	for i := range rules {
		compiled[i] = compileRule(rules[i])
	}
	rle.rules.Store(&compiled)
}

func (rle *RateLimitEngine) AddRule(rule RateLimitRule) {
	old := *rle.rules.Load()
	updated := make([]compiledRule, 0, len(old)+1)
	for i := range old {
		if old[i].rule.Path != rule.Path {
			updated = append(updated, old[i])
		}
	}
	updated = append(updated, compileRule(rule))
	rle.rules.Store(&updated)
}

func (rle *RateLimitEngine) RemoveRule(path string) {
	old := *rle.rules.Load()
	updated := make([]compiledRule, 0, len(old))
	for i := range old {
		if old[i].rule.Path != path {
			updated = append(updated, old[i])
		}
	}
	rle.rules.Store(&updated)
}

func (rle *RateLimitEngine) matchRule(path string) *compiledRule {
	rules := *rle.rules.Load()
	var best *compiledRule
	bestSpec := -1
	for i := range rules {
		if rules[i].match(path) {
			spec := rules[i].specificity()
			if spec > bestSpec {
				bestSpec = spec
				best = &rules[i]
			}
		}
	}
	return best
}

func (rle *RateLimitEngine) Check(ip string, path string) (bool, *compiledRule, time.Duration) {
	cr := rle.matchRule(path)
	if cr == nil {
		return true, nil, 0
	}

	var keyBuf [128]byte
	keyLen := len(ip) + 1 + len(cr.keyBase)
	var key string
	if keyLen <= len(keyBuf) {
		n := copy(keyBuf[:], ip)
		keyBuf[n] = '|'
		copy(keyBuf[n+1:], cr.keyBase)
		key = string(keyBuf[:keyLen])
	} else {
		key = ip + "|" + cr.keyBase
	}
	now := CoarseNanotime()

	var entry *rlEntry
	v, ok := rle.clients.Load(alosmap.S(key))
	if !ok {
		newEntry := &rlEntry{}
		newEntry.reset.Store(now + cr.rule.Window.Nanoseconds())
		v, _ = rle.clients.LoadOrStore(alosmap.S(key), newEntry)
	}
	entry = v.(*rlEntry)

	blockedUntil := entry.blocked.Load()
	if blockedUntil > 0 && now < blockedUntil {
		remaining := time.Duration(blockedUntil - now)
		return false, cr, remaining
	}
	if blockedUntil > 0 && now >= blockedUntil {
		entry.blocked.Store(0)
		entry.count.Store(0)
		entry.reset.Store(now + cr.rule.Window.Nanoseconds())
	}

	resetAt := entry.reset.Load()
	if now >= resetAt {
		entry.count.Store(0)
		entry.reset.Store(now + cr.rule.Window.Nanoseconds())
	}

	count := entry.count.Add(1)
	if count > cr.rule.MaxReqs {
		blockDur := cr.rule.BlockFor
		if blockDur <= 0 {
			blockDur = cr.rule.Window
		}
		entry.blocked.Store(now + blockDur.Nanoseconds())
		return false, cr, blockDur
	}

	return true, cr, 0
}

func (rle *RateLimitEngine) Stop() {
	select {
	case <-rle.stopCh:
	default:
		close(rle.stopCh)
	}
}

func (rle *RateLimitEngine) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-rle.stopCh:
			return
		case <-ticker.C:
			now := CoarseNanotime()
			var stale []alosmap.Key
			rle.clients.Range(func(key alosmap.Key, val any) bool {
				entry := val.(*rlEntry)
				resetAt := entry.reset.Load()
				blockedUntil := entry.blocked.Load()
				if now > resetAt+int64(60*time.Second) && (blockedUntil == 0 || now > blockedUntil) {
					stale = append(stale, key)
				}
				return true
			})
			for _, key := range stale {
				rle.clients.Delete(key)
			}
		}
	}
}
