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

// RateLimitRule defines a rate limit for a specific path pattern, used with
// RateLimitEngine.SetRules/AddRule.
//
// Path selects which requests the rule applies to: an exact path, a prefix
// ending in "*", or a regex prefixed with "~".
//
//	Example: Path: "/api/login" matches only that exact path.
//	Example: Path: "/api/*" matches anything under /api/.
//	Example: Path: "~^/users/[0-9]+$" matches paths by regex.
//
// MaxReqs is the maximum number of requests allowed per client within Window.
//
//	Example: MaxReqs: 100 allows 100 requests per Window.
//
// Window is the duration over which MaxReqs is counted.
//
//	Example: Window: time.Minute counts requests per minute.
//
// BlockFor is how long an offending client is blocked after exceeding
// MaxReqs; <= 0 falls back to Window.
//
//	Example: BlockFor: 5 * time.Minute blocks offenders for five minutes.
//	Example: BlockFor: 0 blocks for the same duration as Window.
//
// OnLimit, when set, is invoked instead of the default 429 response.
//
//	Example: OnLimit: nil sends the default 429 "Too Many Requests".
//	Example: OnLimit: func(ev RateLimitEvent, req *Request, resp *Response) bool { resp.Status(429).JSONString(`{"error":"slow down"}`); return true }
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
	state   atomic.Uint64
	reset   atomic.Int64
	blocked atomic.Int64
	_       [CacheLineSize - 24]byte
}

const rlEpochShift = 40
const rlCountMask uint64 = (1 << rlEpochShift) - 1
const rlEpochMask uint64 = (1 << 24) - 1

func rlEpochOf(now, windowNanos int64) uint64 {
	if windowNanos <= 0 {
		windowNanos = 1
	}
	return (uint64(now/windowNanos) & rlEpochMask) << rlEpochShift
}

func rlBumpCount(state *atomic.Uint64, now, windowNanos int64) int64 {
	epoch := rlEpochOf(now, windowNanos)
	for {
		cur := state.Load()
		var next uint64
		if cur&^rlCountMask != epoch {
			next = epoch | 1
		} else {
			c := cur & rlCountMask
			if c >= rlCountMask {
				return int64(c)
			}
			next = epoch | (c + 1)
		}
		if state.CompareAndSwap(cur, next) {
			return int64(next & rlCountMask)
		}
	}
}

// RateLimitEngine tracks per-client request counts against configured rules.
// It uses lock-free atomics for counters and a sharded map for client state.
// The engine runs a background goroutine that cleans up stale entries every
// 30 seconds.
type RateLimitEngine struct {
	rules   atomic.Pointer[[]compiledRule]
	clients *alosmap.TypedMap[string, *rlEntry]
	stopCh  chan struct{}
	OnLimit RateLimitFunc
}

// NewRateLimitEngine creates a new rate limiter with an empty rule set and starts
// the background cleanup goroutine. Call Stop when the engine is no longer needed.
func NewRateLimitEngine() *RateLimitEngine {
	rle := &RateLimitEngine{
		clients: alosmap.NewTypedSized[string, *rlEntry](10000, 0).Prealloc(256),
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

// SetRules atomically replaces the engine's entire rule set with rules.
//
// Example: engine.SetRules([]RateLimitRule{{Path: "/api/*", MaxReqs: 1000, Window: time.Minute}})
func (rle *RateLimitEngine) SetRules(rules []RateLimitRule) {
	compiled := make([]compiledRule, len(rules))
	for i := range rules {
		compiled[i] = compileRule(rules[i])
	}
	rle.rules.Store(&compiled)
}

// AddRule adds rule to the engine, replacing any existing rule with the same
// Path.
//
// Example: engine.AddRule(RateLimitRule{Path: "/api/login", MaxReqs: 100, Window: time.Minute})
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

// RemoveRule removes the rule registered for the exact path, if any.
//
// Example: engine.RemoveRule("/api/login")
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

// Check reports whether a request from ip to path is allowed under the rule
// matching path, incrementing that client's counter as a side effect. It
// returns true with a zero duration when no rule matches or the request is
// within its limit, and false with the remaining wait time when the client
// is currently blocked.
//
// Example: allowed, _, retryAfter := engine.Check(req.RemoteAddr, req.Path)
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

	entry, ok := rle.clients.Load(key)
	if !ok {
		newEntry := &rlEntry{}
		newEntry.reset.Store(now + cr.rule.Window.Nanoseconds())
		entry, _ = rle.clients.LoadOrStore(key, newEntry)
	}

	blockedUntil := entry.blocked.Load()
	if blockedUntil > 0 && now < blockedUntil {
		remaining := time.Duration(blockedUntil - now)
		return false, cr, remaining
	}
	windowNanos := cr.rule.Window.Nanoseconds()
	if blockedUntil > 0 && now >= blockedUntil {
		entry.blocked.Store(0)
		entry.state.Store(rlEpochOf(now, windowNanos))
		entry.reset.Store(now + windowNanos)
	}

	count := rlBumpCount(&entry.state, now, windowNanos)
	if count == 1 {
		entry.reset.Store(now + windowNanos)
	}
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

// Stop halts the engine's background cleanup goroutine. It is safe to call
// multiple times.
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
			func() {
				defer func() {
					if r := recover(); r != nil {
						Dbg("[ratelimit cleanup] recovered panic: %v", r)
					}
				}()
				now := CoarseNanotime()
				var stale []string
				rle.clients.Range(func(key string, entry *rlEntry) bool {
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
			}()
		}
	}
}
