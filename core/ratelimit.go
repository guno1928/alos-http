package core

import (
	"sync/atomic"
	"time"
)

// TokenBucket is a lock-free token-bucket rate limiter safe for concurrent
// use. Create one with NewTokenBucket.
type TokenBucket struct {
	tokens   atomic.Int64
	lastTime atomic.Int64
	rate     int64
	burst    int64
	_        [CacheLineSize - 32]byte
}

// NewTokenBucket returns a TokenBucket that refills at ratePerSec tokens per
// second up to a maximum of burst tokens, starting full.
//
// Example: tb := NewTokenBucket(1_000_000, 1_000_000) // ~1MB/s, 1MB burst
// Example: tb := NewTokenBucket(65536, 131072)         // 64KB/s, 128KB burst
func NewTokenBucket(ratePerSec, burst int64) *TokenBucket {
	tb := &TokenBucket{
		rate:  ratePerSec,
		burst: burst,
	}
	tb.tokens.Store(burst)
	tb.lastTime.Store(CoarseNanotime())
	return tb
}

func (tb *TokenBucket) refill() {
	now := CoarseNanotime()
	last := tb.lastTime.Load()
	elapsed := now - last
	if elapsed <= 0 {
		return
	}

	seconds := elapsed / 1_000_000_000
	remainder := elapsed % 1_000_000_000
	tokensToAdd := seconds*tb.rate + (remainder*tb.rate)/1_000_000_000
	if tokensToAdd <= 0 {
		return
	}

	if tb.lastTime.CompareAndSwap(last, now) {
		for {
			current := tb.tokens.Load()
			newTokens := current + tokensToAdd
			if newTokens > tb.burst {
				newTokens = tb.burst
			}
			if tb.tokens.CompareAndSwap(current, newTokens) {
				break
			}
		}
	}
}

// Allow reports whether tokens can be spent immediately, deducting them if
// so. It returns false without waiting if the bucket lacks enough tokens or
// if tokens exceeds the bucket's burst size.
//
// Example: if !tb.Allow(1024) { return errRateLimited }
// Example: ok := tb.Allow(1)
func (tb *TokenBucket) Allow(tokens int64) bool {
	if tokens <= 0 {
		return true
	}
	if tokens > tb.burst {
		return false
	}
	tb.refill()
	for {
		current := tb.tokens.Load()
		if current < tokens {
			return false
		}
		if tb.tokens.CompareAndSwap(current, current-tokens) {
			return true
		}
	}
}

// Wait blocks until tokens have been spent from the bucket, sleeping in small
// increments as it waits for refills. Requests larger than the burst size are
// spent in burst-sized chunks.
//
// Example: tb.Wait(int64(len(chunk)))
func (tb *TokenBucket) Wait(tokens int64) {
	for tokens > tb.burst {
		tb.waitForChunk(tb.burst)
		tokens -= tb.burst
	}
	if tokens > 0 {
		for !tb.Allow(tokens) {
			tb.sleepForDeficit(tokens)
		}
	}
}

func (tb *TokenBucket) waitForChunk(n int64) {
	for !tb.Allow(n) {
		tb.sleepForDeficit(n)
	}
}

func (tb *TokenBucket) sleepForDeficit(n int64) {
	tb.refill()
	deficit := n - tb.tokens.Load()
	if deficit <= 0 || tb.rate <= 0 {
		time.Sleep(50 * time.Microsecond)
		return
	}
	waitNs := (deficit * 1_000_000_000) / tb.rate
	if waitNs < int64(50*time.Microsecond) {
		waitNs = int64(50 * time.Microsecond)
	}
	if waitNs > int64(10*time.Millisecond) {
		waitNs = int64(10 * time.Millisecond)
	}
	time.Sleep(time.Duration(waitNs))
}

// WaitWithDeadline is like Wait but gives up and returns false if deadline
// passes before enough tokens become available; it returns true once tokens
// have been spent.
//
// Example: ok := tb.WaitWithDeadline(4096, time.Now().Add(2*time.Second))
func (tb *TokenBucket) WaitWithDeadline(tokens int64, deadline time.Time) bool {
	for tokens > tb.burst {
		for !tb.Allow(tb.burst) {
			if time.Now().After(deadline) {
				return false
			}
			tb.sleepForDeficit(tb.burst)
		}
		tokens -= tb.burst
	}
	if tokens <= 0 {
		return true
	}
	for !tb.Allow(tokens) {
		if time.Now().After(deadline) {
			return false
		}
		tb.sleepForDeficit(tokens)
	}
	return true
}

// BandwidthConfig sets a bandwidth limit in megabits per second. Pass it in
// Config.ConnBandwidth for a per-connection limit or Config.GlobalBandwidth
// for a server-wide limit.
//
// MaxUploadRate caps inbound data in Mbps; <= 0 leaves uploads unthrottled.
//
//	Example: MaxUploadRate: 100 caps uploads at 100 Mbps.
//	Example: MaxUploadRate: 0 disables the upload limiter.
//
// MaxDownloadRate caps outbound data in Mbps; <= 0 leaves downloads unthrottled.
//
//	Example: MaxDownloadRate: 200 caps downloads at 200 Mbps.
//
// BurstSize is the token-bucket burst allowance in Mbps; <= 0 falls back to a
// built-in default (64KB for a connection limiter, 1MB for a global limiter).
//
//	Example: BurstSize: 50 allows short bursts up to 50 Mbps.
//	Example: BurstSize: 0 uses the built-in default burst.
type BandwidthConfig struct {
	MaxUploadRate   int64
	MaxDownloadRate int64
	BurstSize       int64
}

// ConnectionLimiter holds the per-connection upload and download token
// buckets used to throttle a single connection's bandwidth. A nil Upload or
// Download bucket means that direction is unthrottled.
type ConnectionLimiter struct {
	Upload   *TokenBucket
	Download *TokenBucket
}

// NewConnectionLimiter returns a ConnectionLimiter built from config, leaving
// a direction unthrottled (nil bucket) when its rate is <= 0.
//
// Example: cl := NewConnectionLimiter(BandwidthConfig{MaxUploadRate: 10, MaxDownloadRate: 50})
// Example: cl := NewConnectionLimiter(BandwidthConfig{})  // both directions unthrottled
func NewConnectionLimiter(config BandwidthConfig) *ConnectionLimiter {
	var cl ConnectionLimiter
	burst := config.BurstSize * 125000
	if config.BurstSize <= 0 {
		burst = 65536
	}
	if config.MaxUploadRate > 0 {
		cl.Upload = NewTokenBucket(config.MaxUploadRate*125000, burst)
	}
	if config.MaxDownloadRate > 0 {
		cl.Download = NewTokenBucket(config.MaxDownloadRate*125000, burst)
	}
	return &cl
}

// ThrottleUpload blocks until n bytes may be received under the connection's
// upload limit; it is a no-op when cl is nil or has no upload limit.
//
// Example: limiter.ThrottleUpload(int64(len(buf)))
func (cl *ConnectionLimiter) ThrottleUpload(n int64) {
	if cl != nil && cl.Upload != nil {
		cl.Upload.Wait(n)
	}
}

// ThrottleDownload blocks until n bytes may be sent under the connection's
// download limit; it is a no-op when cl is nil or has no download limit.
//
// Example: limiter.ThrottleDownload(int64(len(chunk)))
func (cl *ConnectionLimiter) ThrottleDownload(n int64) {
	if cl != nil && cl.Download != nil {
		cl.Download.Wait(n)
	}
}

// GlobalLimiter holds the server-wide upload and download token buckets
// shared across all connections. A nil Upload or Download bucket means that
// direction is unthrottled.
type GlobalLimiter struct {
	Upload   *TokenBucket
	Download *TokenBucket
}

// NewGlobalLimiter returns a GlobalLimiter built from config, leaving a
// direction unthrottled (nil bucket) when its rate is <= 0.
//
// Example: gl := NewGlobalLimiter(BandwidthConfig{MaxDownloadRate: 1000})
// Example: gl := NewGlobalLimiter(BandwidthConfig{})  // both directions unthrottled
func NewGlobalLimiter(config BandwidthConfig) *GlobalLimiter {
	var gl GlobalLimiter
	burst := config.BurstSize * 125000
	if config.BurstSize <= 0 {
		burst = 1 << 20
	}
	if config.MaxUploadRate > 0 {
		gl.Upload = NewTokenBucket(config.MaxUploadRate*125000, burst)
	}
	if config.MaxDownloadRate > 0 {
		gl.Download = NewTokenBucket(config.MaxDownloadRate*125000, burst)
	}
	return &gl
}
