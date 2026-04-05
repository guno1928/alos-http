package core

import (
	"sync/atomic"
	"time"
)

type TokenBucket struct {
	tokens   atomic.Int64
	lastTime atomic.Int64
	rate     int64
	burst    int64
	_        [CacheLineSize - 32]byte
}

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

func (tb *TokenBucket) Wait(tokens int64) {
	if tokens > tb.burst {
		return
	}
	for !tb.Allow(tokens) {
		time.Sleep(time.Millisecond)
	}
}

func (tb *TokenBucket) WaitWithDeadline(tokens int64, deadline time.Time) bool {
	for !tb.Allow(tokens) {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

// BandwidthConfig sets per-connection or global bandwidth limits in megabits
// per second. MaxUploadRate limits inbound data, MaxDownloadRate limits outbound
// data, and BurstSize controls the token bucket burst allowance. Pass this
// in Config.ConnBandwidth for per-connection limits or Config.GlobalBandwidth
// for server-wide limits.
//
//	cfg := core.Config{
//	    ConnBandwidth: core.BandwidthConfig{
//	        MaxUploadRate:   100,
//	        MaxDownloadRate: 200,
//	        BurstSize:       50,
//	    },
//	    GlobalBandwidth: core.BandwidthConfig{
//	        MaxDownloadRate: 1000,
//	    },
//	}
type BandwidthConfig struct {
	MaxUploadRate   int64
	MaxDownloadRate int64
	BurstSize       int64
}

type ConnectionLimiter struct {
	Upload   *TokenBucket
	Download *TokenBucket
}

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

func (cl *ConnectionLimiter) ThrottleUpload(n int64) {
	if cl != nil && cl.Upload != nil {
		cl.Upload.Wait(n)
	}
}

func (cl *ConnectionLimiter) ThrottleDownload(n int64) {
	if cl != nil && cl.Download != nil {
		cl.Download.Wait(n)
	}
}

type GlobalLimiter struct {
	Upload   *TokenBucket
	Download *TokenBucket
}

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
