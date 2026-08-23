package core

import (
	"sync/atomic"
	"time"

	"github.com/guno1928/turbo"
)

// ServerStats holds atomic counters for server-wide metrics. All fields are
// safe for concurrent reads from any goroutine. Access the global instance
// via the Stats package variable.
//
//	active := core.Stats.ActiveConns.Load()
//	total := core.Stats.TotalReqs.Load()
type ServerStats struct {
	ActiveConns atomic.Int64
	_           [CacheLineSize - 8]byte
	TotalConns  atomic.Uint64
	_           [CacheLineSize - 8]byte
	H2Conns     atomic.Uint64
	_           [CacheLineSize - 8]byte
	H1Conns     atomic.Uint64
	_           [CacheLineSize - 8]byte
	TotalReqs   atomic.Uint64
	_           [CacheLineSize - 8]byte
	BytesIn     atomic.Uint64
	_           [CacheLineSize - 8]byte
	BytesOut    atomic.Uint64
	_           [CacheLineSize - 8]byte
	RawReqs     atomic.Uint64
	_           [CacheLineSize - 8]byte
	BlockedReqs atomic.Uint64
	_           [CacheLineSize - 8]byte

	rawPerSec atomic.Uint64
	_         [CacheLineSize - 8]byte
	blkPerSec atomic.Uint64
	_         [CacheLineSize - 8]byte
}

// Stats is the global server statistics instance. Counters are updated
// automatically by the server as connections are accepted and requests
// are processed.
var Stats ServerStats

func (s *ServerStats) ReqsPerSec() uint64 { return s.rawPerSec.Load() }

func (s *ServerStats) BlockedPerSec() uint64 { return s.blkPerSec.Load() }

func statsBlocked() { Stats.BlockedReqs.Add(1) }

func statsRawBlocked() {
	Stats.RawReqs.Add(1)
	Stats.BlockedReqs.Add(1)
}

func init() { go statsSampler() }

func statsSampler() {
	ticker := turbo.NewTicker(time.Second)
	defer ticker.Stop()
	lastRaw := Stats.RawReqs.Load()
	lastBlk := Stats.BlockedReqs.Load()
	for range ticker.C {
		raw := Stats.RawReqs.Load()
		blk := Stats.BlockedReqs.Load()
		Stats.rawPerSec.Store(raw - lastRaw)
		Stats.blkPerSec.Store(blk - lastBlk)
		lastRaw = raw
		lastBlk = blk
	}
}
