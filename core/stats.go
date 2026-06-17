package core

import "sync/atomic"

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
}

// Stats is the global server statistics instance. Counters are updated
// automatically by the server as connections are accepted and requests
// are processed.
var Stats ServerStats
