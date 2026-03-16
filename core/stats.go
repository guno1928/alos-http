package core

import "sync/atomic"

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

var Stats ServerStats
