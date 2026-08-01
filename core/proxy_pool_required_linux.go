//go:build linux

package core

// The epoll data path pools upstream connections inside the event loop, so the
// blocking connPool is never consulted. Building one per backend would start an
// eviction goroutine and hold buffers for a pool nothing reads.
const backendPoolRequired = false
