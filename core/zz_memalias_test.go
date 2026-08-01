//go:build linux && amd64

package core

import "runtime"

// MemStatsAlias keeps the allocation tests readable without repeating the
// runtime import in every helper.
type MemStatsAlias = runtime.MemStats

func readMem(m *MemStatsAlias) {
	runtime.GC()
	runtime.ReadMemStats(m)
}
