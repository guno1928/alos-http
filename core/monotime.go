package core

import _ "unsafe"

// MonotonicNanotime returns the current value of the Go runtime's monotonic clock, in nanoseconds.
func MonotonicNanotime() int64 {
	return runtimeNanotime()
}

//go:linkname runtimeNanotime runtime.nanotime
func runtimeNanotime() int64
