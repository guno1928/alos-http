package core

import _ "unsafe"

// MonotonicNanotime returns the runtime's monotonic nanosecond clock.
// It is appropriate for timeout and elapsed-time bookkeeping in hot paths.
func MonotonicNanotime() int64 {
	return runtimeNanotime()
}

//go:linkname runtimeNanotime runtime.nanotime
func runtimeNanotime() int64
