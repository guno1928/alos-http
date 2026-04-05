package core

import _ "unsafe"

func MonotonicNanotime() int64 {
	return runtimeNanotime()
}

//go:linkname runtimeNanotime runtime.nanotime
func runtimeNanotime() int64
