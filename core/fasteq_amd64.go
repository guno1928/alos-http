//go:build amd64

package core

import "unsafe"

func equalPrefix16(data []byte, ref *[16]byte) bool {
	p := unsafe.Pointer(unsafe.SliceData(data))
	q := unsafe.Pointer(ref)
	return *(*uint64)(p) == *(*uint64)(q) &&
		*(*uint64)(unsafe.Add(p, 8)) == *(*uint64)(unsafe.Add(q, 8))
}
