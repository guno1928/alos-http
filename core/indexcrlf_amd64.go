//go:build amd64

package core

import (
	"math/bits"
	"unsafe"

	"golang.org/x/sys/cpu"
)

//go:noescape
func indexCRLF4AVX2(p *byte, n int) int

//go:noescape
func indexCRLF2AVX2(p *byte, n int) int

var hasAVX2 = cpu.X86.HasAVX2

func indexCRLF2(b []byte) int {
	if len(b) < 2 {
		return -1
	}
	if hasAVX2 {
		return indexCRLF2AVX2(unsafe.SliceData(b), len(b))
	}
	return indexCRLF2Swar(b)
}

func indexCRLF2Swar(b []byte) int {
	n := len(b)
	const ones = 0x0101010101010101
	const high = 0x8080808080808080
	const cr = uint64(0x0D) * ones
	const pat = uint16(0x0A0D)
	if n < 2 {
		return -1
	}
	p := unsafe.Pointer(unsafe.SliceData(b))
	i := 0
	for ; i+8 <= n; i += 8 {
		w := *(*uint64)(unsafe.Add(p, i))
		x := w ^ cr
		found := (x - ones) &^ x & high
		for found != 0 {
			pos := i + (bits.TrailingZeros64(found) >> 3)
			if pos+2 <= n && *(*uint16)(unsafe.Add(p, pos)) == pat {
				return pos
			}
			found &= found - 1
		}
	}
	for ; i+2 <= n; i++ {
		if *(*uint16)(unsafe.Add(p, i)) == pat {
			return i
		}
	}
	return -1
}

func indexCRLFCRLF(b []byte) int {
	if len(b) < 4 {
		return -1
	}
	if hasAVX2 {
		return indexCRLF4AVX2(unsafe.SliceData(b), len(b))
	}
	return indexCRLFCRLFSwar(b)
}

func indexCRLFCRLFSwar(b []byte) int {
	n := len(b)
	const ones = 0x0101010101010101
	const high = 0x8080808080808080
	const cr = uint64(0x0D) * ones
	const pat = uint32(0x0A0D0A0D)
	if n < 4 {
		return -1
	}
	p := unsafe.Pointer(unsafe.SliceData(b))
	i := 0
	for ; i+8 <= n; i += 8 {
		w := *(*uint64)(unsafe.Add(p, i))
		x := w ^ cr
		found := (x - ones) &^ x & high
		for found != 0 {
			pos := i + (bits.TrailingZeros64(found) >> 3)
			if pos+4 <= n && *(*uint32)(unsafe.Add(p, pos)) == pat {
				return pos
			}
			found &= found - 1
		}
	}
	for ; i+4 <= n; i++ {
		if *(*uint32)(unsafe.Add(p, i)) == pat {
			return i
		}
	}
	return -1
}
