//go:build linux && amd64

package core

import (
	"bytes"
	"fmt"
	"testing"
)

func fillStreamPatternReference(dst []byte, offset int) {
	for i := range dst {
		position := offset + i
		dst[i] = byte(position*31 + position>>11)
	}
}

func TestFillStreamPatternMatchesScalar(t *testing.T) {
	const period = 1 << 19
	maxInt := int(^uint(0) >> 1)
	minInt := -maxInt - 1
	offsets := []int{
		0, 1, 2047, 2048, period - 1, period, period + 1,
		-1, -2048, -period - 1, -1234567,
		maxInt, maxInt - 16, minInt, minInt + 1,
	}
	for _, offset := range offsets {
		for _, size := range []int{0, 1, 32 << 10, period + 1, 2*period + 17} {
			t.Run(fmt.Sprintf("offset_%d/size_%d", offset, size), func(t *testing.T) {
				got := bytes.Repeat([]byte{0xa5}, size+2)
				want := make([]byte, size)
				fillStreamPatternReference(want, offset)
				fillStreamPattern(got[1:size+1], offset)
				if !bytes.Equal(got[1:size+1], want) {
					for i := range want {
						if got[i+1] != want[i] {
							t.Fatalf("byte %d = %d, want %d", i, got[i+1], want[i])
						}
					}
				}
				if got[0] != 0xa5 || got[size+1] != 0xa5 {
					t.Fatal("fill changed bytes outside destination")
				}
			})
		}
		fillStreamPattern(nil, offset)
	}
}

func TestFillStreamPatternKnownBytes(t *testing.T) {
	for _, test := range []struct {
		offset int
		want   []byte
	}{
		{0, []byte{0, 31, 62, 93}},
		{2047, []byte{225, 1, 32, 63}},
		{-1, []byte{224, 0, 31, 62}},
	} {
		got := make([]byte, len(test.want))
		fillStreamPattern(got, test.offset)
		if !bytes.Equal(got, test.want) {
			t.Errorf("offset %d: got %v, want %v", test.offset, got, test.want)
		}
	}
}
