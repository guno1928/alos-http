//go:build !amd64

package core

import "bytes"

func equalPrefix16(data []byte, ref *[16]byte) bool {
	return bytes.Equal(data[:16], ref[:])
}
