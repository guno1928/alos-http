//go:build !amd64

package core

import "bytes"

var crlfcrlfNeedle = []byte{'\r', '\n', '\r', '\n'}
var crlfNeedle = []byte{'\r', '\n'}

func indexCRLFCRLF(b []byte) int {
	return bytes.Index(b, crlfcrlfNeedle)
}

func indexCRLF2(b []byte) int {
	return bytes.Index(b, crlfNeedle)
}
